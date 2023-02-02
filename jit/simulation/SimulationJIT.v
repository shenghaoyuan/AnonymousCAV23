From Coq Require Import ZArith Lia.
From compcert Require Import Integers Values AST Memory Memdata.

From compcert.arm Require Import AsmSyntax ABinSem.

From bpf.comm Require Import Flag Regs State Monad BinrBPF rBPFMonadOp rBPFMemType rBPFValues.

From bpf.monadicmodel2 Require Import ConcreteState.

From bpf.jit.thumb Require Import KeyValue2 Arm32Reg JITState ThumbJITOpcode ThumbJIT.


Open Scope nat_scope.

(** The file defines the equivalence relation between the concrete synthesis model (monadicmodel2/) and the JIT model (jit.thumb/) *)

(** we define a forward simulation relation: FR = R \/ R'

bpf state      : st_i(0)  ->  ... -> st_i(k) -> st_i(k+1) -> ... -> st_i(k+l) -> st_i(k+l+1) -> ... -> st_j(end)
   |               |                 |             |                    |            \                    \
   |               |                 |             |                    |             \                    \
   |               |                 |             |                    |              \                    \
   |               |                 |             |                    |               \                    \
 (FR)              R                 R             R'                   R'              R                    R
   |               |                 |             |                    |                \                    \
   |               |                 |             |                    |                 \                    \
   |               |                 |             |                    |                  \                    \
   |               |                 |             |                    |                   \                    \
arm state   \/     |                 | .. -> st_r(n) -> ... -> ... -> st_r(t) -> ...         \                    \
jit state     :  st_j(0)  ->  ... -> st_j(k) -------------(magic_function)--------------> st_j(k+1) ->  ... -> st_j(end')
*)

Global Transparent Archi.ptr64.

(** * Equivalence Relation: concrete interpreter model ``='' JIT model *)

Definition match_registers (sti: state) (stj: jit_state) (regs_blk: block) : Prop :=
  regs_st sti = Vptr regs_blk Ptrofs.zero /\
  jit_regs stj = Vptr regs_blk Ptrofs.zero /\
  forall (r: reg), exists vl,
    Mem.loadv AST.Mint64 (bpf_m sti) (Val.add (regs_st sti) (Vint (Int.repr (8 * (id_of_reg r))))) = Some (Vlong vl) /\
    Mem.loadv AST.Mint64 (jit_mem stj) (Val.add (jit_regs stj) (Vint (Int.repr (8 * (id_of_reg r))))) = Some (Vlong vl).

Definition match_registers_arm (sti: state) (stj: jit_state) (st_a: aregset)  (regs_blk: block): Prop :=
  regs_st sti = Vptr regs_blk Ptrofs.zero /\
  jit_regs stj = Vptr regs_blk Ptrofs.zero /\
  forall (r: reg), exists vl,
    Mem.loadv AST.Mint64 (bpf_m sti) (Val.add (regs_st sti) (Vint (Int.repr (8 * (id_of_reg r))))) = Some (Vlong vl) /\
    (
      Mem.loadv AST.Mint64 (jit_mem stj) (Val.add (jit_regs stj) (Vint (Int.repr (8 * (id_of_reg r))))) = Some (Vlong vl) \/
      match (st_a (ireg_of_reg r)) with
      | Cval v =>
        match v with
        | Vint i => Int64.repr (Int.unsigned i) = vl
        | _ => False
        end
      | _ => False
      end
    ).

Definition match_flag (sti: state) (stj: jit_state) (flag_blk: block) : Prop :=
  flag sti = Vptr flag_blk Ptrofs.zero /\
  jit_flag stj = Vptr flag_blk Ptrofs.zero /\
  exists f,
    eval_flag sti = Some (Vint (int_of_flag f)) /\
    eval_jit_flag stj = Some (Vint (int_of_flag f)).

Definition ptr_range_perm (m: mem) (chunk: memory_chunk) (ptr: val) (p: permission): Prop :=
  match ptr with
  | Vptr b ofs => Mem.valid_access m chunk b (Ptrofs.unsigned ofs) p
  | _ => False
  end.

Definition cur_ins_is_jit (st: jit_state) : bool :=
  match ListKeyV.index (kv2 st) (jit_pc st) with
  | Some kv =>
      (Nat.ltb 0 (arm_ofs kv)) || (Nat.ltb 0 (alu32_ofs kv))
  | None => false
  end.

(** The relation consists of:
- Concrete Interpreter Memory and JIT Memory are same
- Other components (from pc to ins_len) are also same
  - Concrete flag (JIT) has the form `Vptr flag_blk 0`
  - the value of Concrete flag (JIT) is stored into the `flag_blk` and it is equal to JIT's flag
  - Concrete regs (JIT) also has the similar form `Vptr regs_blk 0`
  - the value of Concrete regs (JIT) is stored into the `regs_blk` and each Ri in `regs_blk` is equal to each Ri of JIT
  - same memory regions
  - same instruction list length
  - different insttruction list (because JIT will modify `ins`)
*)


Section Relation.
  Variable flag_blk: block.
  Variable regs_blk: block.
  Variable jit_blk: block.

  Record Rel (sti: state) (stj: jit_state) (st_a: aregset): Prop :=
  {
    munchange:  Mem.unchanged_on (fun b _ => b <> jit_blk) (bpf_m sti) (jit_mem stj);
    mpc      :  ((cur_ins_is_jit stj = false) ->
                  pc_loc sti = jit_pc stj) /\

                ((cur_ins_is_jit stj = true) ->
                  Int.cmpu Cle (jit_pc stj) (pc_loc sti) = true (*/\
                  Int.cmpu Cle (pc_loc sti) (Int.add (jit_pc stj) ofs) *));
    mflag    :  match_flag sti stj flag_blk;
    mregs    :  ((cur_ins_is_jit stj = false) -> match_registers sti stj regs_blk) /\

                ((cur_ins_is_jit stj = true) -> match_registers_arm sti stj st_a regs_blk);
    mmrs_num :  mrs_num sti = jit_mrs_num stj;
    mbpf_mrs :  bpf_mrs sti = jit_mrs stj;
    mins_len :  ins_len sti = jit_ins_len stj;
    mins     :  ins sti = jit_ins stj;
    mjit     :  Vptr jit_blk Ptrofs.zero = jitted_list stj;

    mperm    :  ptr_range_perm (bpf_m sti) Mint32 (flag sti) Freeable /\
                (forall r, ptr_range_perm (bpf_m sti) Mint64
                    (Val.add (regs_st sti) (Vint (Int.repr (8 * (id_of_reg r))))) Freeable) /\
                ptr_range_perm (jit_mem stj) Mint32 (jit_flag stj) Freeable /\
                (forall r, ptr_range_perm (jit_mem stj) Mint64
                  (Val.add (jit_regs stj) (Vint (Int.repr (8 * (id_of_reg r))))) Freeable) /\
                (forall pc, (0 <= pc < Nat.div JITTED_LIST_MAX_LENGTH 2)%nat ->
                  ptr_range_perm (jit_mem stj) Mint16unsigned
                    (Val.add (JITState.jitted_list stj) (Vint (Int.repr (Z.of_nat (2 * pc))))) Freeable);
    minvalid :  ~Mem.valid_block (bpf_m sti) jit_blk /\
                  (flag_blk <> regs_blk /\ jit_blk <> flag_blk /\ jit_blk <> regs_blk) /\
                  (forall b, b <> jit_blk ->
                    Mem.valid_block (bpf_m sti) b -> Mem.valid_block (jit_mem stj) b);
  }.

End Relation.