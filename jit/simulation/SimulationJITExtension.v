From Coq Require Import ZArith Lia.
From compcert Require Import Integers Values AST Memory Memdata.

From bpf.comm Require Import Flag Regs State Monad BinrBPF rBPFMonadOp rBPFMemType rBPFValues.

From bpf.monadicmodel2 Require Import ConcreteState.

From bpf.jit.thumb Require Import LoadStoreRegs ThumbEncode ThumbInsOp Arm32Reg JITState ThumbJITOpcode ThumbJIT.

From bpf.jit.simulation Require Import SimulationJIT.

Section RelationEx.
  Variable flag_blk: block.
  Variable regs_blk: block.
  Variable jit_blk: block.

  Record RelEx (sti: state) (stj: jit_state): Prop :=
  {
    munchange:  Mem.unchanged_on (fun b _ => b <> jit_blk) (bpf_m sti) (jit_mem stj);
    mpc      :  ConcreteState.pc_loc sti = jit_pc stj;
    mflag    :  match_flag sti stj flag_blk;
    mregs    :  match_registers sti stj regs_blk;
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

End RelationEx.