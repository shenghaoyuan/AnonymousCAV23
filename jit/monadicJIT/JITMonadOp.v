From compcert.common Require Import AST Values Memory.
From compcert.lib Require Import Integers.
From compcert.arm Require Import AsmSyntax.

From bpf.comm Require Import Regs BinrBPF Flag rBPFValues MemRegion Monad.
From bpf.jit.thumb Require Import LoadStoreRegs KeyValue2 Arm32Reg JITState.
From Coq Require Import ZArith List.
Import ListNotations.

Definition eval_pc: M jit_state int := fun st => Some (eval_jit_pc st, st).

Definition upd_pc (p: int): M jit_state unit := fun st =>
  if Int.cmpu Cle p (Int.sub (Int.repr (Z.of_nat (jit_ins_len st))) (Int.repr 2%Z)) then
    Some (tt, upd_jit_pc p st)
  else (**r TODO: bpf verifier / verifier-invariant should ensure this branch is unreachable *)
    None.

Definition upd_pc_incr: M jit_state unit := fun st =>
  if (Int.cmpu Clt (Int.add (jit_pc st) Int.one) (Int.repr (Z.of_nat (jit_ins_len st)))) then
    Some (tt, upd_jit_pc_incr st)
  else (**r TODO: bpf verifier / verifier-invariant should ensure this branch is unreachable *)
    None.

Definition eval_flag: M jit_state val := fun st => 
  match eval_jit_flag st with
  | Some f => Some (f, st)
  | None => None
  end.

Definition upd_flag (f: bpf_flag) : M jit_state unit := fun st =>
  match upd_jit_flag f st with
  | Some m => Some (tt, m)
  | None => None
  end.

Definition eval_reg (r: reg) : M jit_state val := fun st =>
  match eval_jit_reg r st with
  | Some v => Some (v, st)
  | None => None
  end.

Definition upd_reg (r: reg) (v: val) : M jit_state unit := fun st =>
  match v with
  | Vlong _ =>
    match upd_jit_reg r v st with
    | Some m => Some (tt, m)
    | None => None
    end
  | _ => None
  end.

Definition eval_mrs_num: M jit_state nat := fun st => Some (eval_jit_mem_num st, st).
Definition eval_mrs_regions : M jit_state MyMemRegionsType := fun st => Some (eval_jit_mem_regions st, st).

Definition get_mem_region (n:nat) (mrs: MyMemRegionsType): M jit_state memory_region := fun st =>
  if (Nat.ltb n (jit_mrs_num st)) then
    match List.nth_error mrs n with
    | Some mr => Some (mr, st)
    | None => None (**r TODO: we should infer this *)
    end
  else
    None.

Definition eval_mem : M jit_state Mem.mem := fun st => Some (eval_jit_mem st, st).

Definition load_mem (chunk: memory_chunk) (ptr: val): M jit_state val := fun st => 
  match load_jit_mem chunk ptr st with
  | Some res =>
    match res with
    | Vundef => None
    | _ => Some (res, st)
    end
  | None => None
  end.

Definition store_mem_imm (ptr: val) (chunk: memory_chunk) (v: val) : M jit_state unit := fun st =>
  match store_jit_mem_imm ptr chunk v st with
  | Some res => Some (tt, res)
  | None => None
  end.

Definition store_mem_reg (ptr: val) (chunk: memory_chunk) (v: val) : M jit_state unit := fun st => 
  match store_jit_mem_reg ptr chunk v st with
  | Some res => Some (tt, res)
  | None => None
  end.

Definition eval_ins_len : M jit_state int := fun st => Some (eval_jit_ins_len st, st).
Definition eval_ins (idx: int) : M jit_state int64 := fun st =>
  if (Int.cmpu Clt idx (Int.repr (Z.of_nat (jit_ins_len st)))) then
    match eval_jit_ins idx st with
    | Some ins => Some (ins, st)
    | None => None
    end
  else (**r TODO: if bpf verifier / verifier-invariant guarantees upd_pc*, we should infer it *)
    None.

Definition cmp_ptr32_nullM (v: val): M jit_state bool := fun st =>
  match cmp_ptr32_null (JITState.eval_jit_mem st) v with
  | Some res => Some (res, st)
  | None     => None (**r TODO: we should infer this *)
  end.

Definition int64_to_dst_reg (ins: int64): M jit_state reg := fun st =>
  match int64_to_dst_reg' ins with
  | Some r => Some (r, st)
  | None => None (**r TODO: bpf verifier / verifier-invariant should ensure this branch is unreachable *)
  end.

Definition int64_to_src_reg (ins: int64): M jit_state reg := fun st =>
  match int64_to_src_reg' ins with
  | Some r => Some (r, st)
  | None => None (**r TODO: bpf verifier / verifier-invariant should ensure this branch is unreachable *)
  end.

(* Given the immediate of the call, it returns a function pointer *)

(* Let assume there is a bpf context pointer in the memory. For the time being, your interpreter does not use it.
   Let keep it that way -- at least for the moment. *)
Axiom _bpf_get_call : val -> M jit_state val. (**r here is Vint -> Vptr *)
Axiom exec_function : val -> M jit_state val. (**r Vptr -> Vint *)
Axiom lemma_bpf_get_call :
  forall i st1,
    exists ptr,
      _bpf_get_call (Vint i) st1 = Some (ptr, st1) /\
      (ptr = Vnullptr \/ (exists b ofs, ptr = Vptr b ofs /\ ((Mem.valid_pointer (jit_mem st1) b (Ptrofs.unsigned ofs)
        || Mem.valid_pointer (jit_mem st1) b (Ptrofs.unsigned ofs - 1)) = true)%bool)).
Axiom lemma_exec_function0 :
  forall b ofs st1,
      exists v st2, exec_function (Vptr b ofs) st1 = Some (Vint v, st2) /\ cmp_ptr32_null (JITState.eval_jit_mem st1) (Vptr b ofs) = Some false.

Definition upd_IR11_jittedthumb (f: bool): M jit_state unit := fun st => Some (tt, upd_IR11_jittedthumb f st).

Definition add_ins_jittedthumb (ins: int): M jit_state unit := fun st =>
  if Nat.ltb (thumb_len st) JITTED_LIST_MAX_LENGTH then
    Some (tt, add_ins_jittedthumb ins st)
  else
    match JITState.upd_jit_flag BPF_ILLEGAL_ARM_LEN st with
    | Some st1 => Some (tt, st1)
    | None => None
    end.

Definition upd_bpf_offset_jittedthumb: M jit_state unit := fun st => Some (tt, upd_bpf_offset_jittedthumb st).

Definition upd_load_store_regs_jittedthumb (r: reg) (ls: LoadStorePerm): M jit_state unit := fun st =>
  match upd_load_store_regs_jittedthumb r ls st with
  | Some st0 => Some (tt, st0)
  | None => None
  end.

Definition upd_thumb_jittedthumb (ins: int) (pc: nat): M jit_state unit := fun st => Some (tt, upd_thumb_jittedthumb ins pc st).

Definition upd_jitted_list (ins: int): M jit_state unit := fun st =>
  if Nat.ltb (thumb_len st) JITTED_LIST_MAX_LENGTH then
    match upd_jitted_list ins st with
    | Some st1 => Some (tt, st1)
    | None => None
    end
  else
    match JITState.upd_jit_flag BPF_ILLEGAL_ARM_LEN st with
    | Some st1 => Some (tt, st1)
    | None => None
    end.

Definition magic_function (ofs: int) : M jit_state unit := fun st =>
  let fuel := JITTED_LIST_MAX_LENGTH in
  let sz := (Int.repr 56) in (**r 14 * 4 *)
    match magic_function fuel ofs sz st with
    | Some st1 => Some (tt, st1)
    | None => None
    end.

Definition eval_use_IR11: M jit_state bool := fun st => Some(use_IR11 st, st).
Definition eval_load_store_regs: M jit_state LoadStoreRegs := fun st => Some(load_store_regs st, st).
Definition eval_offset: M jit_state nat := fun st => Some(offset st, st).
Definition eval_thumb_len: M jit_state nat := fun st => Some(thumb_len st, st).
Definition eval_jitted_len: M jit_state nat := fun st => Some(jitted_len st, st).

Definition eval_thumb_ins (idx: int): M jit_state int := fun st =>
  if (Int.cmpu Clt idx (Int.repr (Z.of_nat (thumb_len st)))) then
    match eval_thumb_ins idx st with
    | Some ins => Some (ins, st)
    | None => None
    end
  else
    None.

Definition add_key_value2 (pc: nat) (v0 v1: nat) : M jit_state unit := fun st => Some (tt, add_key_value2 pc v0 v1 st).

Definition reg_of_ireg (r: ireg): M jit_state reg := fun st =>
  match reg_of_ireg r with
  | Some res => Some (res, st)
  | None => None
  end.

Definition reset_init_jittedthumb: M jit_state unit := fun st => Some (tt, reset_init_jittedthumb st).

Definition eval_key_value2_arm_ofs (idx: int): M jit_state nat := fun st =>
  match eval_key_value2_arm_ofs idx st with
  | Some kv => Some (kv, st)
  | None => None
  end.

Definition eval_key_value2_alu32_ofs (idx: int): M jit_state nat := fun st =>
  match eval_key_value2_alu32_ofs idx st with
  | Some kv => Some (kv, st)
  | None => None
  end.