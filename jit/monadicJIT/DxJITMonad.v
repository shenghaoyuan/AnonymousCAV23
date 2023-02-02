From compcert.common Require Import AST Memory.
From compcert.lib Require Import Integers.
From compcert.arm Require Import AsmSyntax.

From bpf.comm Require Import Monad Flag Regs MemRegion.
From bpf.dxcomm Require Import DxIntegers DxValues.
From bpf.dxmodel Require Import DxRegs DxFlag DxMemRegion DxState.

From bpf.jit.thumb Require Import LoadStoreRegs KeyValue2 Arm32Reg JITState.
From bpf.jit.monadicJIT Require Import JITMonadOp.

Definition M (A: Type) := Monad.M jit_state A.
Definition returnM {A: Type} (a: A) : M A := Monad.returnM a.
Definition bindM {A B: Type} (x: M A) (f: A -> M B) : M B := Monad.bindM x f.

Definition eval_pc: M int := JITMonadOp.eval_pc.
Definition upd_pc (p: int): M unit := JITMonadOp.upd_pc p.
Definition upd_pc_incr: M unit := JITMonadOp.upd_pc_incr.

Definition eval_flag: M valu32_t := JITMonadOp.eval_flag.
Definition upd_flag (f:bpf_flag) : M unit := JITMonadOp.upd_flag f.

Definition eval_mrs_num: M nat := JITMonadOp.eval_mrs_num.

Definition eval_reg (r: reg) : M val64_t := JITMonadOp.eval_reg r.
Definition upd_reg (r: reg) (v: val64_t) : M unit := JITMonadOp.upd_reg r v.

Definition eval_mrs_regions : M MyMemRegionsType := JITMonadOp.eval_mrs_regions.

Definition load_mem (chunk: memory_chunk) (ptr: valu32_t): M val64_t := JITMonadOp.load_mem chunk ptr.

Definition store_mem_imm (ptr: valptr8_t) (chunk: memory_chunk) (v: vals32_t) : M unit := JITMonadOp.store_mem_imm ptr chunk v.

Definition store_mem_reg (ptr: valptr8_t) (chunk: memory_chunk) (v: val64_t) : M unit := JITMonadOp.store_mem_reg ptr chunk v.

Definition eval_ins_len : M int := JITMonadOp.eval_ins_len.

(**r here we must use sint32_t instead of int because pc is signed int *)
Definition eval_ins (idx: int) : M int64 := JITMonadOp.eval_ins idx.

Definition add_key_value2 (pc: nat) (v0 v1: nat) : M unit := JITMonadOp.add_key_value2 pc v0 v1.

Definition cmp_ptr32_nullM (v: valptr8_t): M bool := JITMonadOp.cmp_ptr32_nullM v.

Definition get_dst (ins: int64): M reg := int64_to_dst_reg ins.

Definition get_src (ins: int64): M reg := int64_to_src_reg ins.

Definition get_mem_region (n:nat) (mrs: MyMemRegionsType): M memory_region := get_mem_region n mrs.

Definition upd_IR11_jittedthumb (f: bool): M unit := JITMonadOp.upd_IR11_jittedthumb f.

Definition add_ins_jittedthumb (ins: int16): M unit := JITMonadOp.add_ins_jittedthumb ins.

Definition upd_bpf_offset_jittedthumb: M unit := JITMonadOp.upd_bpf_offset_jittedthumb.

Definition upd_load_store_regs_jittedthumb (r: reg) (ls: LoadStorePerm): M unit := JITMonadOp.upd_load_store_regs_jittedthumb r ls.

Definition upd_thumb_jittedthumb (ins: int16) (pc: nat): M unit := JITMonadOp.upd_thumb_jittedthumb ins pc.

Definition upd_jitted_list (ins: int16): M unit := JITMonadOp.upd_jitted_list ins.

Definition magic_function (ofs: int) : M unit := JITMonadOp.magic_function ofs.

Definition eval_use_IR11: M bool := JITMonadOp.eval_use_IR11.
Definition eval_load_store_regs: M LoadStoreRegs := JITMonadOp.eval_load_store_regs.
Definition eval_offset: M nat := JITMonadOp.eval_offset.
Definition eval_thumb_len: M nat := JITMonadOp.eval_thumb_len.
Definition eval_jitted_len: M nat := JITMonadOp.eval_jitted_len.
Definition reg_of_ireg (r: ireg): M reg := JITMonadOp.reg_of_ireg r.

Definition reset_init_jittedthumb: M unit := JITMonadOp.reset_init_jittedthumb.
Definition eval_thumb_ins (idx: int): M int := JITMonadOp.eval_thumb_ins idx.
Definition eval_key_value2_arm_ofs (idx: int): M nat := JITMonadOp.eval_key_value2_arm_ofs idx.
Definition eval_key_value2_alu32_ofs (idx: int): M nat := JITMonadOp.eval_key_value2_alu32_ofs idx.

Declare Scope monad_scope.
Notation "'do' x <-- a ; b" :=
  (bindM a (fun x => b))
    (at level 200, x name, a at level 100, b at level 200)
  : monad_scope.

Definition _bpf_get_call (i: vals32_t) : M valptr8_t := JITMonadOp._bpf_get_call i.
Definition exec_function (f: valptr8_t) : M valu32_t := JITMonadOp.exec_function f.
