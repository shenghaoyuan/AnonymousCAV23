From Coq Require Import ZArith Lia.
From compcert Require Import Integers Values AST Memory Memdata.

From bpf.comm Require Import Flag Regs State Monad rBPFMonadOp rBPFMemType rBPFValues.

From bpf.verifier.comm Require Import state.

From bpf.jit.thumb Require Import JITState ThumbJIT.
From bpf.jit.verifier Require Import JITVerifier.

(** * JIT Correctness *)

(** This module is used to prove the functional correctness of jit_alu *)

Definition state_include (st: state) (stj: jit_state): Prop :=
  state.ins_len st = JITState.ins_len stj /\ ins st = ibpf stj.

Theorem jit_alu32_functional_correctness :
  forall st stj
    (Hverifier: jit_verifier st = Some(true, st))
    (Hinclude: state_include st stj),
    exists stk,
      jit_alu32 stj = Some stk /\
      (**r invariant info: *)
      pc_loc stj  = pc_loc stk /\
      flag stj    = flag stk /\
      regs_st stj = regs_st stk /\
      mrs_num stj = mrs_num stk /\
      bpf_mrs stj = bpf_mrs stk /\
      ins_len stj = ins_len stk /\
      ibpf stj    = ibpf stk /\
      jit_mem stj = jit_mem stk.
Proof.
  unfold jit_verifier, state_include, jit_alu32.
  unfold bindM, returnM.
  unfold monad.eval_ins_len.
  intros.
  unfold reset_init_entry_point; simpl.
  destruct negb; try discriminate.
  destruct negb; try discriminate.
  unfold state.eval_ins_len in *.

Admitted.