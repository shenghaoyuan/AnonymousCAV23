From compcert.lib Require Import Integers.
From compcert.arm Require Import Asm AsmSyntax BinSyntax BinSem BinDecode.
From compcert.common Require Import Values Globalenvs Smallstep Memory Memdata Events AST.

From bpf.comm Require Import Flag BinrBPF ListAsArray Regs.
From bpf.model Require Import Encode Syntax.
From bpf.monadicmodel2 Require Import ConcreteState.
From bpf.jit.thumb Require Import LoadStoreRegs JITState.
From bpf.jit.thumb Require Import Arm32Reg ThumbJITOpcode ThumbInsOp.

From bpf.jit.verification Require Import rBPFSemInd JITSimple JITSimpleProof0 JITSimpleProofCore.
From bpf.jit.simulation Require Import BitfieldLemma.

From Coq Require Import List ZArith Arith String Lia.
Import ListNotations.
Open Scope Z_scope.
Open Scope bool_scope.
Open Scope asm.

(**r similar to nodup_load in JITSimpleProof.v *)
Lemma nodup_stack:
  forall l1 l l0 st
    (Hldr: jit_alu32_stack_list l l0 st = l1),
      NoDup l1.
Proof.
  induction l1; simpl; intros.
  - constructor.
  - admit.
Admitted.