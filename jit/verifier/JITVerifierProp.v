From compcert Require Import Integers Values AST Ctypes.
From Coq Require Import ZArith Lia.

From bpf.comm Require Import BinrBPF Monad LemmaInt.
From bpf.verifier.comm Require Import state monad.
From bpf.model Require Import Syntax.
From bpf.verifier.synthesismodel Require Import opcode_synthesis verifier_synthesis.
From bpf.verifier.property Require Import invariant.

From bpf.jit.verifier Require Import JITVerifier DxJITVerifier.

Open Scope nat_scope.
Open Scope monad_scope.

(** * Equivalence between JITVerifier and DxJITVerifer *)

Theorem equivalence_jitverifier_dxjitverifier:
  forall st,
    JITVerifier.jit_verifier st = DxJITVerifier.jit_verifier st.
Proof.
  intros.
  unfold JITVerifier.jit_verifier, DxJITVerifier.jit_verifier.
  unfold rBPFValues.Int_leu, Dxmonad.bindM, Dxmonad.returnM.
  unfold Dxmonad.eval_ins_len, Dxmonad.eval_ins.
  f_equal.
Qed.


(** * JITVerifier implies rBPFVerifier *)

Lemma jitverifier_implies_rbpfverifier_aux2_some:
  forall k len op ins st
    (Haux2 : JITVerifier.jit_verifier_aux2 k len op ins st = Some (true, st)),
      verifier_synthesis.bpf_verifier_aux2 k len op ins st = Some (true, st).
Proof.
  unfold JITVerifier.jit_verifier_aux2, verifier_synthesis.bpf_verifier_aux2.
  unfold bindM, returnM.
  intros.
  destruct nat_to_opcode; try discriminate; try assumption.
  destruct Int.eq.
  - (**r IMM *)
    unfold JITVerifier.jit_verifier_opcode_alu32_imm in *.
    unfold bpf_verifier_opcode_alu32_imm.
    destruct nat_to_opcode_alu32_imm; try discriminate; try assumption.
  - (**r REG *)
    unfold JITVerifier.jit_verifier_opcode_alu32_reg in *.
    unfold bpf_verifier_opcode_alu32_reg.
    destruct nat_to_opcode_alu32_reg; try discriminate; try assumption.
    unfold JITVerifier.is_compcert_udiv, is_compcert_udiv' in *.
    unfold is_well_src, is_well_src'.
    unfold bindM, returnM in *.
    inversion Haux2.
    rewrite H0.
    rewrite Bool.andb_true_iff in H0.
    destruct H0.
    simpl.
    apply Int.same_if_eq in H0.
    rewrite H0.
    change (Int.ltu (Int.repr 10) Int.one) with false.
    simpl.
    reflexivity.
Qed.

Lemma jitverifier_aux2_some:
  forall st pc len op ins,
    exists b,
      JITVerifier.jit_verifier_aux2 pc len op ins st = Some (b ,st).
Proof.
  intros.
  unfold JITVerifier.jit_verifier_aux2.
  unfold bindM, returnM in *.
  destruct nat_to_opcode; try discriminate.
  + destruct Int.eq; try discriminate.
    * unfold bpf_verifier_opcode_alu64_imm.
      unfold bindM, returnM.
      destruct nat_to_opcode_alu64_imm;
       try discriminate; try eexists; reflexivity.
    * unfold bpf_verifier_opcode_alu64_reg.
      unfold bindM, returnM.
      destruct nat_to_opcode_alu64_reg;
       try discriminate; try eexists; reflexivity.
  + destruct Int.eq; try discriminate.
    * unfold JITVerifier.jit_verifier_opcode_alu32_imm.
      unfold bindM, returnM.
      destruct nat_to_opcode_alu32_imm;
       try discriminate; try eexists; reflexivity.
    * unfold JITVerifier.jit_verifier_opcode_alu32_reg.
      unfold bindM, returnM.
      destruct nat_to_opcode_alu32_reg;
       try discriminate; try eexists; reflexivity.
  + destruct Int.eq; try discriminate.
    * unfold bpf_verifier_opcode_branch_imm.
      unfold bindM, returnM.
      destruct nat_to_opcode_branch_imm;
       try discriminate; try eexists; reflexivity.
    * unfold bpf_verifier_opcode_branch_reg.
      unfold get_offset, is_well_src, is_well_jump.
      unfold bindM, returnM.
      destruct nat_to_opcode_branch_reg;
       try discriminate.
      all: try destruct is_well_src'; try discriminate.
      all: try eexists; try reflexivity.
      instantiate (1:=0%Z).
      change Int64.modulus with 18446744073709551616%Z.
      lia.
  + unfold bpf_verifier_opcode_load_imm.
    unfold bindM, returnM.
    destruct nat_to_opcode_load_imm;
     try discriminate; try eexists; reflexivity.
  + unfold bpf_verifier_opcode_load_reg.
    unfold bindM, returnM.
    destruct nat_to_opcode_load_reg;
     try discriminate; try eexists; reflexivity.
  + unfold bpf_verifier_opcode_store_imm.
    unfold bindM, returnM.
    destruct nat_to_opcode_store_imm;
     try discriminate; try eexists; reflexivity.
  + unfold bpf_verifier_opcode_store_reg.
    unfold bindM, returnM.
    destruct nat_to_opcode_store_reg;
     try discriminate; try eexists; reflexivity.
  + eexists; reflexivity.
Qed.

Open Scope Z_scope.

Lemma jitverifier_aux_never_none:
  forall st k,
    (Z.of_nat (ins_len st) <= Int.max_unsigned) ->
    (k <= (ins_len st))%nat ->
      JITVerifier.jit_verifier_aux k (ins_len st) st <> None.
Proof.
  intros.
  induction k.
  - simpl.
    unfold returnM.
    intro Hfalse; inversion Hfalse.
  - assert (Hlt: (k <= ins_len st)%nat). {
      apply le_Sn_le.
      assumption.
    }
    specialize (IHk Hlt).

    assert (HltZ: Z.of_nat k <= Z.of_nat (ins_len st)). {
      rewrite Nat2Z.inj_le in Hlt.
      assumption.
    }

    simpl.
    unfold eval_ins, get_opcode, bindM, returnM.

    unfold Int.cmpu.
    destruct Int.ltu eqn: Hcond. 2:{
      apply Bool.negb_true_iff in Hcond.
      apply Cle_Zle_unsigned in Hcond.
      do 2 rewrite Int.unsigned_repr in Hcond; lia.
    }

    unfold is_well_dst, bindM, returnM.

    unfold is_well_dst'.
    destruct Int.cmpu; [| intro Hfalse; inversion Hfalse].

    assert (Haux2:
  forall st pc len op ins,
    exists b,
      JITVerifier.jit_verifier_aux2 pc len op ins st = Some (b ,st)) by apply jitverifier_aux2_some.

    specialize (Haux2 st k (ins_len st) (BinrBPF.get_opcode (state.eval_ins (Int.repr (Z.of_nat k)) st))
    (state.eval_ins (Int.repr (Z.of_nat k)) st)).
    destruct Haux2 as (b & Haux2).
    rewrite Haux2.
    destruct b; [assumption | intro Hfalse; inversion Hfalse].
Qed.


Lemma jitverifier_aux_some:
  forall st k,
    (Z.of_nat (ins_len st) <= Int.max_unsigned) ->
    (k <= (ins_len st))%nat ->
      exists res,
        JITVerifier.jit_verifier_aux k (ins_len st) st = Some (res, st).
Proof.
  intros.
  destruct JITVerifier.jit_verifier_aux eqn: Haux.
  destruct p.
  assert (Hst_eq: st = s). {
    clear - Haux.
    induction k; simpl in Haux.
    - unfold returnM in Haux.
      inversion Haux.
      reflexivity.
    - unfold eval_ins, is_well_dst, get_opcode, bindM, returnM in Haux.
      destruct Int.cmpu in Haux; [| inversion Haux].
      destruct is_well_dst' in Haux; [| inversion Haux; reflexivity].
      specialize (jitverifier_aux2_some st k
            (ins_len st)).
      intros.
      specialize (H (BinrBPF.get_opcode (state.eval_ins (Int.repr (Z.of_nat k)) st))
            (state.eval_ins (Int.repr (Z.of_nat k)) st)).
      destruct H as (b0 & H).
      rewrite H in Haux.
      destruct b0; try discriminate.
      + apply IHk.
        assumption.
      + inversion Haux. reflexivity.
  }
  subst s.
  eexists; reflexivity.
  eapply jitverifier_aux_never_none in Haux; eauto.
  inversion Haux.
Qed.


Lemma jitverifier_implies_rbpfverifier_aux_some:
  forall st k,
    JITVerifier.jit_verifier_aux k (ins_len st) st = Some (true, st) ->
      verifier_synthesis.bpf_verifier_aux k (ins_len st) st = Some (true, st).
Proof.
  intros.
  induction k; simpl.
  - unfold returnM; reflexivity.
  - simpl in H.
    unfold bindM, returnM in *.
    unfold eval_ins in *.
    destruct Int.cmpu; try discriminate.
    unfold is_well_dst in *.
    simpl in *.
    destruct is_well_dst'; try discriminate.

    specialize jitverifier_aux2_some.
    intros.
    specialize (H0 st k (ins_len st)
        (BinrBPF.get_opcode (state.eval_ins (Int.repr (Z.of_nat k)) st))
        (state.eval_ins (Int.repr (Z.of_nat k)) st)).
    destruct H0.
    rewrite H0 in H.
    destruct x; [| inversion H; reflexivity].
    apply jitverifier_implies_rbpfverifier_aux2_some in H0.
    rewrite H0.
    apply IHk.
    assumption.
Qed.

Theorem jitverifier_implies_rbpfverifier_some:
  forall st,
     Z.of_nat (ins_len st) <= Int.max_unsigned ->
    JITVerifier.jit_verifier st = Some(true, st) ->
      verifier_synthesis.bpf_verifier st = Some (true, st).
Proof.
  unfold JITVerifier.jit_verifier, verifier_synthesis.bpf_verifier.
  unfold bindM, returnM.
  unfold eval_ins_len, state.eval_ins_len.
  intros.
  destruct negb; try discriminate.
  destruct negb; try discriminate.
  specialize jitverifier_aux_some.
  intros.
  assert (H2: (ins_len st <= ins_len st)%nat) by lia.
  specialize (H1 st (ins_len st) H H2).
  destruct H1.
  rewrite H1 in H0.
  destruct x; try discriminate.
  apply jitverifier_implies_rbpfverifier_aux_some in H1.
  rewrite H1.
  assumption.
Qed.