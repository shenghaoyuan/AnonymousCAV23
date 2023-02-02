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


Lemma ireg2nat_ireg_of_reg_reg2nat:
  forall r, ireg2nat (ireg_of_reg r) = reg2nat r.
Proof.
  destruct r; unfold ireg2nat, ireg_of_reg, reg2nat; intros; simpl; reflexivity.
Qed.

Lemma ireg_of_reg_eq:
  forall r0 r1,
    ireg_of_reg r0 = ireg_of_reg r1 -> r0 = r1.
Proof.
  intros.
  unfold ireg_of_reg in H.
  destruct r0; destruct r1; inversion H.
  all: reflexivity.
Qed.

Lemma jit_alu32_load_aux_list_spec:
  forall ins l,
    jit_alu32_load_aux_list ins = Some l ->
    (exists r0, l = [r0]) \/ (exists r0 r1, l = [r0; r1] /\ r0 <> r1).
Proof.
  unfold jit_alu32_load_aux_list; intros.
  destruct ins; inversion H.
  destruct a; inversion H.
  clear - H.
  destruct s.
  - destruct reg_eqb eqn: Heq.
    + apply reg_eqb_true in Heq.
      subst r0.
      left.
      destruct b; inversion H; exists r; reflexivity.
    + right.
      apply reg_eqb_false in Heq.
      destruct b; inversion H; exists r; exists r0; intuition.
  - left.
    destruct b; inversion H; exists r; reflexivity.
Qed.

Lemma nodup_load:
  forall l l1
    (Hldr: jit_alu32_load_list l = Some l1),
      NoDup l1.
Proof.
  induction l; simpl; intros.
  - inversion Hldr.
    constructor.
  - destruct jit_alu32_load_list eqn: Hload in Hldr; [| inversion Hldr].
    specialize (IHl l0 Hload).
    destruct jit_alu32_load_aux_list eqn: Haux; inversion Hldr.
    apply jit_alu32_load_aux_list_spec in Haux.
    destruct Haux.
    + destruct H as (r0 & H).
      subst l2.
      simpl.
      destruct list_in_bool eqn: Hb.
      * assumption.
      * apply List_in_bool_false in Hb.
        constructor; auto.
    + destruct H as (r0 & r1 & H & Hneq).
      subst l2.
      simpl.
      destruct list_in_bool eqn: Hb0.
      * destruct (list_in_bool reg_eqb r1 l0) eqn: Hb1.
        assumption.
        apply List_in_bool_false in Hb1.
        constructor; auto.
      * destruct (list_in_bool reg_eqb r1 l0) eqn: Hb1.
        apply List_in_bool_false in Hb0.
        constructor; auto.

        apply List_in_bool_false in Hb0, Hb1.
        constructor; auto.
        intros HF.
        apply Hb0.
        simpl in HF.
        intuition.

        constructor; auto.
Qed.

Lemma regs_agree_trans:
  forall l r st rs
    (Hreg_agree : regs_agree l st rs)
    (Heq : regs_agree [r] st rs),
      regs_agree (r :: l) st rs.
Proof.
  unfold regs_agree; intros.
  destruct H.
  - subst r0.
    apply Heq.
    unfold In.
    left; reflexivity.
  - apply Hreg_agree.
    assumption.
Qed.

Definition regs_layout (rbpf_st: state) (jit_st: jit_state) (regs_blk: block): Prop :=
  forall r,
    exists vi, (eval_reg r rbpf_st) = Some (Val.longofintu (Vint vi)) /\
      Mem.load Mint64 (jit_mem jit_st) regs_blk (8 * id_of_reg r) = Some (Val.longofintu (Vint vi)) /\
      Mem.load Mint32 (jit_mem jit_st) regs_blk (8 * id_of_reg r) = Some (Vint vi) /\
      forall vj, (eval_reg r rbpf_st) = Some (Val.longofintu (Vint vj)) -> vi = vj.

Definition memory_layout_jit_state (m: Mem.mem) (jit_state_blk flag_blk regs_blk: block): Prop :=
  Mem.load Mptr m jit_state_blk 0 = Some (Vptr flag_blk Ptrofs.zero) /\
  Mem.load Mptr m jit_state_blk 4 = Some (Vptr regs_blk Ptrofs.zero).

Definition match_registers (rbpf_st: state) (jit_st: jit_state) (regs_blk: block): Prop :=
  regs_st rbpf_st = Vptr regs_blk Ptrofs.zero /\
  jit_regs jit_st = Vptr regs_blk Ptrofs.zero /\
  forall r,
    exists vi, (eval_reg r rbpf_st) = Some (Val.longofintu (Vint vi)) /\
      (eval_jit_reg r jit_st) = Some (Val.longofintu (Vint vi)) /\
      Mem.load Mint32 (jit_mem jit_st) regs_blk (8 * id_of_reg r) = Some (Vint vi) /\
        forall vj, (eval_reg r rbpf_st) = Some (Val.longofintu (Vint vj)) -> vi = vj.

Definition match_flag (rbpf_st: state) (jit_st: jit_state) (flag_blk: block) : Prop :=
  flag rbpf_st = Vptr flag_blk Ptrofs.zero /\
  jit_flag jit_st = Vptr flag_blk Ptrofs.zero /\
  exists f,
    eval_flag rbpf_st = Some (Vint (int_of_flag f)) /\
    eval_jit_flag jit_st = Some (Vint (int_of_flag f)).

Definition ptr_range_perm (m: mem) (chunk: memory_chunk) (ptr: val) (p: permission): Prop :=
  match ptr with
  | Vptr b ofs => Mem.valid_access m chunk b (Ptrofs.unsigned ofs) p
  | _ => False
  end.

Definition arm_regs_agree (lsr: list reg) (rbpf_st: state) (rs0 rs1: Asm.regset): Prop :=
  regs_agree lsr rbpf_st rs0 -> regs_agree lsr rbpf_st rs1.

Fixpoint build_rs (l: list reg) (rbpf_st: state) (rs: Asm.regset): option Asm.regset :=
  match l with
  | [] => Some rs
  | hd :: tl =>
    match (eval_reg hd rbpf_st) with
    | Some v => match v with
                | Vlong vl => build_rs tl rbpf_st (
                    (rs # (ireg_of_reg hd) <- (Vint (Int.repr (Int64.unsigned vl)))) # PC <-
                (Val.offset_ptr (rs # (ireg_of_reg hd) <- (Vint (Int.repr (Int64.unsigned vl))) PC) wsize))
                | _ => None
                end
    | None => None
    end
  end.


Lemma build_rs_one:
  forall l st rs0 rs1 a
    (Hnodup_load : ~ In a l /\ NoDup l)
    (Hrs1_eq : build_rs l st rs0 = Some rs1)
    (Hreg_agree : regs_agree [a] st rs0),
      regs_agree [a] st rs1.
Proof.
  induction l; simpl; intros.
  - inversion Hrs1_eq.
    subst rs0.
    assumption.
  - destruct eval_reg eqn: Heval_reg; inversion Hrs1_eq.
    clear H0.
    destruct v; inversion Hrs1_eq.
    clear H0.
    destruct Hnodup_load as (HF & Hnodup).
    apply NoDup_cons_iff in Hnodup.

    assert (Hneq: ~ In a0 l). {
      intros Hf.
      apply HF.
      right.
      assumption.
    }

    assert (Hneq0: a <> a0). {
      intros Hf.
      apply HF.
      left.
      assumption.
    }

    eapply IHl.
    intuition.
    apply Hrs1_eq.

    clear - Hneq0 Hreg_agree.
    unfold regs_agree in *.
    intros.
    specialize (Hreg_agree _ H).
    destruct Hreg_agree as (vi & Hrs0_eq & Heval_reg1).

    unfold In in H.
    destruct H.
    2:{ inversion H. }
    subst a0.

    exists vi.

    split; [| assumption].
    rewrite Pregmap.gso.
    2:{ intros HF; inversion HF. }
    rewrite Pregmap.gso.
    2:{ intros HF; apply Hneq0.
        destruct r; destruct a; inversion HF; try reflexivity.
      }
    assumption.
Qed.

Lemma upd_jitted_list_max2:
  forall (v : int) (st0 st1 : jit_state),
    upd_jitted_list v st0 = Some st1 -> Z.of_nat (2 * jitted_len st1) <= Z.of_nat JITTED_LIST_MAX_LENGTH.
Proof.
  intros.
  unfold upd_jitted_list, upd_jitted_list' in H.
  destruct (2 * jitted_len st0 + 4 <=? JITTED_LIST_MAX_LENGTH)%nat eqn: Hcond; [| inversion H].
  destruct Mem.storev; [| inversion H].
  inversion H.
  apply Nat.leb_le in Hcond.
  unfold JITTED_LIST_MAX_LENGTH in *.
  change (jitted_len
     {|
       jit_pc := jit_pc st0;
       jit_flag := jit_flag st0;
       jit_regs := jit_regs st0;
       jit_mrs_num := jit_mrs_num st0;
       jit_mrs := jit_mrs st0;
       jit_ins_len := jit_ins_len st0;
       jit_ins := jit_ins st0;
       kv2 := kv2 st0;
       use_IR11 := use_IR11 st0;
       load_store_regs := load_store_regs st0;
       offset := offset st0;
       thumb_len := thumb_len st0;
       thumb := thumb st0;
       jitted_len := S (jitted_len st0);
       jitted_list := jitted_list st0;
       jit_mem := m
     |}) with (S (jitted_len st0)).
  lia.
Qed.

Lemma jit_alu32_thumb_load_jitted_len:
  forall l st0 st1,
    jit_alu32_thumb_load l st0 = Some st1 ->
      (jitted_len st1 = (jitted_len st0) + ((List.length l) * 2))%nat.
Proof.
  induction l; simpl; intros.
  - inversion H.
    subst st0.
    lia.
  - destruct jit_alu32_thumb_upd_load eqn: Hload; inversion H.
    clear H1.
    rename j into stk.
    unfold jit_alu32_thumb_upd_load in Hload.
    unfold jit_alu32_thumb_load_store_template_jit in Hload.
    Search upd_jitted_list.
    apply upd_jitted_list_jittted_len_2 in Hload.
    specialize (IHl _ _ H).
    rewrite IHl.
    rewrite <- Hload.
    lia.
Qed.

Lemma build_rs_pc:
  forall l st rs0 rs1 jit_blk ofs0
    (Hrange: ((Z.of_nat (List.length l)) * 4) <= ofs0 + ((Z.of_nat (List.length l)) * 4) <= 1000)
    (Hnodup: NoDup l)
    (Hrs1_eq : build_rs l st rs0 = Some rs1)
    (Heq : rs0 PC = Vptr jit_blk (Ptrofs.repr ofs0)),
      rs1 PC = Vptr jit_blk (Ptrofs.repr (ofs0 + ((Z.of_nat (List.length l)) * 4))).
Proof.
  induction l; simpl; intros.
  - inversion Hrs1_eq.
    subst rs0.
    rewrite Z.add_0_r.
    assumption.
  - apply NoDup_cons_iff in Hnodup.
    destruct eval_reg eqn: Heval_reg; inversion Hrs1_eq.
    clear H0.
    destruct v; inversion Hrs1_eq.
    clear H0.
    destruct Hnodup as (Hnot_in & Hnodup).
    assert (Heq1: Z.of_nat (Datatypes.length l) * 4 <= (ofs0 + 4) + Z.of_nat (Datatypes.length l) * 4 <= 1000) by lia.
    specialize (IHl st _ _ jit_blk (ofs0 + 4) Heq1 Hnodup Hrs1_eq).

    assert (Heq2: (ofs0 + 4 + Z.of_nat (Datatypes.length l) * 4) = 
      ofs0 + Z.pos (Pos.of_succ_nat (Datatypes.length l) * 4)) by lia.
    rewrite <- Heq2; clear Heq2.
    apply IHl.
    rewrite Pregmap.gss.
    rewrite Pregmap.gso.
    2:{ intros HF; inversion HF. }
    rewrite Heq.
    simpl.
    f_equal.
    unfold Ptrofs.add, wsize.
    change (Ptrofs.unsigned (Ptrofs.repr 4)) with 4.
    rewrite Ptrofs.unsigned_repr.
    reflexivity.
    change Ptrofs.max_unsigned with 4294967295; lia.
Qed.

Lemma jit_alu32_thumb_load_st_max:
  forall l st0 st1,
    Z.of_nat (2 * jitted_len st0) <= Z.of_nat JITTED_LIST_MAX_LENGTH ->
    jit_alu32_thumb_load l st0 = Some st1 ->
    Z.of_nat (2 * jitted_len st1) <= Z.of_nat JITTED_LIST_MAX_LENGTH.
Proof.
  induction l; simpl; intros.
  - inversion H0.
    subst st0.
    assumption.
  - destruct jit_alu32_thumb_upd_load eqn: Hload; [| inversion H0].
    unfold jit_alu32_thumb_upd_load in Hload.
    unfold jit_alu32_thumb_load_store_template_jit in Hload.
    destruct upd_jitted_list eqn: Hupd; [| inversion Hload].
    apply upd_jitted_list_max2 in Hload.
    specialize (IHl _ _ Hload H0).
    unfold JITTED_LIST_MAX_LENGTH in *.
    lia.
Qed.

Lemma jit_alu32_thumb_upd_load_unchange_jittted_list:
  forall r st0 st1
    (Hone : jit_alu32_thumb_upd_load r st0 = Some st1),
      jitted_list st0 = jitted_list st1.
Proof.
  intros.
  unfold jit_alu32_thumb_upd_load in Hone.
  unfold jit_alu32_thumb_load_store_template_jit in Hone.
  eapply upd_jitted_list_unchange_jittted_list_2; eauto.
Qed.

Lemma jit_alu32_thumb_upd_load_max:
  forall r st0 st1
    (Hone: jit_alu32_thumb_upd_load r st0 = Some st1),
      Z.of_nat (2 * jitted_len st0) <= Z.of_nat JITTED_LIST_MAX_LENGTH.
Proof.
  intros.
  unfold jit_alu32_thumb_upd_load in Hone.
  unfold jit_alu32_thumb_load_store_template_jit in Hone.
  destruct upd_jitted_list eqn: Hupd; [| inversion Hone].
  eapply upd_jitted_list_max; eauto.
Qed.

Lemma jit_alu32_thumb_upd_load_sub_mem:
  forall r st0 st1 arm_blk
    (Hptr: jitted_list st0 = Vptr arm_blk Ptrofs.zero)
    (Hmax: Z.of_nat (2 * jitted_len st0) <= Z.of_nat JITTED_LIST_MAX_LENGTH)
    (Hone : jit_alu32_thumb_upd_load r st0 = Some st1),
      sub_mem (jit_mem st0) (jit_mem st1) arm_blk (Z.of_nat (2 * jitted_len st0)).
Proof.
  unfold sub_mem; intros.
  unfold jit_alu32_thumb_upd_load in Hone.
  unfold jit_alu32_thumb_load_store_template_jit in Hone.
  eapply upd_jitted_list_load_2; eauto.
  lia.
Qed.

Lemma jit_alu32_thumb_upd_load_jittted_len:
  forall r st0 st1
    (Hone : jit_alu32_thumb_upd_load r st0 = Some st1),
      (jitted_len st0 <= jitted_len st1)%nat.
Proof.
  unfold sub_mem; intros.
  unfold jit_alu32_thumb_upd_load in Hone.
  unfold jit_alu32_thumb_load_store_template_jit in Hone.
  eapply upd_jitted_list_jittted_len_2 in Hone; eauto; lia.
Qed.

Lemma jit_load_sub_mem:
  forall l st0 st1 arm_blk
    (Hptr: jitted_list st0 = Vptr arm_blk Ptrofs.zero)
    (Hjit : jit_alu32_thumb_load l st0 = Some st1),
      sub_mem (jit_mem st0) (jit_mem st1) arm_blk (Z.of_nat (2 * jitted_len st0)).
Proof.
  induction l; unfold sub_mem; simpl; intros.
  - inversion Hjit; reflexivity.
  - destruct jit_alu32_thumb_upd_load eqn: Hone in Hjit; [| inversion Hjit].
    rename j into stk.
    apply jit_alu32_thumb_upd_load_unchange_jittted_list in Hone as Hptr1.
    symmetry in Hptr1.
    rewrite Hptr in Hptr1.
    specialize (IHl stk st1 arm_blk Hptr1 Hjit).
    apply jit_alu32_thumb_upd_load_max in Hone as Hmax.
    apply jit_alu32_thumb_upd_load_sub_mem with (arm_blk := arm_blk) in Hone as Htmp; auto.

    unfold sub_mem in *.

    rewrite <- IHl.
    + apply Htmp.
      lia.
    + apply jit_alu32_thumb_upd_load_jittted_len in Hone.
      lia.
Qed.

Lemma store_unchanged_on_1:
  forall m0 m1 m chunk b1 ofs v
  (Hunchanged : Mem.unchanged_on (fun (b : block) (_ : Z) => b <> b1) m0 m1)
  (Hstore : Mem.store chunk m0 b1 ofs v = Some m),
    Mem.unchanged_on (fun (b : block) (_ : Z) => b <> b1) m m1.
Proof.
  intros.
  destruct Hunchanged.
  split.
  - (**r unchanged_on_nextblock *)
    apply Mem.nextblock_store in Hstore.
    rewrite Hstore.
    assumption.
  - (**r unchanged_on_perm *)
    intros.
    assert (Heq: Mem.perm m b ofs0 k p <-> Mem.perm m0 b ofs0 k p). {
      split; intro HT.
      - eapply Mem.perm_store_2; eauto.
      - eapply Mem.perm_store_1; eauto.
    }
    apply iff_trans with (B := Mem.perm m0 b ofs0 k p); auto.
    apply unchanged_on_perm; auto.
    eapply Mem.store_valid_block_2; eauto.
  - (**r unchanged_on_contents *)
    intros.
    apply Mem.store_mem_contents in Hstore as Hcontents0; auto.
    rewrite Hcontents0.
    rewrite Maps.PMap.gso; auto.
    eapply unchanged_on_contents; eauto.
    eapply Mem.perm_store_2; eauto.
Qed.

Lemma store_unchanged_on_2:
  forall m0 m1 m chunk b1 ofs v
  (Hunchanged : Mem.unchanged_on (fun (b : block) (_ : Z) => b <> b1) m0 m1)
  (Hstore : Mem.store chunk m1 b1 ofs v = Some m),
    Mem.unchanged_on (fun (b : block) (_ : Z) => b <> b1) m0 m.
Proof.
  intros.
  destruct Hunchanged.
  split.
  - (**r unchanged_on_nextblock *)
    apply Mem.nextblock_store in Hstore.
    rewrite Hstore.
    assumption.
  - (**r unchanged_on_perm *)
    intros.
    assert (Heq: Mem.perm m1 b ofs0 k p <-> Mem.perm m b ofs0 k p). {
      split; intro HT.
      - eapply Mem.perm_store_1; eauto.
      - eapply Mem.perm_store_2; eauto.
    }
    apply iff_trans with (B := Mem.perm m1 b ofs0 k p); auto.
  - (**r unchanged_on_contents *)
    intros.
    apply Mem.store_mem_contents in Hstore as Hcontents0; auto.
    rewrite Hcontents0.
    rewrite Maps.PMap.gso; auto.
Qed.

Lemma store_unchanged_on_3:
  forall m0 m1 m chunk b1 b2 ofs v
  (Hunchanged : Mem.unchanged_on (fun (b : block) (_ : Z) => b <> b1 /\ b <> b2) m0 m1)
  (Hstore : Mem.store chunk m1 b1 ofs v = Some m),
    Mem.unchanged_on (fun (b : block) (_ : Z) => b <> b1 /\ b <> b2) m0 m.
Proof.
  intros.
  destruct Hunchanged.
  split.
  - (**r unchanged_on_nextblock *)
    apply Mem.nextblock_store in Hstore.
    rewrite Hstore.
    assumption.
  - (**r unchanged_on_perm *)
    intros.
    assert (Heq: Mem.perm m1 b ofs0 k p <-> Mem.perm m b ofs0 k p). {
      split; intro HT.
      - eapply Mem.perm_store_1; eauto.
      - eapply Mem.perm_store_2; eauto.
    }
    apply iff_trans with (B := Mem.perm m1 b ofs0 k p); auto.
  - (**r unchanged_on_contents *)
    intros.
    apply Mem.store_mem_contents in Hstore as Hcontents0; auto.
    rewrite Hcontents0.
    rewrite Maps.PMap.gso; auto.
    intuition.
Qed.

Lemma upd_jitted_list_unchanged_on_store:
  forall ins st0 st1 st b0
  (Hupd: upd_jitted_list ins st0 = Some st1)
    (Harm_blk : jitted_list st0 = Vptr b0 Ptrofs.zero)
    (Hunchanged : Mem.unchanged_on (fun (b : block) (_ : Z) => b <> b0) (jit_mem st0) (jit_mem st)),
  Mem.unchanged_on (fun (b : block) (_ : Z) => b <> b0) (jit_mem st1) (jit_mem st).
Proof.
  unfold upd_jitted_list, upd_jitted_list'; intros.
  destruct (2 * jitted_len st0 + 4 <=? JITTED_LIST_MAX_LENGTH)%nat; [| inversion Hupd].
  rewrite Harm_blk in Hupd.
  simpl in Hupd.
  destruct Mem.store eqn: Hstore; [| inversion Hupd].
  injection Hupd as Hst1_eq; subst st1.
  eapply store_unchanged_on_1; eauto.
Qed.

Lemma mem_unchanged_on_store:
  forall r st0 st1 st b1
    (Hupd_load : jit_alu32_thumb_upd_load r st0 = Some st1)
    (Harm_blk : jitted_list st0 = Vptr b1 Ptrofs.zero)
    (Hunchanged : Mem.unchanged_on (fun (b : block) (_ : Z) => b <> b1) (jit_mem st0)
               (jit_mem st)),
      Mem.unchanged_on (fun (b : block) (_ : Z) => b <> b1) (jit_mem st1) (jit_mem st).
Proof.
  intros.
  unfold jit_alu32_thumb_upd_load in Hupd_load.
  unfold jit_alu32_thumb_load_store_template_jit in Hupd_load.
  destruct upd_jitted_list eqn: Hupd0; [| inversion Hupd_load].
  rename j into stk.

  apply upd_jitted_list_unchange_jittted_list in Hupd0 as Harm_stk.

  eapply upd_jitted_list_unchanged_on_store in Hupd0; eauto.
  destruct upd_jitted_list eqn: Hupd1; [| inversion Hupd_load].
  rename j into stj.
  injection Hupd_load as Hst1_eq; subst stj.
  eapply upd_jitted_list_unchanged_on_store in Hupd1; eauto.
  rewrite <- Harm_stk.
  assumption.
Qed.

Lemma upd_jitted_list_valid_blk:
  forall v st0 st1 b b0
    (Hupd: upd_jitted_list v st0 = Some st1)
    (Harm_blk : jitted_list st0 = Vptr b Ptrofs.zero)
    (Hvalid_blk : Mem.valid_block (jit_mem st0) b0)
    (Hneq : b <> b0),
      Mem.valid_block (jit_mem st1) b0.
Proof.
  unfold upd_jitted_list, upd_jitted_list'; intros.
  destruct (2 * jitted_len st0 + 4 <=? JITTED_LIST_MAX_LENGTH)%nat; [| inversion Hupd].
  rewrite Harm_blk in Hupd.
  simpl in Hupd.
  destruct Mem.store eqn: Hstore; [| inversion Hupd].
  injection Hupd as Hst1_eq; subst st1.
  eapply Mem.store_valid_block_1; eauto.
Qed.

Lemma jit_alu32_load_list_tl:
  forall l a l1
    (Hldr : jit_alu32_load_list l = Some (a :: l1)),
      exists lr : list bpf_instruction, jit_alu32_load_list lr = Some l1.
Proof.
  induction l; simpl; intros.
  - inversion Hldr.
  - destruct jit_alu32_load_list eqn: Hload in Hldr; [| inversion Hldr].
    destruct jit_alu32_load_aux_list eqn: Haux in Hldr; [| inversion Hldr].
    apply jit_alu32_load_aux_list_spec in Haux.
    destruct Haux.
    + destruct H as (r0 & H); subst l2.
      injection Hldr as Heq.
      destruct list_in_bool.
      * subst l0.
        specialize (IHl _ _ Hload).
        assumption.
      * inversion Heq.
        subst a0 l1.
        exists l; assumption.
    + destruct H as (r0 & r1 & H & Hneq).
      injection Hldr as Heq.
      subst l2.
      simpl in Heq.
      destruct list_in_bool eqn: Hb0 in Heq.
      * destruct list_in_bool eqn: Hb1 in Heq.
        { subst l0.
          eapply IHl; eauto.
        }
        { inversion Heq.
          subst a0 l1.
          exists l; assumption.
        }
      * destruct list_in_bool eqn: Hb1 in Heq.
        { inversion Heq.
          subst a0 l1.
          exists l; assumption.
        }
        { inversion Heq.
          subst a0 l1.
          exists ((BPF_BINARY A32 BPF_ADD r1 (inl r1)) :: l).
          simpl.
          rewrite Hload.
          rewrite reg_eqb_refl.
          simpl.
          rewrite Hb1.
          reflexivity.
        }
Qed.

Lemma upd_jitted_list_load_other:
  forall i st0 st1 ofs chunk arm_blk regs_blk,
    jitted_list st0 = Vptr arm_blk Ptrofs.zero ->
    arm_blk <> regs_blk ->
    upd_jitted_list i st0 = Some st1 ->
      Mem.load chunk (jit_mem st0) regs_blk ofs =
      Mem.load chunk (jit_mem st1) regs_blk ofs.
Proof.
  unfold upd_jitted_list, upd_jitted_list'; intros.
  destruct (2 * jitted_len st0 + 4 <=? JITTED_LIST_MAX_LENGTH)%nat; [| inversion H1].
  rewrite H in H1.
  simpl in H1.
  destruct Mem.store eqn: Hstore; [| inversion H1].
  symmetry.
  inversion H1.
  eapply Mem.load_store_other; eauto.
Qed.


Section JITPreSpillingLoad.
  Variable ge : genv.

  (** Definition *)
  Variable flag_blk: block.
  Variable regs_blk: block.
  Variable jit_blk: block.
  Variable jit_state_blk: block.

  Record match_state_jit (rbpf_st: state) (jit_st: jit_state): Prop :=
  {
    munchange:  Mem.unchanged_on (fun b _ => b <> jit_blk /\ b <> jit_state_blk) (bpf_m rbpf_st) (jit_mem jit_st);
    mpc      :  pc_loc rbpf_st = jit_pc jit_st;
    mflag    :  match_flag rbpf_st jit_st flag_blk;
    mregs    :  match_registers rbpf_st jit_st regs_blk;
    mmrs_num :  mrs_num rbpf_st = jit_mrs_num jit_st;
    mbpf_mrs :  bpf_mrs rbpf_st = jit_mrs jit_st;
    mins_len :  ins_len rbpf_st = jit_ins_len jit_st;
    mins     :  ins rbpf_st = jit_ins jit_st;
    mjit     :  Vptr jit_blk Ptrofs.zero = jitted_list jit_st; (*
    mjit_len :  (jitted_len jit_st <= 500)%nat; *)

    mperm    :  ptr_range_perm (bpf_m rbpf_st) Mint32 (flag rbpf_st) Freeable /\
                (forall r, ptr_range_perm (bpf_m rbpf_st) Mint64
                    (Val.add (regs_st rbpf_st) (Vint (Int.repr (8 * (id_of_reg r))))) Freeable) /\
                ptr_range_perm (jit_mem jit_st) Mint32 (jit_flag jit_st) Freeable /\
                (forall r, ptr_range_perm (jit_mem jit_st) Mint64
                  (Val.add (jit_regs jit_st) (Vint (Int.repr (8 * (id_of_reg r))))) Freeable) /\
                (forall pc, (0 <= pc < Nat.div JITTED_LIST_MAX_LENGTH 2)%nat ->
                  ptr_range_perm (jit_mem jit_st) Mint16unsigned
                    (Val.add (JITState.jitted_list jit_st) (Vint (Int.repr (Z.of_nat (2 * pc))))) Freeable);
    minvalid :  ~Mem.valid_block (bpf_m rbpf_st) jit_blk /\
                  (flag_blk <> regs_blk /\ jit_blk <> flag_blk /\ jit_blk <> regs_blk) /\
                  (flag_blk <> jit_state_blk /\ jit_blk <> jit_state_blk /\ jit_state_blk <> regs_blk) /\
                  (forall b, b <> jit_blk ->
                    Mem.valid_block (bpf_m rbpf_st) b -> Mem.valid_block (jit_mem jit_st) b);
    mvalid   : memory_layout_jit_state (jit_mem jit_st) jit_state_blk flag_blk regs_blk;
  }.

Lemma upd_jitted_list_match_state_jit:
  forall st st0 st1 v
    (Hst: match_state_jit st st0)
    (Hupd: upd_jitted_list v st0 = Some st1),
      match_state_jit st st1.
Proof.
  unfold upd_jitted_list, upd_jitted_list'; intros.
  destruct (2 * jitted_len st0 + 4 <=? JITTED_LIST_MAX_LENGTH)%nat; [| inversion Hupd].
  destruct Hst.
  rewrite <- mjit0 in Hupd.
  simpl in Hupd.
  destruct Mem.store eqn: Hstore; inversion Hupd.
  clear Hupd H0.
  split; auto.
  - (**r Mem.unchanged_on *)
    simpl.
    eapply store_unchanged_on_3; eauto.
  - (**r match_flag *)
    unfold match_flag in mflag0.
    unfold match_flag; simpl.
    destruct mflag0 as (Hflag_eq0 & Hflag_eq1 & Hflag).
    split; [assumption | ].
    split; [assumption | ].
    destruct Hflag as (f & Heval_flag0 & Heval_flag1).
    exists f.
    split; [assumption | ].
    unfold eval_jit_flag in *.
    simpl.
    rewrite Hflag_eq1 in *.
    simpl in Heval_flag1.
    simpl.
    rewrite <- Heval_flag1.
    eapply Mem.load_store_other; eauto.
    left.
    destruct minvalid0 as (_ & Hneq & _); intuition.
  - (**r match_registers *)
    unfold match_registers in *.
    destruct mregs0 as (Hreg_eq0 & Hreg_eq1 & Hregs).
    split; [assumption | ].
    simpl.
    split; [assumption | ].
    intros.
    specialize (Hregs r).
    destruct Hregs as (rv & Heval_reg0 & Heval_reg1 & Hload & Hint).
    exists rv.
    split; [assumption | ].
    unfold eval_jit_reg in *.
    rewrite Hreg_eq1 in *.
    simpl in Heval_reg1.
    simpl.
    split.
    + rewrite <- Heval_reg1.
      eapply Mem.load_store_other; eauto.
      left.
      destruct minvalid0 as (_ & Hneq & _); intuition.
    + split.
      * rewrite <- Hload.
        eapply Mem.load_store_other; eauto.
        left.
        destruct minvalid0 as (_ & Hneq & _); intuition.
      * intros.
        specialize (Hint vj H).
        assumption.
  - (**r ptr_range_perm *)
    unfold ptr_range_perm in *.
    destruct mperm0 as (Hperm0 & Hperm1 & Hperm2 & Hperm3 & Hperm4).
    split; [assumption | ].
    split; [assumption | ].
    unfold match_flag in mflag0.
    destruct mflag0 as (Hflag0 & Hflag1 & _).
    rewrite Hflag0, Hflag1 in *.
    rewrite <- mjit0 in *.
    unfold match_registers in mregs0.
    destruct mregs0 as (Hregs0 & Hregs1 & Hregs).
    rewrite Hregs0, Hregs1 in *.
    split.
    {
      intros.
      simpl.
      eapply Mem.store_valid_access_1; eauto.
    }

    split.
    {
      intros.
      simpl.
      specialize (Hperm3 r).
      simpl in Hperm3.
      eapply Mem.store_valid_access_1; eauto.
    }

    intros.
    simpl.
    simpl in Hperm4.
    specialize (Hperm4 pc H).
    eapply Mem.store_valid_access_1; eauto.
  - (**r Mem.valid_block *)
    destruct minvalid0 as (Hvalid0 & Hvalid1 & Hvalid2 & Hvalid3).
    split; [assumption | ].
    split; [assumption | ].
    split; [assumption | ].
    intros.
    simpl.
    specialize (Hvalid3 b H H0).
    eapply Mem.store_valid_block_1; eauto.
  - (**r memory_layout_jit_state *)
    unfold memory_layout_jit_state in *.
    destruct mvalid0 as (Hload0 & Hload1).
    split; simpl.
    + rewrite <- Hload0.
      eapply Mem.load_store_other; eauto.
      left.
      destruct minvalid0 as (_ & _ & Hneq & _); intuition.
    + rewrite <- Hload1.
      eapply Mem.load_store_other; eauto.
      left.
      destruct minvalid0 as (_ & _ & Hneq & _); intuition.
Qed.

  Definition jitted_arm_initial_state (rs: Asm.regset) (jit_st: jit_state) (ofs: ptrofs): Prop :=
      (rs IR0) = Vptr jit_blk ofs /\
      (rs IR1) = Vptr jit_state_blk Ptrofs.zero /\
      (rs IR0) = (rs PC).

  Definition jitted_arm_initial_state_load (rs: Asm.regset) (ofs: ptrofs): Prop :=
    (rs IR12) = Vptr regs_blk Ptrofs.zero /\ (**r load stage IR12 is the start address of regs block *)
    (rs PC) = Vptr jit_blk ofs.

  Lemma jit_load_one_simulation: forall r l v rbpf_st jit_st0 jit_st1 jit_st_final arm_blk rs0 rs1 ofs0 ofs1
    (Hupd_load : jit_alu32_thumb_upd_load r jit_st0 = Some jit_st1)

    (Hlist_not_in: ~ List.In r l)
    (Hblk_eq: arm_blk = jit_blk)
    (Hvalid_blk: Mem.valid_block (jit_mem jit_st1) jit_state_blk)
    (Hblk_neq: arm_blk <> jit_state_blk)
    (Hblk_neq1: arm_blk <> regs_blk)
    (Hlayout: regs_layout rbpf_st jit_st0 regs_blk)
    (Hunchanged: Mem.unchanged_on (fun b _ => b <> jit_blk) (jit_mem jit_st1) (jit_mem jit_st_final))

    (Hmem: sub_mem (jit_mem jit_st1) (jit_mem jit_st_final) jit_blk ofs1)
    (Hofs0 : ofs0 = Z.of_nat (jitted_len jit_st0 + (jitted_len jit_st0 + 0)))
    (Hofs1 : ofs1 = Z.of_nat (jitted_len jit_st1 + (jitted_len jit_st1 + 0)))
    (Harm_blk : jitted_list jit_st0 = Vptr arm_blk Ptrofs.zero)
    (Harm_st0 : jitted_arm_initial_state_load rs0 (Ptrofs.repr ofs0))
    (Hmatch_st0 : match_state_jit rbpf_st jit_st0)

    (Hst: match_state_core rbpf_st l arm_blk ofs0 jit_st_final (State rs0 (jit_mem jit_st_final)))

    (Hreg_rv : (eval_reg r rbpf_st) = Some (Val.longofintu (Vint v)))
    (Hrs1_eq: (rs0 # (ireg_of_reg r) <- (Vint v)) # PC <-
                  (Val.offset_ptr (rs0 # (ireg_of_reg r) <- (Vint v) PC) wsize) = rs1),
      match_state_jit rbpf_st jit_st1 /\
      star BinSem.step ge (State rs0 (jit_mem jit_st_final)) E0 (State rs1 (jit_mem jit_st_final)) /\
      match_state_core rbpf_st (r :: l) arm_blk ofs1 jit_st_final (State rs1 (jit_mem jit_st_final)).
  Proof.
    intros.
    unfold jit_alu32_thumb_upd_load in Hupd_load.
    unfold jit_alu32_thumb_load_store_template_jit in Hupd_load.
    unfold jitted_arm_initial_state_load in Harm_st0.
    destruct Harm_st0 as (Hrs_12 & Hrs_pc).
    remember (State rs0 (jit_mem jit_st_final)) as arm_st0.
    destruct Hst as [l rbpf_st arm_rs jit_st_final arm_blk ofs0].
    injection Heqarm_st0 as Hrs_eq.
    subst arm_rs.
    rewrite <- Hblk_eq in *.

    split.
    { (**r match_state_jit *)
      destruct upd_jitted_list eqn: Hupd; [| inversion Hupd_load].
      eapply upd_jitted_list_match_state_jit in Hupd; eauto.
      eapply upd_jitted_list_match_state_jit; eauto.
    }

    unfold regs_layout in Hlayout.
    specialize (Hlayout r).
    destruct Hlayout as (vi & Hlayout).
    assert (Hreg_eq: Mem.load Mint32 (jit_mem jit_st1) regs_blk (8 * id_of_reg r) = Some (Vint vi)). {
      destruct Hlayout as (_ & _ & Hload & _).
      rewrite <- Hload.
      symmetry.
      destruct upd_jitted_list eqn: Hupd; [| inversion Hupd_load].

      rename j into stk.
      eapply upd_jitted_list_unchange_jittted_list in Hupd as Hstk_blk; eauto.

      eapply upd_jitted_list_load_other in Hupd; eauto.
      rewrite Hupd.
      eapply upd_jitted_list_load_other in Hupd_load; eauto.
      rewrite <- Hstk_blk.
      assumption.
    }

    apply upd_jitted_list_jittted_len_2 in Hupd_load as Hlen_eq.

    assert (Hcond: (2 * jitted_len jit_st0 <= 1000)%nat). {
      simpl.
      unfold upd_jitted_list, upd_jitted_list' in Hupd_load.
      destruct (2 * jitted_len jit_st0 + 4 <=? JITTED_LIST_MAX_LENGTH)%nat eqn: Hcond1; [| inversion Hupd_load].
      clear Hupd_load.
      unfold JITTED_LIST_MAX_LENGTH in Hcond1.
      rewrite Nat.leb_le in Hcond1.
      lia.
    }

    assert (Hlen_eq0: Ptrofs.unsigned (Ptrofs.repr (Z.of_nat (jitted_len jit_st0 + (jitted_len jit_st0 + 0)))) = 
        (Z.of_nat (jitted_len jit_st0 + (jitted_len jit_st0 + 0)))). {
      rewrite Ptrofs.unsigned_repr.
      reflexivity.
      change Ptrofs.max_unsigned with 4294967295; lia.
    }
(*
    eexists. *)
    split.
    {
      eapply star_one.
      eapply exec_step_bin.
      - (**r find_instr *)
        rewrite HPC_eq.

        assert (Heq: find_instr (Vptr arm_blk (Ptrofs.repr ofs0)) (jit_mem jit_st_final) =
                      find_instr (Vptr arm_blk (Ptrofs.repr ofs0)) (jit_mem jit_st1)). {
          unfold find_instr.
          rewrite Hofs0; simpl.
          clear - flag_blk regs_blk jit_blk jit_state_blk Hofs1 Hupd_load Hmem Hcond Hlen_eq Hlen_eq0.
          unfold sub_mem in Hmem.
          repeat rewrite <- Hmem.

          3:{
            rewrite Hofs1.
            rewrite Hlen_eq0.
            simpl.
            lia.
          }

          2:{
            simpl.
            unfold Ptrofs.add, Ptrofs.of_int.
            rewrite Hlen_eq0.
            change (Ptrofs.unsigned (Ptrofs.repr (Int.unsigned (Int.repr 2)))) with 2.

            assert (Hlen_eq1: Ptrofs.unsigned (Ptrofs.repr 
                  (Z.of_nat (jitted_len jit_st0 + (jitted_len jit_st0 + 0)) + 2))  = 
                (Z.of_nat (jitted_len jit_st0 + (jitted_len jit_st0 + 0)) + 2)). {
              rewrite Ptrofs.unsigned_repr.
              reflexivity.
              change Ptrofs.max_unsigned with 4294967295; lia.
            }
            rewrite Hlen_eq1.
            lia.
          }
          reflexivity.
        }

        rewrite Heq; clear Heq.

        instantiate (2 := Pldr (ireg_of_reg r) IR12 (SOimm (Int.mul (Int.repr (Z.of_nat (reg2nat r))) (Int.repr 8)))).
        instantiate (1 := true).
        eapply lemma_thumb_ldr; eauto.
        + change (Int.unsigned (Int.repr 8)) with 8.
          rewrite Int.unsigned_repr.
          * destruct r; simpl; lia.
          * change Int.max_unsigned with 4294967295; destruct r; simpl; lia.
        + unfold int_of_ireg.
          change (Z.of_nat (ireg2nat IR12)) with 12.
          rewrite ireg2nat_ireg_of_reg_reg2nat.
          change (Int.unsigned (Int.repr 8)) with 8.
          assumption.
      - (**r exec_instr *)
        simpl.
        rewrite Hrs_12; simpl.
        rewrite Ptrofs.add_zero_l.
        unfold exec_load; simpl.
        erewrite Mem.load_unchanged_on_1; eauto.

        2: { (**r Mem.valid_block (jit_mem jit_st1) regs_blk *)

          destruct Hlayout as (_ & Hload & _).
          apply rBPFMemType.load_valid_block in Hload.
          destruct upd_jitted_list eqn: Hupd; [| inversion Hupd_load].
          rename j into stk.
          eapply upd_jitted_list_unchange_jittted_list in Hupd as Hstk_blk.
          eapply upd_jitted_list_valid_blk in Hupd; eauto.
          eapply upd_jitted_list_valid_blk in Hupd_load; eauto.
          rewrite <- Hstk_blk.
          assumption.
        }


        2:{ (**r regs_blk <> arm_blk *)
          intros.
          simpl.
          auto.
        }

        assert (Heq: (Ptrofs.unsigned (Ptrofs.of_int (Int.mul (Int.repr (Z.of_nat (reg2nat r))) (Int.repr 8)))) =
              (8 * id_of_reg r)). {
          clear.
          unfold Ptrofs.of_int, Int.mul, id_of_reg.
          change (Int.unsigned (Int.repr 8)) with 8.
          rewrite Int.unsigned_repr.
          rewrite Int.unsigned_repr.
          rewrite Ptrofs.unsigned_repr.
          unfold reg2nat; destruct r; reflexivity.
          change Ptrofs.max_unsigned with 4294967295; destruct r; simpl; lia.
          change Int.max_unsigned with 4294967295; destruct r; simpl; lia.
          rewrite Int.unsigned_repr.
          change Int.max_unsigned with 4294967295; destruct r; simpl; lia.
          change Int.max_unsigned with 4294967295; destruct r; simpl; lia.
        }

        rewrite Heq; clear Heq.
        rewrite Hreg_eq.

        simpl.
        rewrite <- Hrs1_eq.
        unfold nextinstr_nf, nextinstr.
        destruct Hlayout as (Heval_reg & _ & _ & Hint).
        specialize (Hint _ Hreg_rv).
        subst vi.
        reflexivity.
    }

    split.
    { rewrite <- Hrs1_eq.
      clear - flag_blk regs_blk jit_blk jit_state_blk Hlist_not_in Hlayout Hreg_agree Hreg_eq Hreg_rv.
      - unfold regs_agree in *.
        intros.
        simpl in H.
        destruct H.
        + (**r r = r0 *)
          subst r0.
          exists vi.
          split.
          * rewrite Pregmap.gso.
            2:{ intros HF; inversion HF. }
            rewrite Pregmap.gss.
            destruct Hlayout as (Heval_reg & _ & _ & Hint).
            specialize (Hint _ Hreg_rv).
            subst vi.
            reflexivity.
          * destruct Hlayout as (Heval_reg & _).
            assumption.
        + (**r In r0 l *)
          specialize (Hreg_agree r0 H).
          destruct Hreg_agree as (vk & Hreg_eq0 & Hreg_eq1).
          exists vk.
          split; [| assumption ].
          rewrite Pregmap.gso.
          2:{ intros HF; inversion HF. }
          assert (Hneq: r0 <> r). {
            clear - H Hlist_not_in.
            intros HF; apply Hlist_not_in; subst r; assumption.
          }
          rewrite Pregmap.gso.
          2:{ intros HF; apply Hneq. destruct r0; destruct r; inversion HF; try reflexivity. }
          apply Hreg_eq0.
    }

    { clear - HPC_eq Hrs1_eq Hofs0 Hofs1 Hlen_eq Hcond.
      rewrite <- Hrs1_eq.
      rewrite Pregmap.gss.
      rewrite Pregmap.gso.
      2:{ intros HF; inversion HF. }
      rewrite <- Hlen_eq in Hofs1.
      rewrite Hofs0 in HPC_eq.
      rewrite HPC_eq, Hofs1.
      assert (Heq: (Z.of_nat (S (S (jitted_len jit_st0)) + (S (S (jitted_len jit_st0)) + 0))) = 
          (Z.of_nat (jitted_len jit_st0 + (jitted_len jit_st0 + 0))) + 4) by lia.
      rewrite Heq; clear Heq.
      simpl.
      f_equal.
      unfold wsize, Ptrofs.add.
      change (Ptrofs.unsigned (Ptrofs.repr 4)) with 4.
      rewrite Ptrofs.unsigned_repr.
      reflexivity.
      change Ptrofs.max_unsigned with 4294967295; simpl; lia.
    }
  Qed.


  Lemma jit_load_simulation: forall l1 l rbpf_st jit_st0 jit_st1 jit_st_final rs0 rs1 ofs0 ofs1
    (Hldr: jit_alu32_load_list l = Some l1)
    (Hjit_load: jit_alu32_thumb_load l1 jit_st0 = Some jit_st1)
    (Hofs0: ofs0 = (Z.of_nat (2 * (jitted_len jit_st0))))
    (Hofs1: ofs1 = (Z.of_nat (2 * (jitted_len jit_st1))))
    (Harm_blk: jitted_list jit_st0 = Vptr jit_blk Ptrofs.zero)
    (Hmem: sub_mem (jit_mem jit_st1) (jit_mem jit_st_final) jit_blk ofs1)

    (Hunchanged: Mem.unchanged_on (fun (b : block) (_ : Z) => b <> jit_blk) (jit_mem jit_st0) (jit_mem jit_st_final))

    (Hst: match_state_jit rbpf_st jit_st0)
    (Harm_st0: jitted_arm_initial_state_load rs0 (Ptrofs.repr ofs0))
    (Hrs1_eq: build_rs l1 rbpf_st rs0 = Some rs1),
      (* exists rs1, *)
        match_state_jit rbpf_st jit_st1 /\
        star BinSem.step ge (State rs0 (jit_mem jit_st_final)) E0 (State rs1 (jit_mem jit_st_final)) /\
        match_state_core rbpf_st l1 jit_blk ofs1 jit_st_final (State rs1 (jit_mem jit_st_final)).
  Proof.
    induction l1.
    { (**r l = [] *)
      simpl; intros.
      injection Hrs1_eq as Hrs_eq; subst rs1.
      injection Hjit_load as Hst_eq; subst jit_st1.
      split; [assumption | ].
      split.
      - econstructor; eauto.
      - split.
        + unfold regs_agree; simpl; intros.
          inversion H.
        + unfold jitted_arm_initial_state_load in Harm_st0.
          destruct Harm_st0 as (_ & Heq).
          rewrite Heq, Hofs1, Hofs0.
          reflexivity.
    }
    (**r l <> [] *)
    simpl; intros.

    apply nodup_load in Hldr as Hnodup_load.

    destruct jit_alu32_thumb_upd_load eqn: Hupd_load in Hjit_load; [| inversion Hjit_load].
    rename j into jit_stk.

    assert (Hexists_l: exists lr, jit_alu32_load_list lr = Some l1). {
      eapply jit_alu32_load_list_tl; eauto.
    }
    destruct Hexists_l as (lr & Hexists_l).
    specialize (IHl1 lr rbpf_st jit_stk jit_st1 jit_st_final).

    destruct jit_alu32_load_list eqn: Hnl1 in Hldr; [| inversion Hldr].
    rename l0 into nl1.

    assert (Hreg_val: exists v, eval_reg a rbpf_st = Some (Val.longofintu (Vint v))). {
      destruct Hst.
      unfold match_registers in mregs0.
      destruct mregs0 as (Hreg_blk & Hjit_blk & Hmregs0).
      specialize (Hmregs0 a).
      destruct Hmregs0 as (vi & Heval_reg & _).
      exists vi. assumption.
    }

    destruct Hreg_val as (v & Hreg_val).

    eapply jit_load_one_simulation with
      (rbpf_st := rbpf_st) (l := []) (v := v) (jit_st_final := jit_st_final) in Hupd_load as Hone_step; eauto.
    - destruct Hone_step as (Hmatch_state & Hstar & Hmatch_core).
      remember ((rs0 # (ireg_of_reg a) <- (Vint v)) # PC <-
             (Val.offset_ptr (rs0 # (ireg_of_reg a) <- (Vint v) PC) wsize)) as rsk.
      rewrite Hreg_val in Hrs1_eq.
      unfold Val.longofintu in Hrs1_eq.
      specialize (IHl1 rsk rs1).

      specialize (IHl1  (Z.of_nat (2 * jitted_len jit_stk)) ).
      specialize (IHl1 (Z.of_nat (2 * jitted_len jit_st1)) ).
      specialize (IHl1 Hexists_l Hjit_load).

      assert (Heq: Z.of_nat (2 * jitted_len jit_stk) = Z.of_nat (2 * jitted_len jit_stk)) by reflexivity.
      specialize (IHl1 Heq); clear Heq.

      assert (Heq: Z.of_nat (2 * jitted_len jit_st1) = Z.of_nat (2 * jitted_len jit_st1)) by reflexivity.
      specialize (IHl1 Heq); clear Heq.

      assert (Heq: jitted_list jit_stk = Vptr jit_blk Ptrofs.zero). {
        unfold jit_alu32_thumb_upd_load in Hupd_load.
        unfold jit_alu32_thumb_load_store_template_jit in Hupd_load.
        apply upd_jitted_list_unchange_jittted_list_2 in Hupd_load.
        rewrite <- Hupd_load.
        assumption.
      }
      specialize (IHl1 Heq); clear Heq.
      simpl in IHl1.
      rewrite Hofs1 in Hmem; specialize (IHl1 Hmem).
      assert (Heq: Mem.unchanged_on (fun (b : block) (_ : Z) => b <> jit_blk) 
         (jit_mem jit_stk) (jit_mem jit_st_final)). {
        eapply mem_unchanged_on_store; eauto.
      }
      specialize (IHl1 Heq); clear Heq.

      specialize (IHl1 Hmatch_state).

      unfold jit_alu32_thumb_upd_load in Hupd_load.
      unfold jit_alu32_thumb_load_store_template_jit in Hupd_load.
      apply upd_jitted_list_jittted_len_2 in Hupd_load as Hlen_eq.

      assert (Hcond: (2 * jitted_len jit_st0 <= 1000)%nat). {
        simpl.
        unfold upd_jitted_list, upd_jitted_list' in Hupd_load.
        destruct (2 * jitted_len jit_st0 + 4 <=? JITTED_LIST_MAX_LENGTH)%nat eqn: Hcond1; [| inversion Hupd_load].
        clear Hupd_load.
        unfold JITTED_LIST_MAX_LENGTH in Hcond1.
        rewrite Nat.leb_le in Hcond1.
        lia.
      }

      assert (Hcond2: ( (2 * (jitted_len jit_st0)) + 4 <= 1000)%nat). {
        simpl.
        unfold upd_jitted_list, upd_jitted_list' in Hupd_load.
        destruct (2 * jitted_len jit_st0 + 4 <=? JITTED_LIST_MAX_LENGTH)%nat eqn: Hcond1; [| inversion Hupd_load].
        clear Hupd_load.
        unfold JITTED_LIST_MAX_LENGTH in Hcond1.
        rewrite Nat.leb_le in Hcond1.
        lia.
      }

      assert (Hlen_eq0: Ptrofs.unsigned (Ptrofs.repr (Z.of_nat (jitted_len jit_st0 + (jitted_len jit_st0 + 0)))) = 
          (Z.of_nat (jitted_len jit_st0 + (jitted_len jit_st0 + 0)))). {
        rewrite Ptrofs.unsigned_repr.
        reflexivity.
        change Ptrofs.max_unsigned with 4294967295; lia.
      }

      assert (Heq: jitted_arm_initial_state_load rsk
         (Ptrofs.repr (Z.of_nat (jitted_len jit_stk + (jitted_len jit_stk + 0))))). {
        unfold jitted_arm_initial_state_load.
        unfold jitted_arm_initial_state_load in Harm_st0.
        rewrite <- Hlen_eq.
        rewrite Heqrsk.

        destruct Harm_st0 as (Hrs_12 & Hrs_pc).
        split.
        - rewrite Pregmap.gso.
          2:{ intros HF; inversion HF. }
          rewrite Pregmap.gso.
          2:{ unfold ireg_of_reg; intros HF; destruct a; inversion HF. }
          assumption.
        - rewrite Pregmap.gss.
          rewrite Pregmap.gso.
          2:{ unfold ireg_of_reg; intros HF; destruct a; inversion HF. }
          rewrite Hrs_pc.
          assert (Heq: Z.of_nat (S (S (jitted_len jit_st0)) + (S (S (jitted_len jit_st0)) + 0)) = 
            (Z.of_nat (jitted_len jit_st0 + (jitted_len jit_st0 + 0))) + 4) by lia.
          rewrite Heq; clear Heq.
          simpl.
          unfold Ptrofs.add, wsize.
          f_equal.
          change (Ptrofs.unsigned (Ptrofs.repr 4)) with 4.
          rewrite Hofs0.
          rewrite Ptrofs.unsigned_repr.
          reflexivity.
          change Ptrofs.max_unsigned with 4294967295; lia.
      }
      specialize (IHl1 Heq); clear Heq.

      rewrite Int64.int_unsigned_repr in Hrs1_eq.
      rewrite Int.repr_unsigned in Hrs1_eq.
      rewrite <- Heqrsk in Hrs1_eq.

      specialize (IHl1 Hrs1_eq).

      destruct IHl1 as (Hmatch_state_k & Hstar_k & Hmatch_core_k).

      split; [ assumption | ].
      split.
      + eapply star_trans with (s2 := (State rsk (jit_mem jit_st_final))) (t1 := E0); eauto.
      +
        eapply exec_step.
        { (**r regs_agree *)

          clear Hstar Hunchanged Hmem.
          clear Hst Hmatch_state Harm_st0 Hmatch_state_k.
          rewrite <- Hofs1 in Hmatch_core_k.
          remember (State rs1 (jit_mem jit_st_final)) as arm_st1.
          induction Hmatch_core_k as [l1 rbpf_st rs1' jit_st_final jit_blk ofs1].
          injection Heqarm_st1 as Hrs1'_eq.
          subst rs1'.
          remember [a] as l0.
          remember (Z.of_nat (jitted_len jit_stk + (jitted_len jit_stk + 0))) as ofsk.
          remember (State rsk (jit_mem jit_st_final)) as arm_stk.
          induction Hmatch_core as [l0 rbpf_st rsk' jit_st_final jit_blk ofsk].

          injection Heqarm_stk as Hrsk_eq.
          subst rsk'.

          rewrite Heql0 in Hreg_agree0.
          rewrite Heqofsk in HPC_eq0.
          apply NoDup_cons_iff in Hnodup_load.
          clear - Hnodup_load Hreg_agree Hreg_agree0 Hrs1_eq.

          assert (Heq: regs_agree [a] rbpf_st rs1). {
            eapply build_rs_one; eauto.
          }

          clear - Hreg_agree Heq.
          apply regs_agree_trans; auto.
        }

        { (**r rs PC *)
          clear - Hnl1 Hldr Hlen_eq Hjit_load Harm_st0 Hrs1_eq Heqrsk Hofs0 Hofs1 Hmatch_core Hcond Hcond2 Hlen_eq0.
          unfold jitted_arm_initial_state_load in Harm_st0.
          destruct Harm_st0 as (_ & Hrs0_eq).

          remember (Z.of_nat (jitted_len jit_stk + (jitted_len jit_stk + 0))) as ofsk.
          rename Heqofsk into Hofsk.

          assert (Heq: rsk PC = Vptr jit_blk (Ptrofs.repr ofsk)). {
            rewrite Hofsk.
            rewrite Heqrsk.
            rewrite Pregmap.gss.
            rewrite Pregmap.gso.
            2:{ intros HF; inversion HF. }
            rewrite Hrs0_eq.
            simpl; unfold wsize, Ptrofs.add.
            f_equal.
            change (Ptrofs.unsigned (Ptrofs.repr 4)) with 4.
            rewrite <- Hlen_eq.
            assert (Heq: (Z.of_nat (S (S (jitted_len jit_st0)) + (S (S (jitted_len jit_st0)) + 0))) = 
              Z.of_nat (jitted_len jit_st0 + (jitted_len jit_st0 + 0)) + 4) by lia.
            rewrite Heq; clear Heq.
            rewrite Hofs0.
            rewrite Ptrofs.unsigned_repr.
            reflexivity.
            change Ptrofs.max_unsigned with 4294967295; lia.
          }

          eapply jit_alu32_thumb_load_st_max in Hjit_load as Hrange.
          2:{
            rewrite <- Hlen_eq.
            unfold JITTED_LIST_MAX_LENGTH.
            lia.
          }

          apply jit_alu32_thumb_load_jitted_len in Hjit_load.
          eapply build_rs_pc in Hrs1_eq; eauto.
          - rewrite Hrs1_eq.
            f_equal.
            rewrite Hofs1.
            rewrite Hjit_load.
            rewrite Hofsk.
            rewrite <- Hlen_eq.
            assert (Heq1: (Z.of_nat (S (S (jitted_len jit_st0)) + (S (S (jitted_len jit_st0)) + 0)) +
   Z.of_nat (Datatypes.length l1) * 4) =
              (Z.of_nat
     (S (S (jitted_len jit_st0)) + Datatypes.length l1 * 2 +
      (S (S (jitted_len jit_st0)) + Datatypes.length l1 * 2 + 0)))) by lia.
            rewrite Heq1; clear Heq1.
            reflexivity.
          - rewrite Hofsk.
            rewrite <- Hlen_eq.
            split.
            lia.
            rewrite Hjit_load in Hrange.
            rewrite <- Hlen_eq in Hrange.
            unfold JITTED_LIST_MAX_LENGTH in Hrange.
            lia.
          - injection Hldr as Hnl1_eq; subst nl1.
            apply nodup_load in Hnl1.
            apply NoDup_cons_iff in Hnl1.
            intuition.
        }

    - (**r Mem.valid_block *)
      assert (Hvalid_blk: Mem.valid_block (jit_mem jit_st0) jit_state_blk). {
        destruct Hst.
        destruct minvalid0 as (_ & Hblk_neq0 & Hblk_neq1 & Hvalid_blk).
        unfold memory_layout_jit_state in mvalid0.
        destruct mvalid0 as (mvalid0 & _).
        apply rBPFMemType.load_valid_block in mvalid0.
        assumption.
      }
      assert (Hneq: jit_blk <> jit_state_blk). {
        destruct Hst.
        clear - minvalid0.
        destruct minvalid0 as (_ & _ & Hneq & _).
        intuition.
      }
      clear - Hupd_load Harm_blk Hvalid_blk Hneq.
      unfold jit_alu32_thumb_upd_load in Hupd_load.
      unfold jit_alu32_thumb_load_store_template_jit in Hupd_load.
      destruct upd_jitted_list eqn: Hupd0; [| inversion Hupd_load].
      rename j into stk.
      eapply upd_jitted_list_unchange_jittted_list in Hupd0 as Harm_stk; eauto.
      eapply upd_jitted_list_valid_blk in Hupd0; eauto.
      eapply upd_jitted_list_valid_blk in Hupd_load; eauto.
      rewrite <- Harm_stk.
      assumption.
    - (**r jit_blk <> jit_state_blk *)
      destruct Hst.
      destruct minvalid0 as (_ & _ & Hblk_neq1 & Hvalid_blk).
      destruct Hblk_neq1 as (_ & Hblk_neq1 & _).
      apply Hblk_neq1.
    - (**r jit_blk <> regs_blk *)
      destruct Hst.
      destruct minvalid0 as (_ & Hblk_neq1 & _).
      destruct Hblk_neq1 as (_ & _ & Hblk_neq1).
      apply Hblk_neq1.
    - (**r regs_layout *)
      unfold regs_layout.
      intros.
      destruct Hst.
      unfold match_registers in mregs0.
      destruct mregs0 as (Hreg_blk0 & Hreg_blk1 & Hmregs).
      specialize (Hmregs r).
      destruct Hmregs as (vi & Heval_reg & Heval_jit_reg).
      exists vi.
      split; [ assumption | ].
      unfold eval_jit_reg in Heval_jit_reg.
      rewrite Hreg_blk1 in Heval_jit_reg.
      remember (8 * id_of_reg r) as rv.
      simpl in Heval_jit_reg.
      rewrite Ptrofs.add_zero_l in Heval_jit_reg.
      assert (Heq: Ptrofs.unsigned (Ptrofs.of_int (Int.repr rv)) = rv). {
        subst rv.
        unfold Ptrofs.of_int.
        rewrite Int.unsigned_repr.
        rewrite Ptrofs.unsigned_repr.
        change Ptrofs.max_unsigned with 4294967295; destruct r; simpl; lia.
        change Ptrofs.max_unsigned with 4294967295; destruct r; simpl; lia.
        change Int.max_unsigned with 4294967295; destruct r; simpl; lia.
      }
      rewrite Heq in Heval_jit_reg; clear Heq.
      simpl.
      assumption.
    - (**r Mem.unchanged_on *)
      eapply mem_unchanged_on_store; eauto.
    - (**r sub_mem: see proofcore *)
      eapply jit_alu32_thumb_upd_load_unchange_jittted_list in Hupd_load.
      rewrite Hupd_load in Harm_blk.
      clear - Hofs1 Harm_blk Hjit_load Hmem.
      assert (Hle: Z.of_nat (2 * jitted_len jit_stk) <= Z.of_nat (2 * jitted_len jit_st1)). {
        clear - Hjit_load.
        eapply jit_alu32_thumb_load_jitted_len in Hjit_load; eauto.
        lia.
      }

      eapply jit_load_sub_mem in Hjit_load; eauto.
      subst ofs1.
      eapply sub_mem_less_than with (ofs1 := Z.of_nat (2 * jitted_len jit_stk)) in Hmem; eauto.
      eapply sub_mem_trans; eauto.
    - (**r match_state_core *)
      unfold jitted_arm_initial_state_load in Harm_st0.
      destruct Harm_st0 as (Hrs_12 & Hrs_pc).
      eapply exec_step; eauto.

      unfold regs_agree.
      intros.
      inversion H.
  Qed.

End JITPreSpillingLoad.


Section JITStoreReloadingPost.
  Variable ge : genv.

  (** Axiom *)

  Variable lemma_jitted_list_is_vptr: forall st,
    exists b, jitted_list st = Vptr b Ptrofs.zero.
  Variable lemma_max_jitted_len: forall st,
    (jitted_len st <= 500)%nat.

  (** Definition *)
End JITStoreReloadingPost.