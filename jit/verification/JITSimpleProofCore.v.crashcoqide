From compcert.lib Require Import Integers.
From compcert.arm Require Import Asm AsmSyntax BinSyntax BinSem BinDecode.
From compcert.common Require Import Values Globalenvs Smallstep Memory Memdata Events AST.

From bpf.comm Require Import Flag BinrBPF ListAsArray Regs.
From bpf.model Require Import Encode Syntax.
From bpf.monadicmodel2 Require Import ConcreteState.
From bpf.jit.thumb Require Import LoadStoreRegs JITState.
From bpf.jit.thumb Require Import Arm32Reg ThumbJITOpcode ThumbInsOp.

From bpf.jit.verification Require Import rBPFSemInd JITSimple JITSimpleProof0.
From bpf.jit.simulation Require Import BitfieldLemma.

From Coq Require Import List ZArith Arith String Lia.
Import ListNotations.
Open Scope Z_scope.
Open Scope bool_scope.
Open Scope asm.

(** * Forward Simulation: JIT core *)

Definition sync_regs := list reg.

Definition ins_is_sync_regs (ins: bpf_instruction) (lsr: sync_regs): Prop :=
  match ins with
  | BPF_BINARY a bop dst src =>
    match a with
    | A32 => (List.In dst lsr) /\ (
      match src with
      | inl r => List.In r lsr
      | inr i => True
      end)
    | A64 => False
    end
  | _ => False
  end.

Definition regs_agree (lsr: sync_regs) (rbpf_st: state) (arm_rs: Asm.regset): Prop :=
  forall r, List.In r lsr ->
    exists vi, arm_rs (ireg_of_reg r) = Vint vi /\
      (eval_reg r rbpf_st) = Some (Val.longofintu (Vint vi)).

Definition sub_mem (m0 m1: mem) (b: block) (ofs: Z): Prop :=
  forall chunk ofs1, 0 <= ofs1 /\ ofs1 + (size_chunk chunk) <= ofs -> Mem.load chunk m0 b ofs1 = Mem.load chunk m1 b ofs1.

Lemma sub_mem_store:
  forall m0 m1 m2 chunk b ofs0 ofs1 v
    (Hstore: Mem.store chunk m0 b ofs0 v = Some m1)
    (Hmem: sub_mem m1 m2 b ofs1)
    (Hrange: 0 <= ofs0 /\ ofs0 + size_chunk chunk <= ofs1),
      Mem.load chunk m1 b ofs0 = Mem.load chunk m2 b ofs0.
Proof.
  unfold sub_mem; intros.
  apply Hmem.
  assumption.
Qed.

Lemma sub_mem_trans:
  forall m0 m1 m2 b ofs
    (Hmem0: sub_mem m0 m1 b ofs)
    (Hmem1: sub_mem m1 m2 b ofs),
      sub_mem m0 m2 b ofs.
Proof.
  unfold sub_mem; intros.
  rewrite Hmem0; auto.
Qed.

Lemma sub_mem_less_than:
  forall m0 m1 b ofs0 ofs1
    (Hless: ofs1 <= ofs0)
    (Hmem: sub_mem m0 m1 b ofs0),
      sub_mem m0 m1 b ofs1.
Proof.
  unfold sub_mem; intros.
  rewrite Hmem; auto.
  lia.
Qed.

Inductive match_state_core: state -> sync_regs -> block -> Z -> jit_state -> Asm.state -> Prop :=
  | exec_step:
      forall lsr rbpf_st rs jit_st arm_blk ofs
        (Hreg_agree: regs_agree lsr rbpf_st rs)
        (HPC_eq: rs PC = Vptr arm_blk (Ptrofs.repr ofs)),
        match_state_core rbpf_st lsr arm_blk ofs jit_st (Asm.State rs (jit_mem jit_st)).

Lemma match_state_core_mem:
  forall st l b ofs jst ast,
    match_state_core st l b ofs jst ast ->
      exists rs, (Asm.State rs (jit_mem jst)) = ast.
Proof.
  intros.
  induction H.
  exists rs; reflexivity.
Qed.

Section JITCoreOne.
  Variable ge : genv.

  (** Axiom *)

  (* Variable mem_agree: val -> mem -> mem -> Prop. *)
  Variable lemma_regs_blk_eq: forall st,
    exists regs_blk, regs_st st = Vptr regs_blk Ptrofs.zero.
  Variable lemma_jitted_list_is_vptr: forall st,
    exists jitted_arm_blk, jitted_list st = Vptr jitted_arm_blk Ptrofs.zero.
  Variable lemma_max_jitted_len: forall st,
    (jitted_len st <= 500)%nat.

  (** Definition *)

  Lemma jit_core_one_simulation: forall ins lsr (* lsr1 *) rbpf_st0 rbpf_st1 jit_st0 jit_st1 jit_st_final arm_blk arm_st0 ofs0 ofs1
    (Hjit: bpf_alu32_to_thumb ins jit_st0 = Some jit_st1)
    (Hmem: sub_mem (jit_mem jit_st1) (jit_mem jit_st_final) arm_blk ofs1)
    (Hofs0: ofs0 = (Z.of_nat (2 * (jitted_len jit_st0))))
    (Hofs1: ofs1 = (Z.of_nat (2 * (jitted_len jit_st1))))
    (Harm_blk: jitted_list jit_st0 = Vptr arm_blk Ptrofs.zero)
    (Hst: match_state_core rbpf_st0 lsr arm_blk ofs0 jit_st_final arm_st0)
    (Hins_regs: ins_is_sync_regs ins lsr)
    (Hstep: rbpf_step rbpf_st0 ins rbpf_st1),
    exists arm_st1,
      plus BinSem.step ge arm_st0 E0 arm_st1 /\
      match_state_core rbpf_st1 lsr arm_blk ofs1 jit_st_final arm_st1.
  Proof.
    unfold bpf_alu32_to_thumb.
    intros.
    induction Hstep as [rbpf_st0 a op rd ri ret rbpf_st1].
    induction Hst as [lsr rbpf_st0 arm_rs jit_st_final arm_blk ofs0].
    destruct a; [| inversion Hjit].
    destruct ri.
    - (**r alu_reg *)
      unfold regs_agree in Hreg_agree.
      unfold ins_is_sync_regs in Hins_regs.
      destruct Hins_regs as (Hins_rd & Hins_r).
      specialize (Hreg_agree rd Hins_rd) as Hins_rd_eq.
      specialize (Hreg_agree r Hins_r) as Hins_r_eq.
      destruct Hins_rd_eq as (v0 & Hv0_eq & Hreg0).
      destruct Hins_r_eq as (v1 & Hv1_eq & Hreg1).

      specialize (lemma_jitted_list_is_vptr jit_st0) as Hjit_ptr0.

      unfold bpf_alu32_to_thumb_reg in Hjit.
      destruct op.
      + (**r add_reg *)
        simpl in *.
        unfold eval_alu_binary, eval_src32 in Heval_alu.
        rewrite Hreg0, Hreg1 in Heval_alu.
        injection Heval_alu as Heq.
        subst ret.
        rewrite ! Int64.int_unsigned_repr in Hupd_reg.
        unfold upd_jitted_list in Hjit.
        unfold upd_jitted_list' in Hjit.
        destruct (2 * jitted_len jit_st0 + 4 <=? JITTED_LIST_MAX_LENGTH)%nat eqn: Hmax_jit_size; inversion Hjit.

        rewrite Harm_blk in *.
        simpl in *.
        destruct Mem.store eqn: Hstore; [| inversion Hjit].

        assert (Hmem_eq: jit_mem jit_st1 = m). {
          clear - Hjit.
          inversion Hjit;
          simpl;
          reflexivity.
        }

        assert (Hjit_ptr_eq: jitted_list jit_st1 = Vptr arm_blk Ptrofs.zero). {
          clear - Hjit.
          inversion Hjit;
          simpl;
          reflexivity.
        }

        assert (Hjit_len_eq: jitted_len jit_st1 = S (jitted_len jit_st0)). {
          clear - Hjit.
          inversion Hjit;
          simpl;
          reflexivity.
        }

        eexists.
        split.
        * (**r we know jitted code is only one *)
          eapply plus_one.
          eapply exec_step_bin.
          {
            rewrite HPC_eq.
            unfold BinDecode.find_instr.

            rewrite Hofs0; simpl.
            subst m.

            rewrite Ptrofs.add_zero_l in *.
            unfold Ptrofs.of_int in Hstore.

            assert (Heq: (Int.unsigned (Int.repr (Z.of_nat (jitted_len jit_st0 + (jitted_len jit_st0 + 0))))) = 
                          (Z.of_nat (jitted_len jit_st0 + (jitted_len jit_st0 + 0)))). {
              clear - lemma_max_jitted_len.
              specialize (lemma_max_jitted_len jit_st0).
              rewrite Int.unsigned_repr.
              reflexivity.
              change Int.max_unsigned with 4294967295; lia.
            }
            rewrite Heq in Hstore.

            assert (Heq1:  Mem.load AST.Mint16unsigned (jit_mem jit_st_final) arm_blk
                            (Ptrofs.unsigned (Ptrofs.repr (Z.of_nat (jitted_len jit_st0 + (jitted_len jit_st0 + 0))))) = 
                          Mem.load AST.Mint16unsigned (jit_mem jit_st1) arm_blk
                            (Ptrofs.unsigned (Ptrofs.repr (Z.of_nat (jitted_len jit_st0 + (jitted_len jit_st0 + 0)))))). {
              clear - lemma_max_jitted_len Hmem Hstore Hofs1 Hjit_len_eq Heq.
              rewrite Hjit_len_eq in Hofs1.
              unfold sub_mem in Hmem.
              symmetry.
              apply Hmem.
              rewrite Hofs1.
              specialize (lemma_max_jitted_len jit_st0).
              rewrite Ptrofs.unsigned_repr; [ | change Ptrofs.max_unsigned with 4294967295; lia].
              simpl. lia.
            }
            rewrite Heq1.
            clear Heq Heq1.

            erewrite Mem.load_store_same with (m1 := jit_mem jit_st0); [| eapply Hstore].

            simpl.
            (**r we know BinDecode.is_thumb2 _ = false in this case *)
            apply lemma_thumb_add_reg.
          }
          {
            simpl.
            unfold nextinstr_nf, nextinstr.
            simpl.
            unfold undef_flags.
            reflexivity.
          }
        * eapply exec_step.
          {
            unfold regs_agree.
            intros.
            specialize (Hreg_agree r0 H).
            destruct (reg_eqb r0 rd) eqn: Hreg_eq0;
              [ apply reg_eqb_true in Hreg_eq0 |
                apply reg_eqb_false in Hreg_eq0].
            - subst.
              erewrite ConcreteState.eval_upd_reg_same; eauto.
              rewrite Pregmap.gso.
              2:{ intro HF. inversion HF. }
              rewrite Hv0_eq, Hv1_eq.
              destruct (reg_eqb r rd) eqn: Hreg_eq1;
                [ apply reg_eqb_true in Hreg_eq1 |
                  apply reg_eqb_false in Hreg_eq1].
              + subst.
                rewrite Pregmap.gss.
                simpl.
                eexists.
                split; [reflexivity | ].
                rewrite ! Int.repr_unsigned.
                reflexivity.
              + rewrite Pregmap.gss.
                eexists; split; [reflexivity | ].
                rewrite ! Int.repr_unsigned.
                reflexivity.
            - destruct Hreg_agree as (vi & Hrs_eq & Hreg_r0).
              exists vi.
              rewrite Pregmap.gso.
              2:{ intro HF. inversion HF. }
              rewrite Pregmap.gso.
              2:{
                clear - Hreg_eq0.
                intro HF.
                apply Hreg_eq0; unfold ireg_of_reg in HF.
                destruct r0, rd; inversion HF; reflexivity.
              }
              split; [assumption | ].
              erewrite <- ConcreteState.eval_upd_reg_other; eauto.
          }
          {
            rewrite Pregmap.gss.
            rewrite Pregmap.gso.
            2:{ intro HF. inversion HF. }
            rewrite HPC_eq, Hofs0, Hofs1, Hjit_len_eq.
            assert (Heq: (jitted_len jit_st0 + (jitted_len jit_st0 + 0) + 2 = 
                        (S (jitted_len jit_st0) + (S (jitted_len jit_st0) + 0)))%nat) by lia.
            rewrite <- Heq; clear Heq.
            simpl; f_equal.
            unfold isize.
            clear - lemma_max_jitted_len.
            rewrite Ptrofs.add_unsigned.
            unfold Ptrofs.of_int.
            specialize (lemma_max_jitted_len jit_st0).
            repeat (rewrite Int.unsigned_repr; [ | change Int.max_unsigned with 4294967295; lia]).
            rewrite Ptrofs.unsigned_repr; [ | change Ptrofs.max_unsigned with 4294967295; lia].
            change (Ptrofs.unsigned (Ptrofs.repr 2)) with 2.
            assert (Heq: Z.of_nat (jitted_len jit_st0 + (jitted_len jit_st0 + 0)) + 2 = 
                          Z.of_nat (jitted_len jit_st0 + (jitted_len jit_st0 + 0) + 2)) by lia.
            rewrite Heq.
            reflexivity.
          }
        all: assumption.
      + admit.
      + admit.
      + admit. (**r the rest part is trivial *)
      + admit.
      + admit.
      + admit.
      + admit.
      + admit.
      + admit.
      + admit.
      + admit.
    - (**r alu_imm *)
      admit.
  Admitted.

End JITCoreOne.

Lemma upd_jitted_list_unchange_jittted_list:
  forall i st0 st1,
    upd_jitted_list i st0 = Some st1 ->
      jitted_list st0 = jitted_list st1.
Proof.
  unfold upd_jitted_list; intros.
  destruct upd_jitted_list'; inversion H; simpl.
  reflexivity.
Qed.

Lemma upd_jitted_list_unchange_jittted_list_2:
  forall i j st0 st1,
    match upd_jitted_list i st0 with
     | Some ins_st0 => upd_jitted_list j ins_st0
     | None => None
     end = Some st1 ->
      jitted_list st0 = jitted_list st1.
Proof.
  unfold upd_jitted_list; intros.
  destruct upd_jitted_list'; inversion H; simpl.
  destruct upd_jitted_list'; inversion H1; simpl; clear.
  reflexivity.
Qed.

Lemma bpf_alu32_to_thumb_unchange_jittted_list:
  forall ins st0 st1
    (Hone : bpf_alu32_to_thumb ins st0 = Some st1),
      jitted_list st0 = jitted_list st1.
Proof.
  intros.
  unfold bpf_alu32_to_thumb in Hone.
  destruct ins in Hone; inversion Hone.
  clear - H0.
  destruct a; [| inversion H0].
  destruct s.
  + unfold bpf_alu32_to_thumb_reg in H0.
    destruct b; inversion H0.
    10:{ eapply upd_jitted_list_unchange_jittted_list; eauto. }
    1:{ eapply upd_jitted_list_unchange_jittted_list; eauto. }
    all: eapply upd_jitted_list_unchange_jittted_list_2; eauto.
  + unfold bpf_alu32_to_thumb_imm in H0.
    destruct (Int.cmp Cle Int.zero i && Int.cmp Cle i (Int.repr 255)).
    * unfold bpf_alu32_to_thumb_imm0 in H0.
      destruct b; inversion H0.
      all: eapply upd_jitted_list_unchange_jittted_list_2; eauto.
    * unfold mov_int_to_movw in H0.
      destruct upd_jitted_list eqn: Hst1 in H0; [| inversion H0].
      eapply upd_jitted_list_unchange_jittted_list in Hst1; eauto; rewrite Hst1; clear Hst1.
      destruct upd_jitted_list eqn: Hst1 in H0; [| inversion H0].
      eapply upd_jitted_list_unchange_jittted_list in Hst1; eauto; rewrite Hst1; clear Hst1.
      destruct Int.eq.
      { unfold bpf_alu32_to_thumb_reg in H0.
        destruct b; inversion H0.
        10:{ eapply upd_jitted_list_unchange_jittted_list; eauto. }
        1:{ eapply upd_jitted_list_unchange_jittted_list; eauto. }
        all: eapply upd_jitted_list_unchange_jittted_list_2; eauto.
      }
      {
        unfold mov_int_to_movt in H0.
        destruct upd_jitted_list eqn: Hst1 in H0; [| inversion H0].
        eapply upd_jitted_list_unchange_jittted_list in Hst1; eauto; rewrite Hst1; clear Hst1.
        destruct upd_jitted_list eqn: Hst1 in H0; [| inversion H0].
        eapply upd_jitted_list_unchange_jittted_list in Hst1; eauto; rewrite Hst1; clear Hst1.
        unfold bpf_alu32_to_thumb_reg in H0.
        destruct b; inversion H0.
        10:{ eapply upd_jitted_list_unchange_jittted_list; eauto. }
        1:{ eapply upd_jitted_list_unchange_jittted_list; eauto. }
        all: eapply upd_jitted_list_unchange_jittted_list_2; eauto.
      }
Qed.

Lemma jit_core_unchange_jittted_list:
  forall l st0 st1
    (Hjit : jit_core l st0 = Some st1),
      jitted_list st0 = jitted_list st1.
Proof.
  induction l; simpl; intros.
  - inversion Hjit; reflexivity.
  - destruct bpf_alu32_to_thumb eqn: Hone; [| inversion Hjit].
    specialize (IHl j st1 Hjit).
    rewrite <- IHl.
    eapply bpf_alu32_to_thumb_unchange_jittted_list; eauto.
Qed.


Lemma upd_jitted_list_jittted_len:
  forall i st0 st1,
    upd_jitted_list i st0 = Some st1 ->
      (S (jitted_len st0) = jitted_len st1)%nat.
Proof.
  unfold upd_jitted_list; intros.
  destruct upd_jitted_list'; inversion H; simpl.
  reflexivity.
Qed.

Lemma upd_jitted_list_jittted_len_2:
  forall i j st0 st1,
    match upd_jitted_list i st0 with
     | Some ins_st0 => upd_jitted_list j ins_st0
     | None => None
     end = Some st1 ->
      (S (S (jitted_len st0)) = jitted_len st1)%nat.
Proof.
  unfold upd_jitted_list; intros.
  destruct upd_jitted_list'; inversion H; simpl.
  destruct upd_jitted_list'; inversion H1; simpl; clear.
  reflexivity.
Qed.

Lemma bpf_alu32_to_thumb_jittted_len:
  forall ins st0 st1
    (Hone : bpf_alu32_to_thumb ins st0 = Some st1),
      (jitted_len st0 <= jitted_len st1)%nat.
Proof.
  intros.
  unfold bpf_alu32_to_thumb in Hone.
  destruct ins in Hone; inversion Hone.
  clear - H0.
  destruct a; [| inversion H0].
  destruct s.
  + unfold bpf_alu32_to_thumb_reg in H0.
    destruct b; inversion H0.
    10:{ eapply upd_jitted_list_jittted_len in H1; eauto. lia. }
    1:{ eapply upd_jitted_list_jittted_len in H1; eauto. lia. }
    all: eapply upd_jitted_list_jittted_len_2 in H0; eauto; lia.
  + unfold bpf_alu32_to_thumb_imm in H0.
    destruct (Int.cmp Cle Int.zero i && Int.cmp Cle i (Int.repr 255)).
    * unfold bpf_alu32_to_thumb_imm0 in H0.
      destruct b; inversion H0.
      all: eapply upd_jitted_list_jittted_len_2 in H0; eauto; lia.
    * unfold mov_int_to_movw in H0.
      destruct upd_jitted_list eqn: Hst1 in H0; [| inversion H0].
      eapply upd_jitted_list_jittted_len in Hst1; eauto.
      destruct upd_jitted_list eqn: Hst2 in H0; [| inversion H0].
      eapply upd_jitted_list_jittted_len in Hst2; eauto.
      destruct Int.eq.
      { unfold bpf_alu32_to_thumb_reg in H0.
        destruct b; inversion H0.
        10:{ eapply upd_jitted_list_jittted_len in H1; eauto. lia. }
        1:{ eapply upd_jitted_list_jittted_len in H1; eauto. lia. }
        all: eapply upd_jitted_list_jittted_len_2 in H1; eauto; lia.
      }
      {
        unfold mov_int_to_movt in H0.
        destruct upd_jitted_list eqn: Hst3 in H0; [| inversion H0].
        eapply upd_jitted_list_jittted_len in Hst3; eauto.
        destruct upd_jitted_list eqn: Hst4 in H0; [| inversion H0].
        eapply upd_jitted_list_jittted_len in Hst4; eauto.
        unfold bpf_alu32_to_thumb_reg in H0.
        destruct b; inversion H0.
        10:{ eapply upd_jitted_list_jittted_len in H1; eauto; lia. }
        1:{ eapply upd_jitted_list_jittted_len in H1; eauto; lia. }
        all: eapply upd_jitted_list_jittted_len_2 in H1; eauto; lia.
      }
Qed.


Lemma upd_jitted_list_load:
  forall i st0 st1 ofs1 chunk arm_blk,
    jitted_list st0 = Vptr arm_blk Ptrofs.zero ->
    0 <= ofs1 /\ ofs1 + size_chunk chunk <= Z.of_nat (2 * jitted_len st0) /\
    Z.of_nat (2 * jitted_len st0) <= Z.of_nat JITTED_LIST_MAX_LENGTH ->
    upd_jitted_list i st0 = Some st1 ->
      Mem.load chunk (jit_mem st0) arm_blk ofs1 = Mem.load chunk (jit_mem st1) arm_blk ofs1.
Proof.
  unfold upd_jitted_list, JITTED_LIST_MAX_LENGTH; intros.
  unfold upd_jitted_list' in H1.
  rewrite H in *.
  simpl in *.
  rewrite Ptrofs.add_zero_l in *.
  unfold Ptrofs.of_int in *.
  rewrite Int.unsigned_repr in H1; [ | change Int.max_unsigned with 4294967295; lia ].
  rewrite Ptrofs.unsigned_repr in H1; [ | change Ptrofs.max_unsigned with 4294967295; lia ].
  symmetry.
  destruct (jitted_len st0 + (jitted_len st0 + 0) + 4 <=? JITTED_LIST_MAX_LENGTH)%nat eqn: Hcond; inversion H1.
  destruct Mem.store eqn: Hstore; inversion H3.
  eapply Mem.load_store_other; eauto.
  clear H1 H3 H4.
  lia.
Qed.

Lemma upd_jitted_list_load_2:
  forall i j st0 st1 ofs1 chunk arm_blk,
    jitted_list st0 = Vptr arm_blk Ptrofs.zero ->
    0 <= ofs1 /\ ofs1 + size_chunk chunk <= Z.of_nat (2 * jitted_len st0) /\
    Z.of_nat (2 * jitted_len st0) <= Z.of_nat JITTED_LIST_MAX_LENGTH ->
    match upd_jitted_list i st0 with
     | Some ins_st0 => upd_jitted_list j ins_st0
     | None => None
     end = Some st1 ->
      Mem.load chunk (jit_mem st0) arm_blk ofs1 = Mem.load chunk (jit_mem st1) arm_blk ofs1.
Proof.
  intros.
  destruct upd_jitted_list eqn: Hupd1; inversion H1.

  eapply upd_jitted_list_unchange_jittted_list in Hupd1 as Heq1.
  eapply upd_jitted_list_jittted_len in Hupd1 as Hle1.

  eapply upd_jitted_list_load in Hupd1; eauto.
  rewrite Hupd1.
  eapply upd_jitted_list_load in H1; eauto.
  - rewrite <- Heq1.
    auto.
  - unfold upd_jitted_list, upd_jitted_list' in H1.
    destruct (2 * jitted_len j0 + 4 <=? JITTED_LIST_MAX_LENGTH)%nat eqn: Hcond; inversion H1.
    clear - H0 Hcond Heq1 Hle1.
    apply leb_complete in Hcond.
    lia.
Qed.

Lemma upd_jitted_list_max:
  forall v st0 st1,
  upd_jitted_list v st0 = Some st1 ->
    Z.of_nat (2 * jitted_len st0) <= Z.of_nat JITTED_LIST_MAX_LENGTH.
Proof.
  unfold upd_jitted_list, upd_jitted_list'.
  intros.
  destruct (2 * jitted_len st0 + 4 <=? JITTED_LIST_MAX_LENGTH)%nat eqn: Hcond; inversion H.
  apply leb_complete in Hcond.
  lia.
Qed.

Lemma bpf_alu32_to_thumb_sub_mem:
  forall ins st0 st1 arm_blk
    (Hptr: jitted_list st0 = Vptr arm_blk Ptrofs.zero)
    (Hmax: Z.of_nat (2 * jitted_len st0) <= Z.of_nat JITTED_LIST_MAX_LENGTH)
    (Hone : bpf_alu32_to_thumb ins st0 = Some st1),
      sub_mem (jit_mem st0) (jit_mem st1) arm_blk (Z.of_nat (2 * jitted_len st0)).
Proof.
  unfold bpf_alu32_to_thumb, sub_mem; intros.
  destruct ins in Hone; inversion Hone.
  clear - Hptr Hmax H H1.
  destruct a; [| inversion H1].
  destruct s.
  + unfold bpf_alu32_to_thumb_reg in H1.
    destruct b; inversion H1.
    10:{ eapply upd_jitted_list_load; eauto. lia. }
    1:{ eapply upd_jitted_list_load; eauto. lia. }
    all: eapply upd_jitted_list_load_2; eauto; lia.
  + unfold bpf_alu32_to_thumb_imm in H1.
    destruct (Int.cmp Cle Int.zero i && Int.cmp Cle i (Int.repr 255)).
    * unfold bpf_alu32_to_thumb_imm0 in H1.
      destruct b; inversion H1.
      all: eapply upd_jitted_list_load_2; eauto; lia.
    * unfold mov_int_to_movw in H1.
      destruct upd_jitted_list eqn: Hst1 in H1; [| inversion H1].

      eapply upd_jitted_list_unchange_jittted_list in Hst1 as Heq1.
      eapply upd_jitted_list_jittted_len in Hst1 as Hle1.

      eapply upd_jitted_list_load with (ofs1 := ofs1) (chunk := chunk) in Hst1 as Hsame1; eauto; try lia.
      rewrite Hsame1; clear Hsame1.


      destruct upd_jitted_list eqn: Hst2 in H1; [| inversion H1].

      eapply upd_jitted_list_unchange_jittted_list in Hst2 as Heq2.
      eapply upd_jitted_list_jittted_len in Hst2 as Hle2.

      eapply upd_jitted_list_load with (ofs1 := ofs1) (chunk := chunk) in Hst2 as Hsame2; eauto; try lia.
      2:{ rewrite <- Heq1. apply Hptr. }
      2:{ unfold upd_jitted_list, upd_jitted_list' in Hst2.
          destruct (2 * jitted_len j + 4 <=? JITTED_LIST_MAX_LENGTH)%nat eqn: Hcond; inversion Hst2.
          apply leb_complete in Hcond. lia.
      }

      rewrite Hsame2.

      assert (Hrange: 0 <= ofs1 /\ ofs1 + size_chunk chunk <= Z.of_nat (2 * jitted_len j0)). {
        lia.
      }
      assert (Hptr0: jitted_list j0 = Vptr arm_blk Ptrofs.zero). {
        rewrite <- Heq2.
        rewrite <- Heq1.
        auto.
      }


      destruct Int.eq.
      { unfold bpf_alu32_to_thumb_reg in H1.
        destruct b; inversion H1.
        10:{ eapply upd_jitted_list_load; eauto. eapply upd_jitted_list_max in H2; eauto; lia. }
        1:{ eapply upd_jitted_list_load; eauto. eapply upd_jitted_list_max in H2; eauto; lia. }
        all: eapply upd_jitted_list_load_2; eauto.
        all: destruct upd_jitted_list eqn: Hupd in H2; inversion H2.
        all:  eapply upd_jitted_list_max in Hupd; eauto; lia.
      }
      {
        unfold mov_int_to_movt in H1.
        destruct upd_jitted_list eqn: Hst3 in H1; [| inversion H1].

        eapply upd_jitted_list_unchange_jittted_list in Hst3 as Heq3.
        eapply upd_jitted_list_jittted_len in Hst3 as Hle3.

        eapply upd_jitted_list_load with (ofs1 := ofs1) (chunk := chunk) in Hst3 as Hsame3; eauto; try lia.
        rewrite Hsame3; clear Hsame3.


        destruct upd_jitted_list eqn: Hst4 in H1; [| inversion H1].

        eapply upd_jitted_list_unchange_jittted_list in Hst4 as Heq4.
        eapply upd_jitted_list_jittted_len in Hst4 as Hle4.

        eapply upd_jitted_list_load with (ofs1 := ofs1) (chunk := chunk) in Hst4 as Hsame4; eauto; try lia.
        2:{ rewrite <- Heq3. apply Hptr0. }
        2:{ unfold upd_jitted_list, upd_jitted_list' in Hst4.
            destruct (2 * jitted_len j1 + 4 <=? JITTED_LIST_MAX_LENGTH)%nat eqn: Hcond; inversion Hst4.
            apply leb_complete in Hcond. lia.
        }

        2:{ eapply upd_jitted_list_max in Hst3; eauto; lia. }

        rewrite Hsame4.

        assert (Hrange1: 0 <= ofs1 /\ ofs1 + size_chunk chunk <= Z.of_nat (2 * jitted_len j2)). {
          lia.
        }
        assert (Hptr1: jitted_list j2 = Vptr arm_blk Ptrofs.zero). {
          rewrite <- Heq4.
          rewrite <- Heq3.
          auto.
        }

        unfold bpf_alu32_to_thumb_reg in H1.
        destruct b; inversion H1.
        10:{ eapply upd_jitted_list_load; eauto. eapply upd_jitted_list_max in H2; eauto; lia. }
        1:{ eapply upd_jitted_list_load; eauto. eapply upd_jitted_list_max in H2; eauto; lia. }
        all: eapply upd_jitted_list_load_2; eauto.
        all: destruct upd_jitted_list eqn: Hupd in H2; inversion H2.
        all:  eapply upd_jitted_list_max in Hupd; eauto; lia.
      }
Qed.

Lemma bpf_alu32_to_thumb_max:
  forall ins st0 st1
    (Hone: bpf_alu32_to_thumb ins st0 = Some st1),
      Z.of_nat (2 * jitted_len st0) <= Z.of_nat JITTED_LIST_MAX_LENGTH.
Proof.
  unfold bpf_alu32_to_thumb; intros.
  destruct ins in Hone; inversion Hone.
  clear - H0.
  destruct a; [| inversion H0].
  destruct s.
  + unfold bpf_alu32_to_thumb_reg in H0.
    destruct b; inversion H0.
    10:{ eapply upd_jitted_list_max; eauto. }
    1:{ eapply upd_jitted_list_max; eauto. }
    all: destruct upd_jitted_list eqn: Hupd in H1; inversion H1.
    all: eapply upd_jitted_list_max; eauto.
  + unfold bpf_alu32_to_thumb_imm in H0.
    destruct (Int.cmp Cle Int.zero i && Int.cmp Cle i (Int.repr 255)).
    * unfold bpf_alu32_to_thumb_imm0 in H0.
      destruct b; inversion H0.
      all: destruct upd_jitted_list eqn: Hupd in H1; inversion H1.
      all: eapply upd_jitted_list_max; eauto.
    * unfold mov_int_to_movw in H0.
      destruct upd_jitted_list eqn: Hst1 in H0; [| inversion H0].
      all: eapply upd_jitted_list_max; eauto.
Qed.


Lemma jit_core_sub_mem:
  forall l st0 st1 arm_blk
    (Hptr: jitted_list st0 = Vptr arm_blk Ptrofs.zero)
    (Hjit : jit_core l st0 = Some st1),
      sub_mem (jit_mem st0) (jit_mem st1) arm_blk (Z.of_nat (2 * jitted_len st0)).
Proof.
  induction l; unfold sub_mem; simpl; intros.
  - inversion Hjit; reflexivity.
  - destruct bpf_alu32_to_thumb eqn: Hone; [| inversion Hjit].
    rename j into stk.
    apply bpf_alu32_to_thumb_unchange_jittted_list in Hone as Hptr1.
    symmetry in Hptr1.
    rewrite Hptr in Hptr1.
    specialize (IHl stk st1 arm_blk Hptr1 Hjit).
    apply bpf_alu32_to_thumb_max in Hone as Hmax.
    apply bpf_alu32_to_thumb_sub_mem with (arm_blk := arm_blk) in Hone as Htmp; auto.

    unfold sub_mem in *.

    rewrite <- IHl.
    + apply Htmp.
      lia.
    + apply bpf_alu32_to_thumb_jittted_len in Hone.
      lia.
Qed.


Lemma List_in_bool_true:
  forall r l,
    list_in_bool reg_eqb r l = true ->
      List.In r l.
Proof.
  induction l; simpl; intros.
  - inversion H.
  - destruct reg_eqb eqn: Heq.
    + left.
      symmetry.
      rewrite reg_eqb_true; assumption.
    + right.
      auto.
Qed.

Lemma reg_eqb_refl:
  forall r,
    reg_eqb r r = true.
Proof.
  destruct r; simpl; reflexivity.
Qed.

Lemma List_in_bool_false:
  forall r l,
    list_in_bool reg_eqb r l = false ->
      ~List.In r l.
Proof.
  induction l; simpl; intros.
  - intro HF; auto.
  - intros HF.
    destruct HF.
    + subst.
      rewrite reg_eqb_refl in H.
      inversion H.
    + destruct reg_eqb eqn: Heq.
      * inversion H.
      * apply IHl; auto.
Qed.

Lemma list_in_app_no_repeat_r:
  forall r l0 l1
    (H : In r l1),
      In r (app_no_repeat reg_eqb l0 l1).
Proof.
  induction l0; simpl; intros.
  - assumption.
  - destruct list_in_bool eqn: Hb.
    + apply IHl0.
      assumption.
    + simpl.
      right.
      apply IHl0.
      auto.
Qed.

Lemma list_in_app_no_repeat_l:
  forall r l0 l1
    (H : In r l0),
      In r (app_no_repeat reg_eqb l0 l1).
Proof.
  induction l0; simpl; intros.
  - inversion H.
  - destruct H.
    + subst.
      destruct list_in_bool eqn: Hin.
      * apply list_in_app_no_repeat_r; auto.
        apply List_in_bool_true; auto.
      * simpl.
        auto.
    + destruct list_in_bool eqn: Hin.
      * apply IHl0; auto.
      * simpl.
        right.
        apply IHl0; auto.
Qed.

Lemma regs_agree_app_no_repeat_intro_r:
  forall l0 l1 rs0 rs1
    (Hreg_agree : regs_agree (app_no_repeat reg_eqb l0 l1) rs0 rs1),
      regs_agree l1 rs0 rs1.
Proof.
  induction l0;
  unfold regs_agree; intros.
  - apply Hreg_agree.
    simpl.
    assumption.
  - apply Hreg_agree.
    simpl.
    destruct list_in_bool.
    + apply list_in_app_no_repeat_r; simpl; auto.
    + simpl.
      right.
      apply list_in_app_no_repeat_r; simpl; auto.
Qed.

Definition list_subset {A: Type} (l0 l1: list A): Prop :=
  forall r, In r l0 -> In r l1.

Lemma list_subset_refl:
  forall {A: Type} (l: list A),
    list_subset l l.
Proof.
  unfold list_subset.
  intros.
  assumption.
Qed.

Lemma list_subset_in:
  forall {A: Type} l0 l1 (r: A)
    (Hldr_sub : list_subset l0 l1)
    (H : In r l0),
      In r l1.
Proof.
  unfold list_subset.
  intros.
  auto.
Qed.

Lemma list_subset_app_no_repeat_in_l:
  forall l0 l1 l2 r
    (Hldr_sub : list_subset (app_no_repeat reg_eqb l0 l1) l2)
    (H : In r l0),
      In r l2.
Proof.
  intros.
  apply list_in_app_no_repeat_l with (l1 := l1) in H.
  eapply list_subset_in; eauto.
Qed.

Lemma list_subset_app_no_repeat_in_r:
  forall l0 l1 l2 r
    (Hldr_sub : list_subset (app_no_repeat reg_eqb l0 l1) l2)
    (H : In r l1),
      In r l2.
Proof.
  intros.
  apply list_in_app_no_repeat_r with (l0 := l0) in H.
  eapply list_subset_in; eauto.
Qed.

Lemma list_in_bool_app_no_repeat_r:
  forall l0 l1 r,
    list_in_bool reg_eqb r l1 = true ->
      list_in_bool reg_eqb r (app_no_repeat reg_eqb l0 l1) = true.
Proof.
  induction l0; simpl; intros.
  assumption.

  destruct (list_in_bool reg_eqb a l1) eqn: Hb.
  - apply IHl0; auto.
  - simpl.
    destruct reg_eqb.
    + reflexivity.
    + apply IHl0; auto.
Qed.

Lemma list_in_bool_in_r:
  forall a l0 l1,
    list_in_bool reg_eqb a (app_no_repeat reg_eqb l0 (a :: l1)) = true.
Proof.
  intros.
  apply list_in_bool_app_no_repeat_r.
  simpl.
  rewrite reg_eqb_refl.
  reflexivity.
Qed.

Lemma app_no_repeat_nil_r:
  forall l,
    app_no_repeat reg_eqb l [] = l.
Proof.
  induction l; simpl; intros.
  - reflexivity.
  - rewrite IHl.
    reflexivity.
Qed.

Lemma jit_core_jitted_len:
  forall l st0 st1
    (Hjit : jit_core l st0 = Some st1),
      Z.of_nat (2 * jitted_len st0) <= Z.of_nat (2 * jitted_len st1).
Proof.
  induction l; simpl; intros.
  - inversion Hjit; lia.
  - destruct bpf_alu32_to_thumb eqn: Halu32; inversion Hjit.
    clear H0.
    rename j into stk.
    specialize (IHl _ _ Hjit).
    eapply bpf_alu32_to_thumb_jittted_len in Halu32.
    lia.
Qed.


Section JITCore.
  Variable ge : genv.

  (** Axiom *)
  Variable lemma_regs_blk_eq: forall st,
    exists regs_blk, regs_st st = Vptr regs_blk Ptrofs.zero.
  Variable lemma_jitted_list_is_vptr: forall st,
    exists b, jitted_list st = Vptr b Ptrofs.zero.
  Variable lemma_max_jitted_len: forall st,
    (jitted_len st <= 500)%nat.

  (** Definition *)

  Lemma jit_core_simulation: forall l rbpf_st0 rbpf_st1 ldr_l
    (Hstep: rbpf_sem rbpf_st0 l rbpf_st1) l1 jit_st0 jit_st1 jit_st_final arm_blk arm_st0 ofs0 ofs1
    (Hldr: jit_alu32_load_list l = Some l1)
    (Hldr_sub: list_subset l1 ldr_l)
    (Hjit: jit_core l jit_st0 = Some jit_st1)
    (Hofs0: ofs0 = (Z.of_nat (2 * (jitted_len jit_st0))))
    (Hofs1: ofs1 = (Z.of_nat (2 * (jitted_len jit_st1))))
    (Harm_blk: jitted_list jit_st0 = Vptr arm_blk Ptrofs.zero)
    (Hmem: sub_mem (jit_mem jit_st1) (jit_mem jit_st_final) arm_blk ofs1)
    (Hst: match_state_core rbpf_st0 ldr_l arm_blk ofs0 jit_st_final arm_st0),
    exists arm_st1,
      star BinSem.step ge arm_st0 E0 arm_st1 /\
      match_state_core rbpf_st1 ldr_l arm_blk ofs1 jit_st_final arm_st1.
  Proof.
    induction 1 as [ | rbpf_st0 rbpf_stk rbpf_st1 hd tl Hone_step Hplus_step IH].

    - intros; simpl in *.
      injection Hjit as Hjit_eq; subst jit_st1.
      exists arm_st0.
      split; [ apply star_refl | ].

      injection Hldr as Hlsr_eq; subst l1.
      rewrite <- Hofs0 in Hofs1.
      subst ofs1.
      assumption.
    - simpl.
      intros.
      destruct bpf_alu32_to_thumb eqn: Hone_ins; [| inversion Hjit].
      rename j into jit_stk.

      assert (Hjit_stk_ptr: jitted_list jit_stk = Vptr arm_blk Ptrofs.zero). {
        clear - Hone_ins Harm_blk.
        rewrite <- Harm_blk.
        symmetry.
        eapply bpf_alu32_to_thumb_unchange_jittted_list; eauto.
      }

      destruct jit_alu32_load_list eqn: Hldr_eq; [| inversion Hldr].

      induction Hone_step as [rbpf_st0 a op rd ri ret rbpf_stk].
      induction Hst as [ldr_l rbpf_st0 rs jit_st_final arm_blk ofs0 arm_st0].

      specialize (IH l jit_stk jit_st1 jit_st_final).

      eapply jit_core_one_simulation with
        (ge := ge) (ins := BPF_BINARY a op rd ri)
        (jit_st0 := jit_st0) (jit_st1 := jit_stk) (jit_st_final := jit_st_final) (ofs0 := ofs0) (lsr := ldr_l)
        (arm_st0 := (State rs (jit_mem jit_st_final))) (rbpf_st0 := rbpf_st0) (rbpf_st1 := rbpf_stk)
      in Hone_ins; eauto.

      2:{ (**r sub_mem *)
        clear - Hofs1 Hjit_stk_ptr Hjit Hmem.
        assert (Hle: Z.of_nat (2 * jitted_len jit_stk) <= Z.of_nat (2 * jitted_len jit_st1)). {
          clear - Hjit.
          eapply jit_core_jitted_len; eauto.
        }

        eapply jit_core_sub_mem in Hjit; eauto.
        subst ofs1.
        eapply sub_mem_less_than with (ofs1 := Z.of_nat (2 * jitted_len jit_stk)) in Hmem; eauto.
        eapply sub_mem_trans; eauto.
      }

      2:{ (**r match_state_core *)
        eapply exec_step; eauto.
      }

      2:{ (**r ins_is_sync_regs *)
        clear - Hldr Hldr_sub.
        destruct jit_alu32_load_aux_list eqn: Haux; inversion Hldr.
        unfold ins_is_sync_regs.
        unfold jit_alu32_load_aux_list in Haux.
        destruct a; inversion Haux.
        clear H1.
        subst l1.

        destruct ri.
        - assert (Hin: List.In rd l0 /\ List.In r l0). {
            clear - Haux.
            destruct op; inversion Haux; simpl; auto.
            all: destruct reg_eqb eqn: Heq;
            [ apply reg_eqb_true in Heq;
              injection Haux as Hreg_eq; rewrite <- Hreg_eq, Heq; intuition |
              inversion Haux; intuition ].
          }
          clear Haux.
          destruct Hin.
          split; eapply list_subset_app_no_repeat_in_l; eauto.
        - assert (Hin: List.In rd l0). {
            clear - Haux.
            destruct op; inversion Haux; simpl; auto.
          }
          clear Haux.
          split; try eapply list_subset_app_no_repeat_in_l; eauto.
      }

      2:{ (**r rbpf_step *)
        econstructor; eauto.
      }

      destruct Hone_ins as (arm_stk & Hplus & Hmatch_state).

      specialize (IH arm_blk arm_stk (Z.of_nat (2 * jitted_len jit_stk)) ofs1).
      assert (Heq: Some l = Some l) by reflexivity.
      specialize (IH Heq); clear Heq.

      assert (Hsub: list_subset l ldr_l). {
        clear - Hldr Hldr_sub.
        destruct jit_alu32_load_aux_list eqn: Haux; inversion Hldr.
        subst l1.
        unfold list_subset in *.
        intros.
        apply Hldr_sub.
        eapply list_subset_app_no_repeat_in_r with (l0 := l0); eauto.
        apply list_subset_refl.

      }

      specialize (IH Hsub Hjit).
      assert (Heq: Z.of_nat (2 * jitted_len jit_stk) = Z.of_nat (2 * jitted_len jit_stk)) by reflexivity.
      specialize (IH Heq Hofs1 Hjit_stk_ptr); clear Heq.

      assert (Hmatch1: match_state_core rbpf_stk ldr_l arm_blk (Z.of_nat (2 * jitted_len jit_stk)) jit_st_final arm_stk). {
        clear - Hldr Hjit Hmatch_state.

        induction Hmatch_state as [ldr_l rbpf_stk rs jit_st_final arm_blk ofs2].
        eapply exec_step; eauto.
      }

      specialize (IH Hmem Hmatch1).
      destruct IH as (arm_st1 & Hstar & Hmatch2).
      exists arm_st1; split.
      + eapply star_trans with (s2 := arm_stk) (t1 := E0); eauto.
        eapply plus_star; eauto.
      + clear - Hmatch2 Hldr.
        induction Hmatch2 as [ldr_l rbpf_st1 rs jit_st1 arm_blk ofs1].
        eapply exec_step; eauto.
  Qed.
End JITCore.