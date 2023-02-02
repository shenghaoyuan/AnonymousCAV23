From Coq Require Import ZArith Lia.
From compcert Require Import Integers Values AST Memory Memdata.

From bpf.comm Require Import ListAsArray Flag Regs State Monad BinrBPF rBPFMonadOp rBPFMemType rBPFValues.

From  bpf.monadicmodel Require Import Opcode.
From bpf.monadicmodel2 Require Import ConcreteState rBPFInterpreter2.

From bpf.jit.thumb Require Import ThumbJITOpcode JITState ThumbJIT.
From bpf.jit.iBPF Require Import ISemantics.
From bpf.jit.simulation Require Import SimulationJIT SimulationJITExtension SimulationJITExtensionProof1.

Lemma upd_flag_extension:
  forall st0 st1 st0' flag_blk regs_blk jit_blk f
  (Hex : RelEx flag_blk regs_blk jit_blk st0 st1)
  (Hflag: upd_flag (Vint (int_of_flag f)) st0 = Some st0'),
    exists st1', upd_jit_flag f st1 = Some st1' /\
    RelEx flag_blk regs_blk jit_blk st0' st1'.
Proof.
  intros.

  unfold upd_flag, upd_flag', Mem.storev in Hflag.
  assert (Hflag1: exists st1', upd_jit_flag f st1 = Some st1'). {
    unfold upd_jit_flag, upd_jit_flag', Mem.storev.
    destruct Hex as (Hunchanged, _,
        (Hflag_eq0 & Hflag_eq1 & Hflag_eq),
        _, _, _, _, _, _, _, (_ & Hblk & _)).
    rewrite Hflag_eq0 in Hflag.
    destruct Mem.store eqn: Hstore1; inversion Hflag.
    clear Hflag H0.
    rewrite Hflag_eq1.
    eapply unchanged_on_store in Hstore1; eauto.
    - destruct Hstore1 as (m3 & Hstore1).
      rewrite Hstore1.
      eexists; reflexivity.
    - intros.
      simpl.
      destruct Hblk as (_ & Hblk & _); auto.
  }

  destruct Hflag1 as (st1' & Hflag1).
  exists st1'; split; [assumption | ].

  unfold upd_jit_flag, upd_jit_flag', Mem.storev in *.
  assert (Hr:= Hex).
  destruct Hr as (Hunchanged, Hpc,
      (Hflag_eq0 & Hflag_eq1 & Hflag_eq),
      (Hreg0 & Hreg1 & Hreg),
      Hnum, Hmrs, Hlen, Hins, Hjit, Hperm, Hinvalid).
  rewrite Hflag_eq0 in *; clear Hflag_eq0.
  rewrite Hflag_eq1 in *; clear Hflag_eq1.

  destruct Mem.store eqn: Hstore0; inversion Hflag.
  clear Hflag; subst.

  destruct Mem.store eqn: Hstore1 in Hflag1; inversion Hflag1.
  clear Hflag1; subst.

  assert (Heq: Mem.unchanged_on (fun (b : block) (_ : Z) => b <> jit_blk) m m0). {
    eapply store_unchanged_on_2; eauto.
    destruct Hinvalid as (_ & (_ & Hblk & _) & _).
    auto.
  }

  split; simpl; try assumption.
  - split; simpl; [reflexivity | ].
    split; simpl; [reflexivity | ].
    exists f.
    unfold eval_flag, eval_jit_flag in *; simpl in *.

    split.
    + erewrite Mem.load_store_same; [ | apply Hstore0].
      f_equal.
    + erewrite Mem.load_store_same; [ | apply Hstore1].
      f_equal.
  - split; simpl; [assumption | ].
    split; [assumption | ].
    intros.
    specialize (Hreg r).
    destruct Hreg as (vl & Hreg_eq0 & Hreg_eq1).
    exists vl.
    unfold Mem.loadv in *; simpl in *.
    rewrite Hreg0, Hreg1 in *; simpl in *.
    rewrite <- Hreg_eq0 at 1.
    rewrite <- Hreg_eq1.
    clear - Hstore0 Hstore1 Hinvalid.
    split.
    + eapply Mem.load_store_other; [apply Hstore0 | ].
      left.
      destruct Hinvalid as (_ & (Hblk & _ & _) & _).
      auto.
    + eapply Mem.load_store_other; [apply Hstore1 | ].
      left.
      destruct Hinvalid as (_ & (Hblk & _ & _) & _).
      auto.
  - unfold ptr_range_perm in *.
    rewrite Hreg0, Hreg1 in *.
    rewrite <- Hjit in *.
    clear - Hex Hstore0 Hstore1 Hperm Hinvalid.
    destruct Hperm as (Hperm0 & Hperm1 & Hperm2 & Hperm3 & Hperm4).
    simpl in *.
    split.
    + eapply Mem.store_valid_access_1; eauto.
    + split.
      * intros.
        specialize (Hperm1 r).
        eapply Mem.store_valid_access_1; eauto.
      * split.
        {
          eapply Mem.store_valid_access_1; eauto.
        }
        {
          split.
          - intros.
            specialize (Hperm3 r).
            eapply Mem.store_valid_access_1; eauto.
          - intros.
            specialize (Hperm4 pc H).
            eapply Mem.store_valid_access_1; eauto.
        }
  - clear - Hjit Hstore0 Hstore1 Hinvalid Heq.
    destruct Hinvalid as (Hinvalid0 & Hblk & Hvalid).
    split.
    + intro Hf; apply Hinvalid0.
      eapply Mem.store_valid_block_2; eauto.
    + split.
      * auto.
      * intros.
        assert (Hv: Mem.valid_block (bpf_m st0) b). {
          eapply Mem.store_valid_block_2; eauto.
        }
        specialize (Hvalid b H Hv).
        eapply Mem.valid_block_unchanged_on; eauto.
Qed.

Lemma upd_reg_extension:
  forall st0 st1 st0' flag_blk regs_blk jit_blk r v
  (Hex : RelEx flag_blk regs_blk jit_blk st0 st1)
  (Hreg: upd_reg r (Vlong v) st0 = Some st0'),
    exists st1', upd_jit_reg r (Vlong v) st1 = Some st1' /\
    RelEx flag_blk regs_blk jit_blk st0' st1'.
Proof.
  intros.

  unfold upd_reg, upd_reg', Mem.storev in Hreg.
  assert (Hreg1: exists st1', upd_jit_reg r (Vlong v) st1 = Some st1'). {
    unfold upd_jit_reg, upd_jit_reg', Mem.storev.
    destruct Hex as (Hunchanged, _, _,
        (Hreg_eq0 & Hreg_eq1 & Hreg_eq),
         _, _, _, _, _, _, (_ & Hblk & _)).
    rewrite Hreg_eq0 in Hreg.
    unfold Val.add, Archi.ptr64 in Hreg.
    destruct Mem.store eqn: Hstore1; inversion Hreg.
    clear Hreg H0.
    rewrite Hreg_eq1.
    unfold Val.add, Archi.ptr64.
    eapply unchanged_on_store in Hstore1; eauto.
    - destruct Hstore1 as (m3 & Hstore1).
      rewrite Hstore1.
      eexists; reflexivity.
    - intros.
      simpl.
      destruct Hblk as (_ & _ & Hblk); auto.
  }

  destruct Hreg1 as (st1' & Hreg1).
  exists st1'; split; [assumption | ].

  unfold upd_jit_reg, upd_jit_reg', Mem.storev in *.
  assert (Hr:= Hex).
  destruct Hr as (Hunchanged, Hpc,
      (Hflag_eq0 & Hflag_eq1 & Hflag_eq),
      (Hreg_eq0 & Hreg_eq1 & Hreg_eq),
      Hnum, Hmrs, Hlen, Hins, Hjit, Hperm, Hinvalid).
  rewrite Hreg_eq0 in *.
  rewrite Hreg_eq1 in *.
  unfold Val.add, Archi.ptr64 in *.

  destruct Mem.store eqn: Hstore0; inversion Hreg.
  clear Hreg; subst.

  destruct Mem.store eqn: Hstore1 in Hreg1; inversion Hreg1.
  clear Hreg1; subst.

  assert (Heq: Mem.unchanged_on (fun (b : block) (_ : Z) => b <> jit_blk) m m0). {
    eapply store_unchanged_on_2; eauto.
    destruct Hinvalid as (_ & (_ & _ & Hblk) & _).
    auto.
  }

  split; simpl; try assumption.
  - clear - Hstore0 Hstore1 Hflag_eq0 Hflag_eq1 Hflag_eq Hinvalid.

    split; simpl; [assumption | ].
    split; simpl; [assumption | ].
    destruct Hflag_eq as (f & Hflag_eq & Hflag_eq').
    exists f.
    unfold eval_flag, eval_jit_flag in *; simpl in *.
    unfold Mem.loadv in *; simpl in *.
    rewrite Hflag_eq0, Hflag_eq1 in *.
    rewrite <- Hflag_eq at 1.
    rewrite <- Hflag_eq'.
    split.
    + eapply Mem.load_store_other; [apply Hstore0 | ].
      left.
      destruct Hinvalid as (_ & (Hblk & _ & _) & _).
      auto.
    + eapply Mem.load_store_other; [apply Hstore1 | ].
      left.
      destruct Hinvalid as (_ & (Hblk & _ & _) & _).
      auto.
  - clear - Hstore0 Hstore1 Hreg_eq0 Hreg_eq1 Hreg_eq Hinvalid.
    split; simpl; [reflexivity | ].
    split; [reflexivity | ].
    intros.
    specialize (Hreg_eq r0).
    destruct Hreg_eq as (vl & Hreg_eq & Hreg_eq').
    (**r case: r0 =? r *)
    destruct (reg_eqb r0 r) eqn: Heq;
      [ rewrite <- reg_eqb_true in Heq |
        rewrite <- reg_eqb_false in Heq].
    + subst r0.
      clear - Hstore0 Hstore1.
      exists v.
      split.
      * erewrite Mem.load_store_same; [ | apply Hstore0].
        f_equal.
      * erewrite Mem.load_store_same; [ | apply Hstore1].
        f_equal.
    + exists vl.
      rewrite ! Ptrofs.add_zero_l in *.
      rewrite <- Hreg_eq at 1.
      rewrite <- Hreg_eq'.
      clear - Hstore0 Hstore1 Heq.
      split.
      * eapply Mem.load_store_other; [apply Hstore0 | ].
        right.
        destruct r; destruct r0; simpl; (**r copy from equivalence3.upd_reg_equiv3 *)
          unfold Ptrofs.add;
          repeat match goal with
          | |- context[Ptrofs.unsigned (Ptrofs.of_int (Int.repr ?X))] =>
              change (Ptrofs.unsigned (Ptrofs.of_int (Int.repr X))) with X
          | |- context[Ptrofs.unsigned (Ptrofs.repr ?X)] =>
              change (Ptrofs.unsigned (Ptrofs.repr X)) with X
          end; simpl; try lia.
        all: exfalso; apply Heq; reflexivity.
      * eapply Mem.load_store_other; [apply Hstore1 | ].
        right.
        destruct r; destruct r0; simpl; (**r copy from equivalence3.upd_reg_equiv3 *)
          unfold Ptrofs.add;
          repeat match goal with
          | |- context[Ptrofs.unsigned (Ptrofs.of_int (Int.repr ?X))] =>
              change (Ptrofs.unsigned (Ptrofs.of_int (Int.repr X))) with X
          | |- context[Ptrofs.unsigned (Ptrofs.repr ?X)] =>
              change (Ptrofs.unsigned (Ptrofs.repr X)) with X
          end; simpl; try lia.
        all: exfalso; apply Heq; reflexivity.
  - unfold ptr_range_perm in *.
    rewrite Hflag_eq0, Hflag_eq1 in *.
    rewrite <- Hjit in *.
    clear - Hex Hstore0 Hstore1 Hperm Hinvalid.
    destruct Hperm as (Hperm0 & Hperm1 & Hperm2 & Hperm3 & Hperm4).
    simpl in *.
    split.
    + eapply Mem.store_valid_access_1; eauto.
    + split.
      * intros.
        specialize (Hperm1 r0).
        eapply Mem.store_valid_access_1; eauto.
      * split.
        {
          eapply Mem.store_valid_access_1; eauto.
        }
        {
          split.
          - intros.
            specialize (Hperm3 r0).
            eapply Mem.store_valid_access_1; eauto.
          - intros.
            specialize (Hperm4 pc H).
            eapply Mem.store_valid_access_1; eauto.
        }
  - clear - Hjit Hstore0 Hstore1 Hinvalid Heq.
    destruct Hinvalid as (Hinvalid0 & Hblk & Hvalid).
    split.
    + intro Hf; apply Hinvalid0.
      eapply Mem.store_valid_block_2; eauto.
    + split.
      * auto.
      * intros.
        assert (Hv: Mem.valid_block (bpf_m st0) b). {
          eapply Mem.store_valid_block_2; eauto.
        }
        specialize (Hvalid b H Hv).
        eapply Mem.valid_block_unchanged_on; eauto.
Qed.

Lemma eval_flag_extension:
  forall st0 st1 flag_blk regs_blk jit_blk f
  (Hex : RelEx flag_blk regs_blk jit_blk st0 st1)
  (Hflag: eval_flag st0 = Some f),
    eval_jit_flag st1 = Some f.
Proof.
  intros.
  unfold eval_flag, Mem.loadv in Hflag.
  unfold eval_jit_flag, Mem.loadv.
  destruct Hex as (Hunchanged, _,
      (Hflag_eq0 & Hflag_eq1 & Hflag_eq),
      _, _, _, _, _, _, _, (_ & Hblk & _)).
  rewrite Hflag_eq0 in Hflag.
  rewrite Hflag_eq1.
  eapply Mem.load_unchanged_on; eauto.
  intros.
  simpl.
  destruct Hblk as (_ & Hblk & _); auto.
Qed.

Lemma eval_reg_extension:
  forall st0 st1 flag_blk regs_blk jit_blk r v
  (Hex : RelEx flag_blk regs_blk jit_blk st0 st1)
  (Hflag: eval_reg r st0 = Some v),
    eval_jit_reg r st1 = Some v.
Proof.
  intros.
  unfold eval_reg, Mem.loadv in Hflag.
  unfold eval_jit_reg, Mem.loadv.
  destruct Hex as (Hunchanged, _, _,
      (Hreg_eq0 & Hreg_eq1 & Hreg_eq)
      , _, _, _, _, _, _, (_ & Hblk & _)).
  rewrite Hreg_eq0, Hreg_eq1 in *; clear Hreg_eq0 Hreg_eq1.
  simpl in *.
  eapply Mem.load_unchanged_on; eauto.
  intros.
  simpl.
  destruct Hblk as (_ & _ & Hblk); auto.
Qed.

Lemma eval_reg_extension_vlong:
  forall st0 st1 flag_blk regs_blk jit_blk r v
  (Hex : RelEx flag_blk regs_blk jit_blk st0 st1)
  (Hflag: eval_reg r st0 = Some v),
    exists vl, v = Vlong vl.
Proof.
  intros.
  unfold eval_reg, Mem.loadv in Hflag.
  destruct Hex as (Hunchanged, _, _,
      (Hreg_eq0 & Hreg_eq1 & Hreg_eq)
      , _, _, _, _, _, _, (_ & Hblk & _)).
  rewrite Hreg_eq0, Hreg_eq1 in *; clear Hreg_eq0 Hreg_eq1.
  simpl in *.
  specialize (Hreg_eq r).
  destruct Hreg_eq as (vl & Heq & _).
  rewrite Hflag in Heq.
  inversion Heq.
  exists vl; reflexivity.
Qed.

Lemma eval_pc_extension:
  forall st0 st1 flag_blk regs_blk jit_blk
  (Hex : RelEx flag_blk regs_blk jit_blk st0 st1),
    pc_loc st0 = jit_pc st1.
Proof.
  intros.
  destruct Hex as (Hunchanged, Hpc, _, _, _, _, _, _, _, _, _).
  assumption.
Qed.

Lemma upd_pc_extension:
  forall st0 st1 flag_blk regs_blk jit_blk pc
  (Hex : RelEx flag_blk regs_blk jit_blk st0 st1),
    RelEx flag_blk regs_blk jit_blk (upd_pc pc st0) (upd_jit_pc pc st1).
Proof.
  intros.
  unfold upd_pc, upd_jit_pc.
  destruct Hex.
  split; try assumption.
  simpl.
  reflexivity.
Qed.

Lemma upd_pc_incr_extension:
  forall st0 st1 flag_blk regs_blk jit_blk
  (Hex : RelEx flag_blk regs_blk jit_blk st0 st1),
    RelEx flag_blk regs_blk jit_blk (upd_pc_incr st0) (upd_jit_pc_incr st1).
Proof.
  intros.
  unfold upd_pc_incr, upd_jit_pc_incr.
  destruct Hex.
  split; try assumption.
  simpl.
  rewrite mpc.
  reflexivity.
Qed.

Lemma eval_ins_len_extension:
  forall st0 st1 flag_blk regs_blk jit_blk
  (Hex : RelEx flag_blk regs_blk jit_blk st0 st1),
    ins_len st0 = jit_ins_len st1.
Proof.
  intros.
  destruct Hex as (Hunchanged, _, _, _, _, _, Hlen, _, _, _, _).
  rewrite Hlen.
  reflexivity.
Qed.

Lemma eval_ins_extension:
  forall st0 st1 flag_blk regs_blk jit_blk
  (Hex : RelEx flag_blk regs_blk jit_blk st0 st1),
    ins st0 = jit_ins st1.
Proof.
  intros.
  destruct Hex as (Hunchanged, _, _, _, _, _, _, Hins, _, _, _).
  rewrite Hins.
  reflexivity.
Qed.

Lemma RelEx_implies_Rel:
  forall flag_blk regs_blk jit_blk st0 st1 st2
    (Hex : RelEx flag_blk regs_blk jit_blk st0 st1),
      Rel flag_blk regs_blk jit_blk st0 st1 st2.
Proof.
  intros.
  destruct Hex.
  split; simpl; try assumption.
  - destruct cur_ins_is_jit eqn: Hcond.
    + split; intro Hc.
      * inversion Hc.
      * rewrite mpc.
        clear.
        rewrite Bool.negb_true_iff.
        unfold Int.ltu.
        apply Coqlib.zlt_false.
        lia.
    + split; intro Hc.
      * assumption.
      * inversion Hc.
  - destruct cur_ins_is_jit eqn: Hcond.
    + split; intro Hc.
      * inversion Hc.
      * clear - mregs.
        unfold match_registers in mregs.
        unfold match_registers_arm.
        destruct mregs as (Hreg_eq0 & Hreg_eq1 & Hreg).
        split; [assumption | ].
        split; [assumption | ].
        intros.
        specialize (Hreg r).
        destruct Hreg as (vl & Hload0 & Hload1).
        exists vl.
        split; [assumption | ].
        left.
        assumption.
    + split; intro Hc.
      * assumption.
      * inversion Hc.
Qed.

Ltac destruct_inversion :=
  match goal with
  | H: match match ?X with |_ => _ end with |_ => _ end = _ |- _ =>
    destruct X; inversion H
  | H: (if ?X then _ else _) _ = _ |- _ =>
    destruct X; inversion H
  | |- ?X = ?X => reflexivity
  | H: match ?X with |_ => _ end = _ |- _ =>
    destruct X; inversion H
  end.

Ltac destruct_inversion_name :=
  let DI := fresh "DI" in
  match goal with
  | H: match match ?X with |_ => _ end with |_ => _ end = _ |- _ =>
    destruct X eqn: DI; inversion H
  | H: (if ?X then _ else _) _ = _ |- _ =>
    destruct X eqn: DI; inversion H
  | |- ?X = ?X => reflexivity
  | H: match ?X with |_ => _ end = _ |- _ =>
    destruct X eqn: DI; inversion H
  end.

Lemma step_opcode_alu64_some_tt:
    forall dst64 src64 dst op st0 st1 u
    (Hf: step_opcode_alu64 dst64 src64 dst op st0 = Some (u, st1)),
      u = tt.
Proof.
  unfold step_opcode_alu64.
  intros.
  unfold rBPFInterpreter2.get_opcode_alu64 in Hf.
  unfold rBPFMonadOp2.upd_reg, rBPFMonadOp2.upd_flag in Hf.
  unfold rBPFInterpreter2.reg64_to_reg32 in Hf.
  unfold bindM, returnM in Hf.
  destruct byte_to_opcode_alu64; repeat destruct_inversion.
Qed.

Lemma step_opcode_alu32_some_tt:
    forall dst32 src32 dst op st0 st1 u
    (Hf: step_opcode_alu32 dst32 src32 dst op st0 = Some (u, st1)),
      u = tt.
Proof.
  unfold step_opcode_alu32.
  intros.
  unfold rBPFInterpreter2.get_opcode_alu32 in Hf.
  unfold rBPFMonadOp2.upd_reg, rBPFMonadOp2.upd_flag in Hf.
  unfold bindM, returnM in Hf.
  destruct byte_to_opcode_alu32; repeat destruct_inversion.
Qed.


Lemma step_opcode_branch_some_tt:
    forall dst64 src64 pc ofs op st0 st1 u
    (Hf: step_opcode_branch dst64 src64 pc ofs op st0 = Some (u, st1)),
      u = tt.
Proof.
  unfold step_opcode_branch.
  intros.
  unfold rBPFInterpreter2.get_opcode_branch in Hf.
  unfold rBPFMonadOp2.upd_pc, rBPFMonadOp2.upd_flag, rBPFMonadOp2.upd_reg in Hf.
  unfold bindM, returnM in Hf.
  destruct byte_to_opcode_branch; repeat destruct_inversion.
Qed.


Lemma step_opcode_mem_ld_imm_some_tt:
    forall imm dst64 dst op st0 st1 u
    (Hf: step_opcode_mem_ld_imm imm dst64 dst op st0 = Some (u, st1)),
      u = tt.
Proof.
  unfold step_opcode_mem_ld_imm.
  intros.
  unfold rBPFInterpreter2.get_opcode_mem_ld_imm in Hf.
  unfold rBPFMonadOp2.upd_flag, rBPFMonadOp2.upd_reg in Hf.
  unfold bindM, returnM in Hf.
  destruct byte_to_opcode_mem_ld_imm; repeat destruct_inversion.
Qed.


Lemma step_opcode_mem_ld_reg_some_tt:
    forall addr dst64 op st0 st1 u
    (Hf: step_opcode_mem_ld_reg addr dst64 op st0 = Some (u, st1)),
      u = tt.
Proof.
  unfold step_opcode_mem_ld_reg.
  intros.
  unfold rBPFInterpreter2.get_opcode_mem_ld_reg in Hf.
  unfold rBPFMonadOp2.upd_flag, rBPFMonadOp2.upd_reg in Hf.
  unfold bindM, returnM in Hf.
  destruct byte_to_opcode_mem_ld_reg; repeat destruct_inversion.
Qed.


Lemma step_opcode_mem_st_imm_some_tt:
    forall imm addr op st0 st1 u
    (Hf: step_opcode_mem_st_imm imm addr op st0 = Some (u, st1)),
      u = tt.
Proof.
  unfold step_opcode_mem_st_imm.
  intros.
  unfold rBPFInterpreter2.get_opcode_mem_st_imm in Hf.
  unfold rBPFMonadOp2.upd_flag, rBPFMonadOp2.upd_reg in Hf.
  unfold bindM, returnM in Hf.
  destruct byte_to_opcode_mem_st_imm; repeat destruct_inversion.
Qed.


Lemma step_opcode_mem_st_reg_some_tt:
    forall src64 addr op st0 st1 u
    (Hf: step_opcode_mem_st_reg src64 addr op st0 = Some (u, st1)),
      u = tt.
Proof.
  unfold step_opcode_mem_st_reg.
  intros.
  unfold rBPFInterpreter2.get_opcode_mem_st_reg in Hf.
  unfold rBPFMonadOp2.upd_flag, rBPFMonadOp2.upd_reg in Hf.
  unfold bindM, returnM in Hf.
  destruct byte_to_opcode_mem_st_reg; repeat destruct_inversion.
Qed.


Lemma step_some_tt:
    forall st0 st1 u
    (Hf: step st0 = Some (u, st1)),
      u = tt.
Proof.
  unfold step.
  intros.
  unfold rBPFMonadOp2.eval_pc, rBPFMonadOp2.eval_ins in Hf.
  unfold rBPFInterpreter2.get_opcode_ins, rBPFInterpreter2.get_opcode in Hf.
  unfold rBPFInterpreter2.get_src64, rBPFInterpreter2.get_src32 in Hf.
  unfold rBPFInterpreter2.get_src, rBPFInterpreter2.reg64_to_reg32 in Hf.
  unfold rBPFMonadOp2.eval_reg, rBPFInterpreter2.get_dst in Hf.
  unfold rBPFInterpreter2.get_immediate, rBPFInterpreter2.eval_immediate in Hf.
  unfold rBPFMonadOp2.int64_to_dst_reg, rBPFMonadOp2.upd_flag in Hf.
  unfold bindM, returnM in Hf.
  destruct Int.cmpu; [| inversion Hf].
  destruct eval_ins; [| inversion Hf].
  destruct int64_to_dst_reg'; [| inversion Hf].
  destruct byte_to_opcode; repeat destruct_inversion.
  - eapply step_opcode_alu64_some_tt; eauto.
  - eapply step_opcode_alu32_some_tt; eauto.
  - eapply step_opcode_branch_some_tt; eauto.
  - eapply step_opcode_mem_ld_imm_some_tt; eauto.
  - eapply step_opcode_mem_ld_reg_some_tt; eauto.
  - eapply step_opcode_mem_st_imm_some_tt; eauto.
  - eapply step_opcode_mem_st_reg_some_tt; eauto.
Qed.

Section SimulationJITProof2.
  Context {flag_blk regs_blk jit_blk: block}.

  Lemma step_opcode_alu64_sim:
    forall dst64 src64 dst op sti0 sti1 stj0
    (Hf: step_opcode_alu64 dst64 src64 dst op sti0 = Some (tt, sti1))
    (Hjit : RelEx flag_blk regs_blk jit_blk sti0 stj0),
      exists stj1, ibpf_step_opcode_alu64 dst64 src64 dst op stj0 = Some (tt, stj1) /\
        RelEx flag_blk regs_blk jit_blk sti1 stj1.
  Proof.
    unfold step_opcode_alu64, ibpf_step_opcode_alu64.
    unfold rBPFInterpreter2.get_opcode_alu64, get_opcode_alu64.
    unfold rBPFMonadOp2.upd_reg, IMonadOp.upd_jit_reg.
    unfold rBPFMonadOp2.upd_flag, IMonadOp.upd_jit_flag.
    unfold rBPFInterpreter2.reg64_to_reg32, reg64_to_reg32.
    unfold bindM, returnM.
    intros.
    destruct byte_to_opcode_alu64; repeat destruct_inversion_name; subst.
    all: try (
      eapply upd_reg_extension in DI0; eauto;
      destruct DI0 as (st1' & Heq & Hex);
      rewrite Heq; clear Heq;
      exists st1';
      split; [reflexivity | assumption]).
    all: try (
      eapply upd_reg_extension in DI1; eauto;
      destruct DI1 as (st1' & Heq & Hex);
      rewrite Heq; clear Heq;
      exists st1';
      split; [reflexivity | assumption]).
    all: try (
      eapply upd_flag_extension in DI0; eauto;
      destruct DI0 as (st1' & Heq & Hex);
      rewrite Heq; clear Heq;
      exists st1';
      split; [reflexivity | assumption]).

    eapply upd_flag_extension in DI; eauto;
    destruct DI as (st1' & Heq & Hex);
    rewrite Heq; clear Heq;
    exists st1';
    split; [reflexivity | assumption].
  Qed.

  Axiom _bpf_get_call_sim:
    forall i v st0 st1
      (Hcall: rBPFMonadOp2._bpf_get_call (Vint i) st0 = Some (v, st0))
      (Hjit : RelEx flag_blk regs_blk jit_blk st0 st1),
        IMonadOp._jit_bpf_get_call (Vint i) st1 = Some (v, st1).

  Axiom exec_function_sim:
    forall b ofs v st0 st1 st2
      (Hexec : rBPFMonadOp2.exec_function (Vptr b ofs) st0 = Some (Vint v, st2))
      (Hjit : RelEx flag_blk regs_blk jit_blk st0 st1),
        exists st3,
          IMonadOp.jit_exec_function (Vptr b ofs) st1 = Some (Vint v, st3) /\
            RelEx flag_blk regs_blk jit_blk st2 st3.


  Lemma step_opcode_branch_sim:
    forall dst64 src64 pc ofs op sti0 sti1 stj0
    (Hf: step_opcode_branch dst64 (Vlong src64) pc ofs op sti0 = Some (tt, sti1))
    (Hjit : RelEx flag_blk regs_blk jit_blk sti0 stj0),
      exists stj1, ibpf_step_opcode_branch dst64 (Vlong src64) pc ofs op stj0 = Some (tt, stj1) /\
        RelEx flag_blk regs_blk jit_blk sti1 stj1.
  Proof.
    unfold step_opcode_branch, ibpf_step_opcode_branch.
    unfold rBPFInterpreter2.get_opcode_branch, get_opcode_branch.
    unfold rBPFMonadOp2.upd_pc, IMonadOp.upd_jit_pc.
    unfold rBPFMonadOp2.upd_flag, IMonadOp.upd_jit_flag.
    unfold bindM, returnM.
    intros.

    assert (Heq_len: ins_len sti0 = jit_ins_len stj0). {
      clear - Hjit.
      eapply eval_ins_len_extension; eauto.
    }
    unfold rBPFMonadOp2.cmp_ptr32_nullM in Hf.
    unfold IMonadOp.cmp_ptr32_nullM.
    unfold cmp_ptr32_null, eval_mem in Hf.
    unfold Val.cmpu_bool in Hf.

    destruct byte_to_opcode_branch.
    13:{
      destruct_inversion_name; subst.
      - unfold val_intsoflongu in *.
        assert (Hcall:= rBPFMonadOp2.lemma_bpf_get_call).
        specialize (Hcall (Int.repr (Int64.unsigned src64)) sti0).
        destruct Hcall as (ptr & Hcall & Hmem_ptr).
        clear H0.
        rewrite Hcall in Hf.
        eapply _bpf_get_call_sim in Hcall; eauto.
        rewrite Hcall; clear Hcall.

        destruct Hmem_ptr as [Hnull | Hptr].
        + subst.
          simpl in *.
          rewrite Int.eq_true in *.
          destruct_inversion_name; subst.
          eapply upd_flag_extension in DI0; eauto.
          destruct DI0 as (st1' & Heq & Hex).
          rewrite Heq; clear Heq.
          exists st1'; split; [reflexivity | assumption].
        + destruct Hptr as (b & ofs1 & Hptr & Hvalid_ptr).
          subst ptr.
          simpl in *.
          rewrite Int.eq_true in *.
          rewrite Hvalid_ptr in Hf.
          simpl in Hf.
          assert (Hexec:= rBPFMonadOp2.lemma_exec_function0).
          specialize (Hexec b ofs1 sti0).
          destruct Hexec as (v & st2 & Hexec & Hptr).
          rewrite Hexec in Hf.
          unfold eval_jit_mem.
          unfold eval_mem in Hptr.

          assert (Htmp:
            (Mem.valid_pointer (jit_mem stj0) b (Ptrofs.unsigned ofs1)
            || Mem.valid_pointer (jit_mem stj0) b (Ptrofs.unsigned ofs1 - 1))%bool = true). {
            apply Bool.orb_prop in Hvalid_ptr.
            destruct Hvalid_ptr as [Hvalid | Hvalid].
            - destruct Hjit as (Hunchanged, _, _, _, _, _, _, _, _, _, Hinvalid).
              apply unchanged_on_valid_pointer with
                (b := b) (ofs := Ptrofs.unsigned ofs1) in Hunchanged.
              + rewrite <- Hunchanged.
                rewrite Hvalid.
                simpl; reflexivity.
              + eapply valid_pointer_implies_valid_block; eauto.
              + intros.
                intros Heq.
                subst b.
                destruct Hinvalid as (Hinvalid & _).
                apply Hinvalid.
                eapply valid_pointer_implies_valid_block; eauto.
            - destruct Hjit as (Hunchanged, _, _, _, _, _, _, _, _, _, Hinvalid).
              apply unchanged_on_valid_pointer with
                (b := b) (ofs := (Ptrofs.unsigned ofs1 - 1)%Z) in Hunchanged.
              + rewrite <- Hunchanged.
                rewrite Hvalid.
                apply Bool.orb_true_r.
              + eapply valid_pointer_implies_valid_block; eauto.
              + intros.
                intros Heq.
                subst b.
                destruct Hinvalid as (Hinvalid & _).
                apply Hinvalid.
                eapply valid_pointer_implies_valid_block; eauto.
          }
          rewrite Htmp; clear Htmp.
          simpl.
          eapply exec_function_sim in Hexec; eauto.
          destruct Hexec as (st3 & Hexec & Hex3).
          rewrite Hexec; clear Hexec.
          unfold rBPFMonadOp2.upd_reg in Hf.
          simpl in Hf.
          unfold IMonadOp.upd_jit_reg; simpl.
          destruct_inversion_name; subst.
          eapply upd_reg_extension in DI0; eauto.
          destruct DI0 as (st1' & Heq & Hex).
          rewrite Heq; clear Heq.
          exists st1'; split; [reflexivity | assumption].
      - clear - Hf Hjit.
        destruct_inversion_name; subst.
        eapply upd_flag_extension in DI; eauto.
        destruct DI as (st1' & Heq & Hex).
        rewrite Heq; clear Heq.
        exists st1'; split; [reflexivity | assumption].
    }

    all: repeat destruct_inversion_name; subst.
    all: try (rewrite <- Heq_len; clear Heq_len).
    all: try rewrite DI1.
    all: try
      (exists (upd_jit_pc (Int.add pc ofs) stj0);
        split; [reflexivity | eapply upd_pc_extension; eauto]).
    all: try
      ( eapply upd_flag_extension in DI0; eauto;
        destruct DI0 as (st1' & Heq & Hex);
        rewrite Heq; clear Heq;
        exists st1'; split; [reflexivity | assumption]).
    all: try (exists stj0; split; [reflexivity | assumption]).
    eapply upd_flag_extension in DI; eauto;
    destruct DI as (st1' & Heq & Hex);
    rewrite Heq; clear Heq;
    exists st1'; split; [reflexivity | assumption].
  Qed.

  Lemma step_opcode_mem_ld_imm_sim:
    forall imm dst64 dst op sti0 sti1 stj0
    (Hf: step_opcode_mem_ld_imm imm dst64 dst op sti0 = Some (tt, sti1))
    (Hjit : RelEx flag_blk regs_blk jit_blk sti0 stj0),
      exists stj1, ibpf_step_opcode_mem_ld_imm imm dst64 dst op stj0 = Some (tt, stj1) /\
        RelEx flag_blk regs_blk jit_blk sti1 stj1.
  Proof.
    unfold step_opcode_mem_ld_imm, ibpf_step_opcode_mem_ld_imm.
    unfold rBPFInterpreter2.get_opcode_mem_ld_imm, get_opcode_mem_ld_imm.
    unfold rBPFMonadOp2.upd_reg, rBPFMonadOp2.upd_flag.
    unfold IMonadOp.upd_jit_reg, IMonadOp.upd_jit_flag.
    unfold bindM, returnM.
    intros.
    destruct byte_to_opcode_mem_ld_imm; repeat destruct_inversion_name; subst.
    - eapply upd_reg_extension in DI0; eauto;
      destruct DI0 as (st1' & Heq & Hex);
      rewrite Heq; clear Heq;
      exists st1'; split; [reflexivity | assumption].
    - eapply upd_reg_extension in DI0; eauto;
      destruct DI0 as (st1' & Heq & Hex);
      rewrite Heq; clear Heq;
      exists st1'; split; [reflexivity | assumption].
    - eapply upd_flag_extension in DI; eauto;
      destruct DI as (st1' & Heq & Hex);
      rewrite Heq; clear Heq;
      exists st1'; split; [reflexivity | assumption].
  Qed.
(*
  Lemma step_opcode_mem_ld_reg_sim:
    forall perm chunk addr v sti0 sti1 stj0
    (Hf: rBPFInterpreter2.check_mem perm chunk addr sti0 = Some (v, sti1))
    (Hjit : RelEx flag_blk regs_blk jit_blk sti0 stj0),
      exists stj1, check_mem perm chunk addr stj0 = Some (v, stj1) /\
        RelEx flag_blk regs_blk jit_blk sti1 stj1.
  Proof.
    intros.
    ...
  Qed.

  Lemma step_opcode_mem_ld_reg_sim:
    forall addr dst op sti0 sti1 stj0
    (Hf: step_opcode_mem_ld_reg addr dst op sti0 = Some (tt, sti1))
    (Hjit : RelEx flag_blk regs_blk jit_blk sti0 stj0),
      exists stj1, ibpf_step_opcode_mem_ld_reg addr dst op stj0 = Some (tt, stj1) /\
        RelEx flag_blk regs_blk jit_blk sti1 stj1.
  Proof.
    unfold step_opcode_mem_ld_reg, ibpf_step_opcode_mem_ld_reg.
    unfold rBPFInterpreter2.get_opcode_mem_ld_reg, get_opcode_mem_ld_reg.
    unfold rBPFMonadOp2.cmp_ptr32_nullM, IMonadOp.cmp_ptr32_nullM.
    unfold rBPFMonadOp2.upd_flag, IMonadOp.upd_jit_flag.
    unfold rBPFMonadOp2.load_mem, IMonadOp.load_jit_mem.
    unfold rBPFMonadOp2.upd_reg, IMonadOp.upd_jit_reg.
    intros.
  Qed. *)

End SimulationJITProof2.