From Coq Require Import ZArith Lia.
From compcert Require Import Integers Values AST Memory Memdata.

From bpf.comm Require Import Flag Regs State Monad BinrBPF rBPFMonadOp rBPFMemType rBPFValues.

From bpf.monadicmodel2 Require Import ConcreteState.

From bpf.jit.thumb Require Import LoadStoreRegs ThumbEncode ThumbInsOp Arm32Reg JITState ThumbJITOpcode ThumbJIT.

From bpf.jit.simulation Require Import SimulationJIT SimulationJITExtension.


Open Scope nat_scope.
(** before calling jit_alu32, the initial jit state just extends the bpf state,
  i.e. most fields of the jit state is equal to the corresponding field of the given bpf state. *)


Lemma add_ins_jittedthumb_extension:
  forall ins st st0 st1 flag_blk regs_blk jit_blk
    (Hex: RelEx flag_blk regs_blk jit_blk st st0)
    (Hf: add_ins_jittedthumb ins st0 = st1),
      RelEx flag_blk regs_blk jit_blk st st1.
Proof.
  intros.
  unfold add_ins_jittedthumb in Hf.
  subst.
  destruct Hex as (Hunchange, Hpc, Hflag, Hregs, Hnum, Hmrs, Hlen, Hins, Hjit, Hperm, Hinvalid).
  split; simpl; assumption.
Qed.

Lemma jit_alu32_thumb_store_template_ins_extension:
  forall rt rn imm st st0 st1 flag_blk regs_blk jit_blk
    (Hex: RelEx flag_blk regs_blk jit_blk st st0)
    (Hf: jit_alu32_thumb_store_template_ins rt rn imm st0 = st1),
      RelEx flag_blk regs_blk jit_blk st st1.
Proof.
  intros.
  unfold jit_alu32_thumb_store_template_ins in Hf.
  apply add_ins_jittedthumb_extension with
    (st0 := (add_ins_jittedthumb (encode_arm32 rn STR_I_OP 0 4) st0))
    (ins := (encode_arm32 rt imm 12 4)).
  apply add_ins_jittedthumb_extension with (st0 := st0)
    (ins := (encode_arm32 rn STR_I_OP 0 4)).
  assumption.
  reflexivity.
  assumption.
Qed.

Lemma jit_alu32_thumb_load_template_ins_extension:
  forall rt rn imm st st0 st1 flag_blk regs_blk jit_blk
    (Hex: RelEx flag_blk regs_blk jit_blk st st0)
    (Hf: jit_alu32_thumb_load_template_ins rt rn imm st0 = st1),
      RelEx flag_blk regs_blk jit_blk st st1.
Proof.
  intros.
  unfold jit_alu32_thumb_load_template_ins in Hf.
  apply add_ins_jittedthumb_extension with
    (st0 := (add_ins_jittedthumb (encode_arm32 rn LDR_I_OP 0 4) st0))
    (ins := (encode_arm32 rt imm 12 4)).
  apply add_ins_jittedthumb_extension with (st0 := st0)
    (ins := (encode_arm32 rn LDR_I_OP 0 4)).
  assumption.
  reflexivity.
  assumption.
Qed.

Lemma jit_alu32_store_flag_extension:
  forall f st st0 st1 flag_blk regs_blk jit_blk
    (Hex: RelEx flag_blk regs_blk jit_blk st st0)
    (Hf: jit_alu32_store_flag f st0 = st1),
      RelEx flag_blk regs_blk jit_blk st st1.
Proof.
  intros.
  unfold jit_alu32_store_flag in Hf.
  destruct is_non_reg.
  - apply jit_alu32_thumb_store_template_ins_extension with
    (st := st) (flag_blk := flag_blk) (regs_blk := regs_blk) (jit_blk := jit_blk) in Hf;
      [apply Hf | clear Hf].

    destruct is_non_reg.
    +
      remember (jit_alu32_thumb_load_template_ins _ _ _ _) as st2 eqn: Hf.
      symmetry in Hf.
      apply jit_alu32_thumb_load_template_ins_extension with
      (st := st) (flag_blk := flag_blk) (regs_blk := regs_blk) (jit_blk := jit_blk)  in Hf;
        [apply Hf | clear Hf st2].

      remember (add_ins_jittedthumb _ _) as st2 eqn: Hf.
      symmetry in Hf.
      apply add_ins_jittedthumb_extension with
      (st := st) (flag_blk := flag_blk) (regs_blk := regs_blk) (jit_blk := jit_blk)  in Hf;
        [apply Hf | clear Hf st2].

      remember (add_ins_jittedthumb _ _) as st2 eqn: Hf.
      symmetry in Hf.
      apply add_ins_jittedthumb_extension with
      (st := st) (flag_blk := flag_blk) (regs_blk := regs_blk) (jit_blk := jit_blk)  in Hf;
        [apply Hf | clear Hf st2].
      assumption.
    + remember (jit_alu32_thumb_load_template_ins _ _ _ _) as st2 eqn: Hf.
      symmetry in Hf.
      apply jit_alu32_thumb_load_template_ins_extension with
      (st := st) (flag_blk := flag_blk) (regs_blk := regs_blk) (jit_blk := jit_blk)  in Hf;
        [apply Hf | clear Hf st2].

      remember (jit_alu32_thumb_store_template_ins _ _ _ _) as st2 eqn: Hf.
      symmetry in Hf.
      apply jit_alu32_thumb_store_template_ins_extension with
      (st := st) (flag_blk := flag_blk) (regs_blk := regs_blk) (jit_blk := jit_blk)  in Hf;
        [apply Hf | clear Hf st2].

      remember (add_ins_jittedthumb _ _) as st2 eqn: Hf.
      symmetry in Hf.
      apply add_ins_jittedthumb_extension with
      (st := st) (flag_blk := flag_blk) (regs_blk := regs_blk) (jit_blk := jit_blk)  in Hf;
        [apply Hf | clear Hf st2].

      remember (add_ins_jittedthumb _ _) as st2 eqn: Hf.
      symmetry in Hf.
      apply add_ins_jittedthumb_extension with
      (st := st) (flag_blk := flag_blk) (regs_blk := regs_blk) (jit_blk := jit_blk)  in Hf;
        [apply Hf | clear Hf st2].
      assumption.
  - apply jit_alu32_thumb_load_template_ins_extension with
    (st := st) (flag_blk := flag_blk) (regs_blk := regs_blk) (jit_blk := jit_blk) in Hf;
      [apply Hf | clear Hf].

    destruct is_non_reg.
    + remember (jit_alu32_thumb_store_template_ins _ _ _ _) as st2 eqn: Hf.
      symmetry in Hf.
      apply jit_alu32_thumb_store_template_ins_extension with
      (st := st) (flag_blk := flag_blk) (regs_blk := regs_blk) (jit_blk := jit_blk)  in Hf;
        [apply Hf | clear Hf st2].

      remember (jit_alu32_thumb_load_template_ins _ _ _ _) as st2 eqn: Hf.
      symmetry in Hf.
      apply jit_alu32_thumb_load_template_ins_extension with
      (st := st) (flag_blk := flag_blk) (regs_blk := regs_blk) (jit_blk := jit_blk)  in Hf;
        [apply Hf | clear Hf st2].

      remember (add_ins_jittedthumb _ _) as st2 eqn: Hf.
      symmetry in Hf.
      apply add_ins_jittedthumb_extension with
      (st := st) (flag_blk := flag_blk) (regs_blk := regs_blk) (jit_blk := jit_blk)  in Hf;
        [apply Hf | clear Hf st2].

      remember (add_ins_jittedthumb _ _) as st2 eqn: Hf.
      symmetry in Hf.
      apply add_ins_jittedthumb_extension with
      (st := st) (flag_blk := flag_blk) (regs_blk := regs_blk) (jit_blk := jit_blk)  in Hf;
        [apply Hf | clear Hf st2].
      assumption.
    + remember (jit_alu32_thumb_store_template_ins _ _ _ _) as st2 eqn: Hf.
      symmetry in Hf.
      apply jit_alu32_thumb_store_template_ins_extension with
      (st := st) (flag_blk := flag_blk) (regs_blk := regs_blk) (jit_blk := jit_blk)  in Hf;
        [apply Hf | clear Hf st2].

      remember (jit_alu32_thumb_load_template_ins _ _ _ _) as st2 eqn: Hf.
      symmetry in Hf.
      apply jit_alu32_thumb_load_template_ins_extension with
      (st := st)
      (flag_blk := flag_blk) (regs_blk := regs_blk) (jit_blk := jit_blk)  in Hf;
        [apply Hf | clear Hf st2].

      remember (jit_alu32_thumb_store_template_ins _ _ _ _) as st2 eqn: Hf.
      symmetry in Hf.
      apply jit_alu32_thumb_store_template_ins_extension with
      (st := st) (flag_blk := flag_blk) (regs_blk := regs_blk) (jit_blk := jit_blk)  in Hf;
        [apply Hf | clear Hf st2].

      remember (add_ins_jittedthumb _ _) as st2 eqn: Hf.
      symmetry in Hf.
      apply add_ins_jittedthumb_extension with
      (st := st) (flag_blk := flag_blk) (regs_blk := regs_blk) (jit_blk := jit_blk)  in Hf;
        [apply Hf | clear Hf st2].

      remember (add_ins_jittedthumb _ _) as st2 eqn: Hf.
      symmetry in Hf.
      apply add_ins_jittedthumb_extension with
      (st := st) (flag_blk := flag_blk) (regs_blk := regs_blk) (jit_blk := jit_blk)  in Hf;
        [apply Hf | clear Hf st2].
      assumption.
Qed.

Lemma upd_IR11_jittedthumb_extension:
  forall f st st0 st1 flag_blk regs_blk jit_blk
    (Hex: RelEx flag_blk regs_blk jit_blk st st0)
    (Hf: upd_IR11_jittedthumb f st0 = st1),
      RelEx flag_blk regs_blk jit_blk st st1.
Proof.
  intros.
  unfold upd_IR11_jittedthumb in Hf.
  subst.
  destruct Hex as (Hunchange, Hpc, Hflag, Hregs, Hnum, Hmrs, Hlen, Hins, Hjit, Hperm, Hinvalid).
  split; simpl; assumption.
Qed.

Lemma upd_thumb_jittedthumb_extension:
  forall ins pc st st0 st1 flag_blk regs_blk jit_blk
    (Hex: RelEx flag_blk regs_blk jit_blk st st0)
    (Hf: upd_thumb_jittedthumb ins pc st0 = st1),
      RelEx flag_blk regs_blk jit_blk st st1.
Proof.
  intros.
  unfold upd_thumb_jittedthumb in Hf.
  subst.
  destruct Hex as (Hunchange, Hpc, Hflag, Hregs, Hnum, Hmrs, Hlen, Hins, Hjit, Hperm, Hinvalid).
  split; simpl; assumption.
Qed.
(*
Lemma jit_alu32_entry_points_list_extension:
  forall k n st st0 st1 flag_blk regs_blk jit_blk t, (**r Imporant k and n must be the first two arguments*)
    k >= n ->
    RelEx flag_blk regs_blk jit_blk st st0 ->
    jit_alu32_entry_points_list n (k-n) t st0 = Some st1 -> (**r Imporant *)
      RelEx flag_blk regs_blk jit_blk st st1.
Proof.
  induction n; simpl; intros st st0 st1 flag_blk regs_blk jit_blk t Hk Hex Haux.
  - subst.
    inversion Haux.
    subst.
    assumption.
  - assert (Heq: (S (k - S n)) = k - n) by lia.
    rewrite Heq in *; clear Heq.
    destruct eval_ins; [| inversion Haux].
    destruct ins_is_bpf_alu32.
    + (**r ins_is_bpf_alu32 _ _ = true *)
      destruct t; simpl in *.
      * (**r t = true *)
        eapply IHn; [ lia | apply Hex | apply Haux].
      *  (**r t = true *)
        destruct is_ep_exists.
        { (**r is_ep_exists _ _ = true *)
          eapply IHn; [ lia | apply Hex | apply Haux].
        }
        {  (**r is_ep_exists _ _ = false *)
          eapply IHn; [ lia | | apply Haux ].
          clear - Hex.
          unfold add_new_entry_point.
          destruct Hex as (Hunchange, Hpc, Hflag, Hregs, Hnum, Hmrs, Hlen, Hins, Hjit, Hperm, Hinvalid).
          split; simpl; assumption.
        }
    +  (**r ins_is_bpf_alu32 _ _ = false *)
      destruct ins_is_bpf_jump.
      * (**r ins_is_bpf_jump _ _ = true *)
        destruct eval_ins; [| inversion Haux].
        destruct ins_is_bpf_alu32.
        { (**r ins_is_bpf_alu32 _ _ = true *)
          eapply IHn; [ lia | | apply Haux ].
          clear - Hex.
          unfold add_new_entry_point.
          destruct Hex as (Hunchange, Hpc, Hflag, Hregs, Hnum, Hmrs, Hlen, Hins, Hjit, Hperm, Hinvalid).
          split; simpl; assumption.
        }
        { (**r ins_is_bpf_alu32 _ _ = false *)
          eapply IHn; [ lia | apply Hex| apply Haux ].
        }
      * (**r ins_is_bpf_jump _ _ = false *)
        eapply IHn; [ lia | apply Hex| apply Haux ].
Qed.
*)

Lemma jit_alu32_to_thumb_pass2_aux_extension:
  forall k n st st0 st1 flag_blk regs_blk jit_blk, (**r Imporant k and n must be the first two arguments*)
    k >= n ->
    RelEx flag_blk regs_blk jit_blk st st0 ->
    jit_alu32_to_thumb_pass2_aux n (k-n) st0 = Some st1 -> (**r Imporant *)
      RelEx flag_blk regs_blk jit_blk st st1.
Proof.
  induction n; simpl; intros st st0 st1 flag_blk regs_blk jit_blk Hk Hex Haux.
  - inversion Haux.
    subst.
    assumption.
  - assert (Heq: (S (k - S n)) = k - n) by lia.
    rewrite Heq in *; clear Heq.
    destruct eval_thumb_ins; [| inversion Haux].
    match goal with
    | H: (if ?COND then ?B0 else ?B1) = _ |- _ =>
      destruct COND
    end.
    + eapply IHn; [ lia | | apply Haux ].
      clear - Hex.

      eapply upd_thumb_jittedthumb_extension; [| reflexivity].
      assumption.
    + eapply IHn; [ lia | apply Hex | apply Haux ].
Qed.

Lemma upd_load_store_regs_jittedthumb_extension:
  forall dst perm st st0 st1 flag_blk regs_blk jit_blk,
    RelEx flag_blk regs_blk jit_blk st st0 ->
    upd_load_store_regs_jittedthumb dst perm st0 = Some st1 ->
      RelEx flag_blk regs_blk jit_blk st st1.
Proof.
  intros dst perm st st0 st1 flag_blk regs_blk jit_blk Hex Haux.
  unfold upd_load_store_regs_jittedthumb in Haux.
  destruct LoadStoreRegs.upd_LoadStoreRegs;[| inversion Haux].
  inversion Haux; clear - Hex; 
  destruct Hex as (Hunchange, Hpc, Hflag, Hregs, Hnum, Hmrs, Hlen, Hins, Hjit, Hperm, Hinvalid).
  split; simpl; assumption.
Qed.

Lemma bpf_alu32_to_thumb_reg_extension:
  forall op dst src st st0 st1 flag_blk regs_blk jit_blk,
    RelEx flag_blk regs_blk jit_blk st st0 ->
    bpf_alu32_to_thumb_reg op dst src st0 = Some st1 ->
      RelEx flag_blk regs_blk jit_blk st st1.
Proof.
  intros op dst src st st0 st1 flag_blk regs_blk jit_blk Hex Haux.
  unfold bpf_alu32_to_thumb_reg in Haux.
  destruct op.
  4:{ (**r BPF_DIV32_REG *)
    match goal with
    | H: (if ?COND then ?B1 else ?B2) = _ |- _ =>
      destruct COND; [| inversion H]
    end.
    destruct upd_load_store_regs_jittedthumb eqn: Heq; [| inversion Haux].
    apply upd_load_store_regs_jittedthumb_extension with
      (st := st) (flag_blk := flag_blk) (regs_blk := regs_blk) (jit_blk := jit_blk) in Heq.
    2:{
      clear - Hex.

      repeat (eapply add_ins_jittedthumb_extension; [| reflexivity]).
      eapply jit_alu32_store_flag_extension; [| reflexivity].
      repeat (eapply add_ins_jittedthumb_extension; [| reflexivity]).
      eapply upd_IR11_jittedthumb_extension with (st0 := st0).
      assumption.
      reflexivity.
    }
    destruct ireg_eqb eqn: Heq'.
    * inversion Haux.
      subst.
      assumption.
    * destruct reg_of_ireg; [| inversion Haux].
      eapply upd_load_store_regs_jittedthumb_extension with (st0 := j).
      assumption.
      apply Haux.
  }
  6:{ (**r BPF_LSH32_REG *)
    destruct upd_load_store_regs_jittedthumb eqn: Heq; [| inversion Haux].
    apply upd_load_store_regs_jittedthumb_extension with
      (st := st) (flag_blk := flag_blk) (regs_blk := regs_blk) (jit_blk := jit_blk) in Heq.
    2:{
      clear - Hex.
      repeat (eapply add_ins_jittedthumb_extension; [| reflexivity]).
      eapply jit_alu32_store_flag_extension; [| reflexivity].
      repeat (eapply add_ins_jittedthumb_extension; [| reflexivity]).
      eapply upd_IR11_jittedthumb_extension with (st0 := st0).
      assumption.
      reflexivity.
    }
    destruct ireg_eqb eqn: Heq'.
    * inversion Haux.
      subst.
      assumption.
    * destruct reg_of_ireg; [| inversion Haux].
      eapply upd_load_store_regs_jittedthumb_extension with (st0 := j).
      assumption.
      apply Haux.
  }
  6:{ (**r BPF_RSH32_REG *)
    destruct upd_load_store_regs_jittedthumb eqn: Heq; [| inversion Haux].
    apply upd_load_store_regs_jittedthumb_extension with
      (st := st) (flag_blk := flag_blk) (regs_blk := regs_blk) (jit_blk := jit_blk) in Heq.
    2:{
      clear - Hex.
      repeat (eapply add_ins_jittedthumb_extension; [| reflexivity]).
      eapply jit_alu32_store_flag_extension; [| reflexivity].
      repeat (eapply add_ins_jittedthumb_extension; [| reflexivity]).
      eapply upd_IR11_jittedthumb_extension with (st0 := st0).
      assumption.
      reflexivity.
    }
    destruct ireg_eqb eqn: Heq'.
    * inversion Haux.
      subst.
      assumption.
    * destruct reg_of_ireg; [| inversion Haux].
      eapply upd_load_store_regs_jittedthumb_extension with (st0 := j).
      assumption.
      apply Haux.
  }
  8:{ (**r BPF_ARSH32_REG *)
    destruct upd_load_store_regs_jittedthumb eqn: Heq; [| inversion Haux].
    apply upd_load_store_regs_jittedthumb_extension with
      (st := st) (flag_blk := flag_blk) (regs_blk := regs_blk) (jit_blk := jit_blk) in Heq.
    2:{
      clear - Hex.
      repeat (eapply add_ins_jittedthumb_extension; [| reflexivity]).
      eapply jit_alu32_store_flag_extension; [| reflexivity].
      repeat (eapply add_ins_jittedthumb_extension; [| reflexivity]).
      eapply upd_IR11_jittedthumb_extension with (st0 := st0).
      assumption.
      reflexivity.
    }
    destruct ireg_eqb eqn: Heq'.
    * inversion Haux.
      subst.
      assumption.
    * destruct reg_of_ireg; [| inversion Haux].
      eapply upd_load_store_regs_jittedthumb_extension with (st0 := j).
      assumption.
      apply Haux.
  }
  7:{
    destruct reg_ireg_eqb; inversion Haux.
    - subst.
      assumption.
    - destruct upd_load_store_regs_jittedthumb eqn: Heq; [| inversion Haux].
      apply upd_load_store_regs_jittedthumb_extension with
      (st := st) (flag_blk := flag_blk) (regs_blk := regs_blk) (jit_blk := jit_blk) in Heq.
      2:{
        clear - Hex.
        repeat (eapply add_ins_jittedthumb_extension; [| reflexivity]).
        assumption.
      }
      destruct ireg_eqb eqn: Heq'.
      * inversion Haux.
        subst.
        assumption.
      * destruct reg_of_ireg; [| inversion Haux].
        eapply upd_load_store_regs_jittedthumb_extension with (st0 := j).
        assumption.
        apply Haux.
  }
  7:{ inversion Haux. }

  all: destruct upd_load_store_regs_jittedthumb eqn: Heq; [| inversion Haux].
  all: eapply upd_load_store_regs_jittedthumb_extension with
      (st := st) (flag_blk := flag_blk) (regs_blk := regs_blk) (jit_blk := jit_blk) in Heq;
        [ |
        repeat (eapply add_ins_jittedthumb_extension; [ | reflexivity]); assumption].
  all:
    match goal with
    | H: (if ireg_eqb _ _ then _ else _) = _ |- _ =>
      destruct ireg_eqb; inversion H; [subst; assumption |]
    end.

  all:
    match goal with
    | H: match reg_of_ireg _ with | _ => _ end = _ |- _ =>
      destruct reg_of_ireg; [ | inversion Haux]
    end.

  all: eapply upd_load_store_regs_jittedthumb_extension with
      (st := st) (flag_blk := flag_blk) (regs_blk := regs_blk) (jit_blk := jit_blk) in Heq;
        [ apply Heq | apply Haux].
Qed.

Lemma bpf_alu32_to_thumb_imm_extension:
  forall op dst src st st0 st1 flag_blk regs_blk jit_blk,
    RelEx flag_blk regs_blk jit_blk st st0 ->
    bpf_alu32_to_thumb_imm op dst src st0 = Some st1 ->
      RelEx flag_blk regs_blk jit_blk st st1.
Proof.
  intros op dst src st st0 st1 flag_blk regs_blk jit_blk Hex Haux.
  unfold bpf_alu32_to_thumb_imm in Haux.
  destruct op.
  9:{ inversion Haux. }
  3:{ inversion Haux. }
  all: eapply upd_load_store_regs_jittedthumb_extension with (st := st) (jit_blk := jit_blk) in Haux;
        [ apply Haux |
          repeat (eapply add_ins_jittedthumb_extension; [ | reflexivity]); apply Hex].
Qed.

Lemma mov_int_to_reg_binary_extension:
  forall i r st st0 st1 flag_blk regs_blk jit_blk
    (Hex: RelEx flag_blk regs_blk jit_blk st st0)
    (Hf: mov_int_to_reg_binary i r st0 = st1),
      RelEx flag_blk regs_blk jit_blk st st1.
Proof.
  intros.
  unfold mov_int_to_reg_binary in Hf.
  destruct Int.eq.
  - eapply add_ins_jittedthumb_extension; [ | apply Hf].
    clear - Hex.
    eapply add_ins_jittedthumb_extension; [ | reflexivity].
    assumption.
  - eapply add_ins_jittedthumb_extension; [ | apply Hf].
    clear - Hex.
    repeat (eapply add_ins_jittedthumb_extension; [ | reflexivity]).
    assumption.
Qed.

Lemma bpf_alu32_to_thumb_extension:
  forall i st st0 st1 flag_blk regs_blk jit_blk,
    RelEx flag_blk regs_blk jit_blk st st0 ->
    bpf_alu32_to_thumb i st0 = Some st1 ->
      RelEx flag_blk regs_blk jit_blk st st1.
Proof.
  intros i st st0 st1 flag_blk regs_blk jit_blk Hex Haux.
  unfold bpf_alu32_to_thumb in Haux.
  destruct z_to_reg; [| inversion Haux].
  destruct nat_to_opcode_alu32.
  - (**r ALU32_REG *)
    destruct z_to_reg; [| inversion Haux].
    eapply bpf_alu32_to_thumb_reg_extension with (st0 := st0).
    assumption.
    apply Haux.
  - (**r ALU32_IMM *)
    match goal with
    | H: (if ?COND then ?B1 else ?B2) = _ |- _ =>
      destruct COND
    end.
    + eapply bpf_alu32_to_thumb_imm_extension with (st0 := st0).
      assumption.
      apply Haux.
    + eapply bpf_alu32_to_thumb_reg_extension with
      (st0 := mov_int_to_reg_binary _ _ _); [| apply Haux].
      clear - Hex.
      eapply mov_int_to_reg_binary_extension; [| reflexivity].
      eapply upd_IR11_jittedthumb_extension with (st0 := st0).
      assumption.
      reflexivity.
  - (**r ALU32_ILLEGAL_INS *)
    inversion Haux.
Qed.

Lemma upd_bpf_offset_jittedthumb_extension:
  forall st st0 st1 flag_blk regs_blk jit_blk
    (Hex: RelEx flag_blk regs_blk jit_blk st st0)
    (Hf: upd_bpf_offset_jittedthumb st0 = st1),
      RelEx flag_blk regs_blk jit_blk st st1.
Proof.
  intros.
  unfold upd_bpf_offset_jittedthumb in Hf.
  subst.
  destruct Hex as (Hunchange, Hpc, Hflag, Hregs, Hnum, Hmrs, Hlen, Hins, Hjit, Hperm, Hinvalid).
  split; simpl; assumption.
Qed.

Lemma jit_alu32_to_thumb_pass1_extension:
  forall k n st st0 st1 flag_blk regs_blk jit_blk, (**r Imporant k and n must be the first two arguments*)
    k >= n ->
    RelEx flag_blk regs_blk jit_blk st st0 ->
    jit_alu32_to_thumb_pass1 n (k-n) st0 = Some st1 -> (**r Imporant *)
      RelEx flag_blk regs_blk jit_blk st st1.
Proof.
  induction n; simpl; intros st st0 st1 flag_blk regs_blk jit_blk Hk Hex Hpass.
  - inversion Hpass.
    subst.
    clear - H0 Hex.
    unfold jit_alu32_to_thumb_pass2 in *.
    eapply jit_alu32_to_thumb_pass2_aux_extension with
      (k := thumb_len st0) (n := thumb_len st0);
      [ lia | apply Hex | ].
    assert (Heq: thumb_len st0 - thumb_len st0 = 0) by lia.
    rewrite Heq; clear Heq.
    assumption.
  - destruct eval_jit_ins; [| inversion Hpass].
    destruct ins_is_bpf_alu32.
    + (**r ins_is_bpf_alu32 _ _ = true *)
      destruct bpf_alu32_to_thumb eqn: Hthumb; [| inversion Hpass].
      assert (Heq: (S (k - S n)) = k - n) by lia.
      rewrite Heq in *; clear Heq.
      eapply IHn with (st0 := upd_bpf_offset_jittedthumb j).
      * lia.
      * eapply bpf_alu32_to_thumb_extension in Hthumb.
        eapply upd_bpf_offset_jittedthumb_extension; [apply Hthumb | reflexivity].
        assumption.
      * assumption.
    + (**r ins_is_bpf_alu32 _ _ = false *)
      inversion Hpass.
      clear Hpass; rename H0 into Hpass.
      unfold jit_alu32_to_thumb_pass2 in *.
      eapply jit_alu32_to_thumb_pass2_aux_extension with
      (k := thumb_len st0) (n := thumb_len st0);
      [ lia | apply Hex | ].
      assert (Heq: thumb_len st0 - thumb_len st0 = 0) by lia.
      rewrite Heq; clear Heq.
      assumption.
Qed.

(*
Lemma upd_ibpf_extension:
  forall ins ep st st0 st1 flag_blk regs_blk jit_blk
    (Hex: RelEx flag_blk regs_blk jit_blk st st0)
    (Hf: upd_ibpf ins ep st0 = st1),
      RelEx flag_blk regs_blk jit_blk st st1.
Proof.
  intros.
  unfold upd_ibpf in Hf.
  subst. (*
  admit. *)
  destruct Hex as (Hunchange, Hpc, Hflag, Hregs, Hnum, Hmrs, Hlen, Hins, Hjit, Hperm, Hinvalid).
  split; simpl; assumption.
Qed. *)

Lemma upd_jitted_list_extension:
  forall ins st st0 st1 flag_blk regs_blk jit_blk
    (Hex: RelEx flag_blk regs_blk jit_blk st st0)
    (Hf: upd_jitted_list ins st0 = Some st1),
      RelEx flag_blk regs_blk jit_blk st st1.
Proof.
  intros.
  unfold upd_jitted_list, upd_jitted_list' in Hf.
  destruct Mem.storev eqn: Hstore; [| inversion Hf].
  inversion Hf; clear H0 Hf.

  destruct Hex as (Hunchange, Hpc,
    (Hflag0, (Hflag1, Hflag)),
    (Hregs0, (Hregs1, Hregs)), Hnum, Hmrs, Hlen, Hins, Hjit, Hperm, Hinvalid).
  split; simpl; try assumption;
    unfold Mem.storev in Hstore; rewrite <- Hjit in Hstore; simpl in Hstore.
  - (**r unchanged_on *)
    clear - Hunchange Hinvalid Hstore.
    assert (Hmem: Mem.unchanged_on (fun (b : block) (_ : Z) => b <> jit_blk) 
              (jit_mem st0) m). {
      eapply Mem.store_unchanged_on; [ apply Hstore | ].
      intros.
      intro Hf; apply Hf; reflexivity.
    }
    eapply Mem.unchanged_on_trans with (m2 := (jit_mem st0)); assumption.
  - (**r flag *)
    split; [assumption | ].
    split; [assumption | ].
    clear - Hunchange Hflag Hflag1 Hinvalid Hstore.
    destruct Hflag as (f & Hflag0 & Hflag).
    exists f.
    split; [assumption | ].
    unfold eval_jit_flag, Mem.loadv in *.
    rewrite Hflag1 in *; simpl.

    assert (Heq: Mem.load Mint32 m flag_blk (Ptrofs.unsigned Ptrofs.zero) =
      Mem.load Mint32 (jit_mem st0) flag_blk (Ptrofs.unsigned Ptrofs.zero) ). {
      eapply Mem.load_unchanged_on_1 with (P := (fun (b : block) (_ : Z) => b <> jit_blk)).
      - eapply Mem.store_unchanged_on; [apply Hstore | ].
        intros.
        auto.
      - eapply load_valid_block; eauto.
      - intros.
        destruct Hinvalid as (_ & (_ & Hblk & _) & _).
        auto.
    }
    rewrite <- Hflag.
    assumption.
  - (**r regs *)
    split; [assumption | ].
    split; [assumption | ].
    intros.
    specialize (Hregs r).
    destruct Hregs as (vl & Hreg_eq0 & Hreg_eq1).
    exists vl.
    rewrite Hreg_eq0.
    split; [reflexivity | ].

    rewrite Hregs1, Hregs0 in *.

    simpl in *.

    remember (Ptrofs.unsigned
     (Ptrofs.add Ptrofs.zero
        (Ptrofs.of_int
           (Int.repr match id_of_reg r with
                     | 0 => 0
                     | Z.pos y' => Z.pos y'~0~0~0
                     | Z.neg y' => Z.neg y'~0~0~0
                     end))))%Z as k.

    assert (Heq: Mem.load Mint64 m regs_blk k =
      Mem.load Mint64 (jit_mem st0) regs_blk k). {
      eapply Mem.load_unchanged_on_1 with (P := (fun (b : block) (_ : Z) => b <> jit_blk)).
      - eapply Mem.store_unchanged_on; [apply Hstore | ].
        intros.
        auto.
      - eapply load_valid_block; eauto.
      - intros.
        destruct Hinvalid as (_ & (_ & _ & Hblk) & _).
        auto.
    }

    rewrite <- Hreg_eq1.
    assumption.

  - (**r perm *)
    destruct Hperm as (Hperm_flag0 & Hperm_reg0 & Hperm_flag1 & Hperm_reg1 & Hperm_jit).
    split; [assumption | ].
    split; [assumption | ].
    rewrite Hregs0, Hregs1 in *.
    simpl in *.
    split.
    + unfold ptr_range_perm in *.
      rewrite Hflag1 in *.
      eapply Mem.store_valid_access_1; eauto.
    + split.
      * intros.
        specialize (Hperm_reg1 r).
        eapply Mem.store_valid_access_1; eauto.
      * intros.
        specialize (Hperm_jit pc H).
        unfold ptr_range_perm in *.
        rewrite <- Hjit in *.
        simpl in *.
        eapply Mem.store_valid_access_1; eauto.

  - (**r invalid *)
    destruct Hinvalid as (Hinvalid0 & Hblk & Hinvalid).
    split; [assumption | ].
    split; [assumption | ].
    intros.
    specialize (Hinvalid b H H0).
    eapply Mem.store_valid_block_1; eauto.
Qed.

Lemma jit_alu32_pre_extension:
  forall st st0 st1 flag_blk regs_blk jit_blk
    (Hex: RelEx flag_blk regs_blk jit_blk st st0)
    (Hf: jit_alu32_pre st0 = Some st1),
      RelEx flag_blk regs_blk jit_blk st st1.
Proof.
  intros.
  unfold jit_alu32_pre in Hf.
  eapply upd_jitted_list_extension; eauto.
Qed.

Lemma jit_alu32_thumb_store_template_jit_extension:
  forall rt rn imm st st0 st1 flag_blk regs_blk jit_blk
    (Hex: RelEx flag_blk regs_blk jit_blk st st0)
    (Hf: jit_alu32_thumb_store_template_jit rt rn imm st0 = Some st1),
      RelEx flag_blk regs_blk jit_blk st st1.
Proof.
  intros.
  unfold jit_alu32_thumb_store_template_jit in Hf.
  destruct upd_jitted_list eqn: Heq; [| inversion Hf].
  eapply upd_jitted_list_extension with (st0 := j); eauto.
  eapply upd_jitted_list_extension with (st0 := st0); eauto.
Qed.

Lemma jit_alu32_thumb_upd_save_extension:
  forall r st st0 st1 flag_blk regs_blk jit_blk
    (Hex: RelEx flag_blk regs_blk jit_blk st st0)
    (Hf: jit_alu32_thumb_upd_save r st0 = Some st1),
      RelEx flag_blk regs_blk jit_blk st st1.
Proof.
  intros.
  unfold jit_alu32_thumb_upd_save in Hf.
  destruct is_non_reg.
  - inversion Hf.
    rewrite <- H0.
    assumption.
  - eapply jit_alu32_thumb_store_template_jit_extension; eauto.
Qed.

Lemma jit_alu32_thumb_save_extension:
  forall st st0 st1 flag_blk regs_blk jit_blk
    (Hex: RelEx flag_blk regs_blk jit_blk st st0)
    (Hf: jit_alu32_thumb_save st0 = Some st1),
      RelEx flag_blk regs_blk jit_blk st st1.
Proof.
  intros.
  unfold jit_alu32_thumb_save in Hf.
  repeat (
    destruct jit_alu32_thumb_upd_save eqn: Heq; [
      eapply jit_alu32_thumb_upd_save_extension in Heq; eauto;
      clear Hex; rename Heq into Hex
    | inversion Hf]).
  destruct use_IR11; [| inversion Hf; rewrite <- H0; assumption].
  eapply jit_alu32_thumb_store_template_jit_extension; eauto.
Qed.

Lemma jit_alu32_thumb_load_template_jit_extension:
  forall rt rn imm st st0 st1 flag_blk regs_blk jit_blk
    (Hex: RelEx flag_blk regs_blk jit_blk st st0)
    (Hf: jit_alu32_thumb_load_template_jit rt rn imm st0 = Some st1),
      RelEx flag_blk regs_blk jit_blk st st1.
Proof.
  intros.
  unfold jit_alu32_thumb_load_template_jit in Hf.
  destruct upd_jitted_list eqn: Heq; [| inversion Hf].
  eapply upd_jitted_list_extension in Heq; eauto.
  eapply upd_jitted_list_extension; eauto.
Qed.

Lemma jit_alu32_thumb_upd_load_extension:
  forall r st st0 st1 flag_blk regs_blk jit_blk
    (Hex: RelEx flag_blk regs_blk jit_blk st st0)
    (Hf: jit_alu32_thumb_upd_load r st0 = Some st1),
      RelEx flag_blk regs_blk jit_blk st st1.
Proof.
  intros.
  unfold jit_alu32_thumb_upd_load in Hf.
  destruct is_load_reg.
  - eapply jit_alu32_thumb_load_template_jit_extension; eauto.
  - inversion Hf.
    rewrite <- H0.
    assumption.
Qed.

Lemma jit_alu32_thumb_load_extension:
  forall st st0 st1 flag_blk regs_blk jit_blk
    (Hex: RelEx flag_blk regs_blk jit_blk st st0)
    (Hf: jit_alu32_thumb_load st0 = Some st1),
      RelEx flag_blk regs_blk jit_blk st st1.
Proof.
  intros.
  unfold jit_alu32_thumb_load in Hf.

  destruct no_reg_load; [inversion Hf; rewrite <- H0; assumption | ].
  destruct jit_alu32_thumb_load_template_jit eqn: Heq; [| inversion Hf].
  eapply jit_alu32_thumb_load_template_jit_extension in Heq; eauto;
  clear Hex; rename Heq into Hex.

  repeat (
    destruct jit_alu32_thumb_upd_load eqn: Heq; [
      eapply jit_alu32_thumb_upd_load_extension in Heq; eauto;
      clear Hex; rename Heq into Hex
    | inversion Hf]).
  inversion Hf; rewrite <- H0; assumption.
Qed.


Lemma copy_thumb_list_from_to_aux_extension:
  forall n k st st0 st1 flag_blk regs_blk jit_blk
    (Hk: k >= n)
    (Hex: RelEx flag_blk regs_blk jit_blk st st0)
    (Hf: copy_thumb_list_from_to_aux n (k-n) st0 = Some st1),
      RelEx flag_blk regs_blk jit_blk st st1.
Proof.
  induction n; intros.
  - simpl in Hf.
    inversion Hf.
    rewrite <- H0.
    assumption.
  - simpl in Hf.
    assert (Heq: (S (k - S n)) = k - n) by lia.
    rewrite Heq in Hf; clear Heq.
    destruct eval_thumb_ins; [| inversion Hf].
    destruct upd_jitted_list eqn: Heq; [| inversion Hf].
    eapply upd_jitted_list_extension in Heq; eauto.
    eapply IHn with (k := k) (st0 := j); eauto.
    lia.
Qed.

Lemma copy_thumb_list_from_to_extension:
  forall st st0 st1 flag_blk regs_blk jit_blk
    (Hex: RelEx flag_blk regs_blk jit_blk st st0)
    (Hf: copy_thumb_list_from_to st0 = Some st1),
      RelEx flag_blk regs_blk jit_blk st st1.
Proof.
  intros.
  unfold copy_thumb_list_from_to in Hf.
  eapply copy_thumb_list_from_to_aux_extension with
    (n := thumb_len st0) (k := thumb_len st0); eauto.
  assert (Heq: thumb_len st0 - thumb_len st0 = 0) by lia.
  rewrite Heq.
  assumption.
Qed.

Lemma jit_alu32_thumb_upd_store_extension:
  forall r st st0 st1 flag_blk regs_blk jit_blk
    (Hex: RelEx flag_blk regs_blk jit_blk st st0)
    (Hf: jit_alu32_thumb_upd_store r st0 = Some st1),
      RelEx flag_blk regs_blk jit_blk st st1.
Proof.
  intros.
  unfold jit_alu32_thumb_upd_store in Hf.
  destruct is_store_reg.
  - eapply jit_alu32_thumb_store_template_jit_extension; eauto.
  - inversion Hf.
    rewrite <- H0.
    assumption.
Qed.

Lemma jit_alu32_thumb_store_extension:
  forall st st0 st1 flag_blk regs_blk jit_blk
    (Hex: RelEx flag_blk regs_blk jit_blk st st0)
    (Hf: jit_alu32_thumb_store st0 = Some st1),
      RelEx flag_blk regs_blk jit_blk st st1.
Proof.
  intros.
  unfold jit_alu32_thumb_store in Hf.
  destruct jit_alu32_thumb_load_template_jit eqn: Heq; [| inversion Hf].
  eapply jit_alu32_thumb_load_template_jit_extension in Heq; eauto;
  clear Hex; rename Heq into Hex.

  repeat (
    destruct jit_alu32_thumb_upd_store eqn: Heq; [
      eapply jit_alu32_thumb_upd_store_extension in Heq; eauto;
      clear Hex; rename Heq into Hex
    | inversion Hf]).
  inversion Hf; rewrite <- H0; assumption.
Qed.

Lemma jit_alu32_thumb_upd_reset_extension:
  forall r st st0 st1 flag_blk regs_blk jit_blk
    (Hex: RelEx flag_blk regs_blk jit_blk st st0)
    (Hf: jit_alu32_thumb_upd_reset r st0 = Some st1),
      RelEx flag_blk regs_blk jit_blk st st1.
Proof.
  intros.
  unfold jit_alu32_thumb_upd_reset in Hf.
  destruct is_non_reg.
  - inversion Hf.
    rewrite <- H0.
    assumption.
  - eapply jit_alu32_thumb_load_template_jit_extension; eauto.
Qed.

Lemma jit_alu32_thumb_reset_extension:
  forall st st0 st1 flag_blk regs_blk jit_blk
    (Hex: RelEx flag_blk regs_blk jit_blk st st0)
    (Hf: jit_alu32_thumb_reset st0 = Some st1),
      RelEx flag_blk regs_blk jit_blk st st1.
Proof.
  intros.
  unfold jit_alu32_thumb_reset in Hf.
  destruct use_IR11.
  -
    destruct jit_alu32_thumb_load_template_jit eqn: Heq; [| inversion Hf].
    eapply jit_alu32_thumb_load_template_jit_extension in Heq; eauto;
    clear Hex; rename Heq into Hex.

    repeat (
      destruct jit_alu32_thumb_upd_reset eqn: Heq; [
        eapply jit_alu32_thumb_upd_reset_extension in Heq; eauto;
        clear Hex; rename Heq into Hex
      | inversion Hf]).
    inversion Hf; rewrite <- H0; assumption.
  - repeat (
      destruct jit_alu32_thumb_upd_reset eqn: Heq; [
        eapply jit_alu32_thumb_upd_reset_extension in Heq; eauto;
        clear Hex; rename Heq into Hex
      | inversion Hf]).
    inversion Hf; rewrite <- H0; assumption.
Qed.

Lemma jit_alu32_post_extension:
  forall st st0 st1 flag_blk regs_blk jit_blk
    (Hex: RelEx flag_blk regs_blk jit_blk st st0)
    (Hf: jit_alu32_post st0 = Some st1),
      RelEx flag_blk regs_blk jit_blk st st1.
Proof.
  intros.
  unfold jit_alu32_post in Hf.

  destruct jit_alu32_thumb_load_template_jit eqn: Heq; [| inversion Hf].
  eapply jit_alu32_thumb_load_template_jit_extension in Heq; eauto;
  clear Hex; rename Heq into Hex.

  eapply upd_jitted_list_extension; eauto.
Qed.

Lemma reset_init_jittedthumb_extension:
  forall st st0 st1 flag_blk regs_blk jit_blk
    (Hex: RelEx flag_blk regs_blk jit_blk st st0)
    (Hf: reset_init_jittedthumb st0 = st1),
      RelEx flag_blk regs_blk jit_blk st st1.
Proof.
  intros.
  unfold reset_init_jittedthumb in Hf.
  subst.
  destruct Hex as (Hunchange, Hpc, Hflag, Hregs, Hnum, Hmrs, Hlen, Hins, Hjit, Hperm, Hinvalid).
  split; simpl; assumption.
Qed.

Lemma add_key_value2_extension:
  forall kv st st0 st1 flag_blk regs_blk jit_blk
    (Hex: RelEx flag_blk regs_blk jit_blk st st0)
    (Hf: add_key_value2 kv st0 = st1),
      RelEx flag_blk regs_blk jit_blk st st1.
Proof.
  intros.
  unfold add_key_value2 in Hf.
  subst.
  destruct Hex as (Hunchange, Hpc, Hflag, Hregs, Hnum, Hmrs, Hlen, Hins, Hjit, Hperm, Hinvalid).
  split; simpl; assumption.
Qed.

Lemma jit_alu32_to_thumb_extension:
  forall n st st0 st1 flag_blk regs_blk jit_blk
    (Hex: RelEx flag_blk regs_blk jit_blk st st0)
    (Haux: jit_alu32_to_thumb n st0 = Some st1),
      RelEx flag_blk regs_blk jit_blk st st1.
Proof.
  intros.
  unfold jit_alu32_to_thumb in Haux.

  destruct jit_alu32_to_thumb_pass1 eqn: Hpass; [| inversion Haux].
  assert (Heq := jit_alu32_to_thumb_pass1_extension (n + (jit_ins_len st0)) (jit_ins_len st0)).

  specialize (Heq st (reset_init_jittedthumb st0) j flag_blk regs_blk jit_blk).
  assert (Hge: n + jit_ins_len st0 >= jit_ins_len st0) by lia.
  specialize (Heq Hge); clear Hge.

  assert (Heq': reset_init_jittedthumb st0 = reset_init_jittedthumb st0) by reflexivity.
  assert (Hex':= reset_init_jittedthumb_extension _ _ (reset_init_jittedthumb st0) _ _ _ Hex Heq').

  specialize (Heq Hex'); clear Hex' Heq'.
  assert (Heqt : (n + jit_ins_len st0 - jit_ins_len st0) = n) by lia.
  rewrite Heqt in Heq; clear Heqt.
  specialize (Heq Hpass); clear Hpass.

  clear Hex; rename Heq into Hex.

  eapply add_key_value2_extension with
    (kv := {| KeyValue2.key_pc := n; KeyValue2.arm_ofs := jitted_len j; KeyValue2.alu32_ofs := offset j - 1 |}) in Hex; [ | reflexivity ].

  destruct jit_alu32_pre eqn: Heq; [
    eapply jit_alu32_pre_extension in Heq; eauto;
    clear Hex; rename Heq into Hex
  | inversion Haux].

  destruct jit_alu32_thumb_save eqn: Heq; [
    eapply jit_alu32_thumb_save_extension in Heq; eauto;
    clear Hex; rename Heq into Hex
  | inversion Haux].

  destruct jit_alu32_thumb_load eqn: Heq; [
    eapply jit_alu32_thumb_load_extension in Heq; eauto;
    clear Hex; rename Heq into Hex
  | inversion Haux].

  destruct copy_thumb_list_from_to eqn: Heq; [
    eapply copy_thumb_list_from_to_extension in Heq; eauto;
    clear Hex; rename Heq into Hex
  | inversion Haux].

  destruct jit_alu32_thumb_store eqn: Heq; [
    eapply jit_alu32_thumb_store_extension in Heq; eauto;
    clear Hex; rename Heq into Hex
  | inversion Haux].

  destruct jit_alu32_thumb_reset eqn: Heq; [
    eapply jit_alu32_thumb_reset_extension in Heq; eauto;
    clear Hex; rename Heq into Hex
  | inversion Haux].

  destruct jit_alu32_post eqn: Heq; [
    eapply jit_alu32_post_extension in Heq; eauto;
    clear Hex; rename Heq into Hex
  | inversion Haux].

  inversion Haux.
  subst.
  destruct Hex as (Hunchange, Hpc, Hflag, Hregs, Hnum, Hmrs, Hlen, Hins, Hjit, Hperm, Hinvalid).
  split; simpl; assumption.
Qed.

Lemma jit_alu32_aux_extension:
  forall k n f st st0 st1 flag_blk regs_blk jit_blk, (**r Imporant k and n must be the first two arguments*)
    k >= n ->
    RelEx flag_blk regs_blk jit_blk st st0 ->
    jit_alu32_aux n (k-n) f st0 = Some st1 -> (**r Imporant *)
      RelEx flag_blk regs_blk jit_blk st st1.
Proof.
  induction n.
  - intros.
    simpl in *.
    inversion H1.
    subst.
    assumption.
  - intros f st st0 st1 flag_blk regs_blk jit_blk Hk Hex Haux.
    simpl in *.
    assert (Heq: (S (k - S n)) = k - n) by lia.
    rewrite Heq in *; clear Heq.
    destruct eval_jit_ins; [| inversion Haux].

    destruct ins_is_bpf_alu32.
    + destruct Bool.eqb.
      * destruct jit_alu32_to_thumb eqn: Heq; [| inversion Haux].
        eapply IHn.
        lia.
        eapply jit_alu32_to_thumb_extension; eauto.
        apply Haux.
      * eapply IHn; eauto.
        lia.
    + destruct ins_is_bpf_jump.
      * destruct eval_jit_ins; [| inversion Haux].
        destruct ins_is_bpf_alu32.
        { destruct jit_alu32_to_thumb eqn: Heq; [| inversion Haux].
          eapply IHn.
          lia.
          eapply jit_alu32_to_thumb_extension; eauto.
          apply Haux.
        }
        { eapply IHn; eauto.
          lia.
        }
      * eapply IHn; eauto.
        lia.
Qed.

Lemma reset_init_entry_point_extension:
  forall st st0 st1 flag_blk regs_blk jit_blk
    (Hex: RelEx flag_blk regs_blk jit_blk st st0)
    (Hf: reset_init_entry_point st0 = st1),
      RelEx flag_blk regs_blk jit_blk st st1.
Proof.
  intros.
  unfold reset_init_entry_point in Hf.
  subst.
  destruct Hex as (Hunchange, Hpc, Hflag, Hregs, Hnum, Hmrs, Hlen, Hins, Hjit, Hperm, Hinvalid).
  split; simpl; assumption.
Qed.

Lemma jit_alu32_preserves_extension:
  forall st st0 st1 flag_blk regs_blk jit_blk
    (Hex: RelEx flag_blk regs_blk jit_blk st st0)
    (Hjit: jit_alu32 st0 = Some st1),
      RelEx flag_blk regs_blk jit_blk st st1.
Proof.
  unfold jit_alu32; intros.
  eapply jit_alu32_aux_extension with
    (k := jit_ins_len (reset_init_entry_point st0))
    (n := jit_ins_len (reset_init_entry_point st0))
    (st0 := (reset_init_entry_point st0)); eauto.
  2:{
    assert (Heq: jit_ins_len (reset_init_entry_point st0) - jit_ins_len (reset_init_entry_point st0) = 0) by lia.
    rewrite Heq; clear Heq.
    apply Hjit.
  }
  clear - Hex Hjit.
  eapply reset_init_entry_point_extension; eauto.
Qed.