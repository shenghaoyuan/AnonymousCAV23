(**************************************************************************)
(*  This file is part of CertrBPF,                                        *)
(*  a formally verified rBPF verifier + interpreter + JIT in Coq.         *)
(*                                                                        *)
(*  Copyright (C) 2022 Inria                                              *)
(*                                                                        *)
(*  This program is free software; you can redistribute it and/or modify  *)
(*  it under the terms of the GNU General Public License as published by  *)
(*  the Free Software Foundation; either version 2 of the License, or     *)
(*  (at your option) any later version.                                   *)
(*                                                                        *)
(*  This program is distributed in the hope that it will be useful,       *)
(*  but WITHOUT ANY WARRANTY; without even the implied warranty of        *)
(*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *)
(*  GNU General Public License for more details.                          *)
(*                                                                        *)
(**************************************************************************)

(** The file defines the equivalence relation between the abstract synthesis model (monadicmodel/) and the concrete synthesis model (monadicmodel2/), and also the equivalence theorem *)

From Coq Require Import Logic.FunctionalExtensionality ZArith Lia.
From compcert Require Import Integers Values AST Memory Memdata.

From bpf.comm Require Import Flag Regs State Monad rBPFMonadOp rBPFMemType rBPFValues.

From bpf.monadicmodel Require Import Opcode rBPFInterpreter.
From bpf.monadicmodel2 Require Import ConcreteState rBPFMonadOp2 rBPFInterpreter2.
From bpf.isolation Require Import CheckMem Isolation1.
From bpf.equivalence Require Import Relation3 CheckMem2 equivalence1.


Open Scope Z_scope.

(** * Equivalence Theorem *)

(** The refinement proof should be enough, because we have already proved `None` case is impossible!
 *)

(** The proof idea is simple: from leaf nodes to the root node, so we first prove 56 lemmas: upd_pc, upd_reg, etc... *)

Section Equivalence_Theorem3.
  Context {flag_blk regs_blk st_blk: block}.


(** * Basic Leafs Lemmas *)
(**
We first prove all basic state operations preserve the relation:
- eval/upd_flag
- eval/upd_pc
- eval/upd_reg
- eval/upd_mem
...

see `monadicmodel2/ConcreteState.v`

 *)


  Lemma eval_pc_equiv3:
    forall st0 st1
    (Hbefore: Rel flag_blk regs_blk st_blk st0 st1),
      State.eval_pc st0 = ConcreteState.eval_pc st1.
  Proof.
    intros.
    unfold State.eval_pc, ConcreteState.eval_pc.
    destruct Hbefore; assumption.
  Qed.

  Lemma ins_len_equiv3:
    forall st0 st1
    (Hbefore: Rel flag_blk regs_blk st_blk st0 st1),
      State.ins_len st0 = ConcreteState.ins_len st1.
  Proof.
    intros.
    unfold State.ins_len, ConcreteState.ins_len.
    destruct Hbefore; assumption.
  Qed.

  Lemma upd_pc_equiv3:
    forall st0 st1 p
    (Hbefore: Rel flag_blk regs_blk st_blk st0 st1),
      Rel flag_blk regs_blk st_blk (State.upd_pc p st0) (ConcreteState.upd_pc p st1).
  Proof.
    intros.
    unfold State.upd_pc, ConcreteState.upd_pc.
    destruct Hbefore.
    split; try assumption.
    reflexivity.
  Qed.

  Lemma upd_pc_incr_equiv3:
    forall st0 st1
    (Hbefore: Rel flag_blk regs_blk st_blk st0 st1),
      Rel flag_blk regs_blk st_blk (State.upd_pc_incr st0) (ConcreteState.upd_pc_incr st1).
  Proof.
    intros.
    unfold State.upd_pc_incr, ConcreteState.upd_pc_incr.
    destruct Hbefore.
    split; try assumption.
    rewrite mpc.
    reflexivity.
  Qed.

  Lemma eval_mem_regions_equiv3:
    forall st0 st1
    (Hbefore: Rel flag_blk regs_blk st_blk st0 st1),
      State.eval_mem_regions st0 = ConcreteState.eval_mem_regions st1.
  Proof.
    intros.
    unfold State.eval_mem_regions, ConcreteState.eval_mem_regions.
    destruct Hbefore.
    assumption.
  Qed.

  Lemma eval_mem_equiv3:
    forall st0 st1
    (Hbefore: Rel flag_blk regs_blk st_blk st0 st1),
      Mem.unchanged_on (fun (b : block) (_ : Z) => b <> flag_blk /\ b <> regs_blk /\ b <> st_blk)
      (State.eval_mem st0) (ConcreteState.eval_mem st1).
  Proof.
    intros.
    unfold State.eval_mem, ConcreteState.eval_mem.
    destruct Hbefore.
    assumption.
  Qed.


  Lemma eval_flag_equiv3:
    forall st0 st1
    (Hbefore: Rel flag_blk regs_blk st_blk st0 st1),
      Some (Vint (int_of_flag (State.eval_flag st0))) = ConcreteState.eval_flag st1.
  Proof.
    intros.
    unfold State.eval_flag, ConcreteState.eval_flag.
    destruct Hbefore.
    destruct mflags as (Hflag_blk & mflags).
    rewrite Hflag_blk in *.
    rewrite mflags.
    reflexivity.
  Qed.

  Lemma upd_flag_equiv3:
    forall st0 st1 f st2
    (Hbefore: Rel flag_blk regs_blk st_blk st0 st1)
    (Hflag: ConcreteState.upd_flag (Vint (int_of_flag f)) st1 = Some st2),
      Rel flag_blk regs_blk st_blk (State.upd_flag f st0) st2.
  Proof.
    intros.
    unfold State.upd_flag, ConcreteState.upd_flag in *.
    destruct Hbefore.
    destruct mflags as (Hflag_blk & mflags).
    rewrite Hflag_blk in *.
    destruct mregs as (Hregs_blk & mregs).
    rewrite Hregs_blk in *.
    destruct upd_flag' eqn: Hflag_eq; [| inversion Hflag].
    unfold upd_flag', Mem.storev in Hflag_eq.
    rewrite Hflag_blk in Hflag_eq; simpl in Hflag_eq.

    (**r we prove the following lemma first and then apply `Mem.unchanged_on_trans` *)
      assert (Hupd:
      Mem.unchanged_on
        (fun (b : block) (_ : Z) => b <> flag_blk /\ b <> regs_blk /\ b <> st_blk)
        (bpf_m st1) m). {
        eapply Mem.store_unchanged_on with
          (chunk := Mint32) (b := flag_blk)
          (ofs:= (Ptrofs.unsigned Ptrofs.zero))
          (v:=(Vint (int_of_flag f))) in Hflag_eq; [apply Hflag_eq | ].

        intros.
        intro Hf.
        destruct Hf as (Hf & _).
        apply Hf; reflexivity.
      }

    eapply Mem.unchanged_on_trans in Hupd; eauto.

    destruct mperm as (perm & perm1).
    unfold ptr_range_perm in perm.
    apply Mem.valid_access_freeable_any with (p:=Writable) in perm as perm0.
    eapply Mem.valid_access_store with (v:=(Vint (int_of_flag f))) in perm0.
    destruct perm0 as (m2, Hstore).

    rewrite Hstore in Hflag_eq.
    inversion Hflag_eq.
    subst.

    inversion Hflag.
    clear st2 Hflag H0 Hflag_eq.

    split; simpl; try assumption.
    all:
      unfold flag, State.flag;
      unfold Mem.loadv, Mem.storev in *.
    - (**r mflags *)
      split; [reflexivity | ].
      rewrite Mem.load_store_same with (m1:= (bpf_m st1))(v := (Vint (int_of_flag f))).
      reflexivity.
      assumption.
    - split; [reflexivity | ].
      unfold match_registers in *.
      clear Hupd.
      intros.
      specialize (mregs r).
      destruct mregs as (vl & Hreg).
      exists vl.
      unfold Mem.loadv, Mem.storev in *.
      rewrite Hregs_blk in *.
      simpl.
      unfold Archi.ptr64.
      destruct Hreg as (Hreg & Hvl).

      unfold State.eval_reg in *.
      unfold State.regs_st in *.
      rewrite <- Hvl.
      split; [| reflexivity].

      simpl in Hreg.

      eapply Mem.load_store_other in Hstore.
      rewrite <- Hreg.
      apply Hstore.
      left.
      destruct minvalid as (_ & _ & _ & (Hblk_neq & _) & _).
      intro Hf; apply Hblk_neq.
      rewrite Hf; reflexivity.
    - split.
      + eapply Mem.store_valid_access_1 in Hstore; eauto.
      + intros.
        specialize (perm1 r).
        unfold ptr_range_perm in *.
        simpl.
        simpl in perm1.
        eapply Mem.store_valid_access_1 in Hstore; eauto.
    - clear - Hstore minvalid.
      destruct minvalid as (Hflag_blk & Hregs_blk & Hst_blk & Hblk_neq & minvalid).
      do 4 (split; [assumption | ]).
      intros.
      apply minvalid; auto.
      eapply Mem.store_valid_block_2; eauto.
  Qed.

  Lemma eval_mem_num_equiv3:
    forall st0 st1
    (Hbefore: Rel flag_blk regs_blk st_blk st0 st1),
      State.eval_mem_num st0 = ConcreteState.eval_mem_num st1.
  Proof.
    intros.
    unfold State.eval_mem_num, ConcreteState.eval_mem_num.
    destruct Hbefore.
    assumption.
  Qed.

  Lemma eval_reg_equiv3:
    forall st0 st1 r v
    (Hbefore: Rel flag_blk regs_blk st_blk st0 st1)
    (Hreg: ConcreteState.eval_reg r st1 = Some v),
      State.eval_reg r st0 = v.
  Proof.
    intros.
    unfold State.eval_reg, ConcreteState.eval_reg in *.
    destruct Hbefore.
    unfold match_registers in mregs.
    destruct mregs as (Hregs_blk & mregs).
    rewrite Hregs_blk in *.
    specialize (mregs r).
    destruct mregs as (vl & Hregs & Hvl).
    rewrite Hregs in Hreg.
    inversion Hreg.
    subst v.
    clear Hreg.

    unfold State.eval_reg in Hvl.
    rewrite <- Hvl.
    reflexivity.
  Qed.

  Lemma upd_reg_equiv3:
    forall st0 st1 st2 r v
    (Hreg_vl: exists vl, v = Vlong vl)
    (Hbefore: Rel flag_blk regs_blk st_blk st0 st1)
    (Hreg: ConcreteState.upd_reg r v st1 = Some st2),
      Rel flag_blk regs_blk st_blk (State.upd_reg r v st0) st2.
  Proof.
    intros.
    unfold State.upd_reg, ConcreteState.upd_reg.
    destruct Hbefore.

    destruct mflags as (Hflag_blk & mflags).
    rewrite Hflag_blk in *.
    destruct mregs as (Hregs_blk & mregs).
    rewrite Hregs_blk in *.

    (** destruct permission *)
    destruct mperm as (mperm0 & mperm1).
    unfold ptr_range_perm in mperm0, mperm1.
    specialize (mperm1 r) as perm1.
    unfold Val.add in perm1.
    unfold Archi.ptr64 in perm1.
    apply Mem.valid_access_freeable_any with (p:=Writable) in perm1.

    eapply Mem.valid_access_store with (v:=v) in perm1 as Hstore.
    destruct Hstore as (m2 & Hstore).

    unfold ConcreteState.upd_reg in Hreg.
    destruct upd_reg' eqn: Hreg_eq; inversion Hreg.
    subst st2.
    clear Hreg.
    unfold upd_reg', Mem.storev in Hreg_eq.
    rewrite Hregs_blk in Hreg_eq.
    unfold Val.add in Hreg_eq.
    unfold Archi.ptr64 in Hreg_eq.
    rewrite Hstore in Hreg_eq.
    inversion Hreg_eq.
    subst m2.
    clear Hreg_eq.

    split; try assumption; simpl.
    - (**r Mem.unchanged_on *)
      (**r first prove the following lemma and then use `unchanged_on_trans` *)
      assert (Hupd: Mem.unchanged_on (fun (b1 : block) (_ : Z) => b1 <> flag_blk /\ b1 <> regs_blk /\ b1 <> st_blk) (bpf_m st1) m). {
        clear - munchange Hstore.
        eapply Mem.store_unchanged_on; [apply Hstore | ].

        intros.
        intro Hf.
        destruct Hf as (_ & Hblks & _).
        apply Hblks; reflexivity.
      }
      eapply Mem.unchanged_on_trans in Hupd; eauto.

    - (**r mflags *)
      split; [assumption | ].
      rewrite <- mflags.
      unfold Mem.loadv.
      rewrite Hflag_blk.
      eapply Mem.load_store_other; eauto.
      left.
      clear - minvalid.
      destruct minvalid as (_ & _ & _ & (Hblk & _) & _).
      assumption.

    - (**r mregs *)
      split; [assumption | ].
      unfold match_registers in *.
      intros.
      simpl.

      specialize (mregs r0).
      destruct mregs as (vl0 & Hload & Hvl).
      unfold Mem.loadv in *.
      rewrite Hregs_blk in *.
      unfold Val.add, Archi.ptr64 in *.

      destruct Hreg_vl as (vl & Hvl_eq).
      subst v.

      destruct (reg_eq r r0) as [Hreg_eq | Hreg_neq].
      {
        (** case: r = r0 *)
        subst r0.
        exists vl.
        simpl in Hload.
        split.
        + eapply Mem.load_store_same in Hstore; eauto.
        + unfold State.eval_reg.
          simpl.
          rewrite eval_upd_reg_same.
          reflexivity.
      }

      (**r r <> r0 *)
      exists vl0.
      simpl in Hload.
      split.
      + rewrite <- Hload.

        eapply Mem.load_store_other; eauto.
        right.
        clear - Hreg_neq.
        repeat rewrite Ptrofs.add_zero_l.
        destruct r; destruct r0; simpl;
          unfold Ptrofs.add;
          repeat match goal with
          | |- context[Ptrofs.unsigned (Ptrofs.of_int (Int.repr ?X))] =>
              change (Ptrofs.unsigned (Ptrofs.of_int (Int.repr X))) with X
          | |- context[Ptrofs.unsigned (Ptrofs.repr ?X)] =>
              change (Ptrofs.unsigned (Ptrofs.repr X)) with X
          end; simpl; try lia.
        all: exfalso; apply Hreg_neq; reflexivity.
      + unfold State.eval_reg in *.
        simpl.
        rewrite eval_upd_reg_other.
        assumption.
        intuition.
    - (**r mperm *)
      unfold ptr_range_perm.
      rewrite Hflag_blk, Hregs_blk in *.
      simpl.
      simpl in mperm1.
      split.
      + eapply Mem.store_valid_access_1; eauto.
      + intros.
        specialize (mperm1 r0).
        eapply Mem.store_valid_access_1; eauto.
    - (**r minvalid *)
      clear - Hstore minvalid.
      destruct minvalid as (Hflag_blk & Hregs_blk & Hst_blk & Hlbk_neq & minvalid).
      do 4 (split;[assumption |]).
      intros.
      apply minvalid; auto.
      eapply Mem.store_valid_block_2; eauto.
  Qed.

(** Regarding the load_mem, we must make sure the pointer is not in the block `state_blk` *)
  Lemma load_mem_equiv3:
    forall st0 st1 ck ptr
    (Hptr: exists b ofs, ptr = Vptr b ofs /\ b <> flag_blk /\ b <> regs_blk /\ b <> st_blk)
    (Hbefore: Rel flag_blk regs_blk st_blk st0 st1),
      State.load_mem ck ptr st0 = ConcreteState.load_mem ck ptr st1.
  Proof.
    intros.
    unfold State.load_mem, ConcreteState.load_mem, Mem.loadv.
    destruct Hptr as (b & ofs & Hptr & Hptr_neq).
    subst ptr.
    destruct Hbefore.

    destruct mflags as (Hflag_blk & mflags).
    rewrite Hflag_blk in *.
    destruct mregs as (Hregs_blk & mregs).
    rewrite Hregs_blk in *.

    destruct ck; try reflexivity.
    - (**r ck =  Mint8unsigned *)
      destruct Mem.load eqn: Hload.
      + eapply Mem.load_unchanged_on in Hload; eauto.
        rewrite Hload.
        reflexivity.
      + destruct (Mem.load Mint8unsigned (bpf_m st1) b (Ptrofs.unsigned ofs)) eqn: Hload'.
        *
          eapply Mem.load_unchanged_on_1 with (chunk := Mint8unsigned) (ofs := Ptrofs.unsigned ofs) in munchange; eauto.
          rewrite Hload' in munchange.
          rewrite Hload in munchange.
          inversion munchange.

          eapply Mem.load_valid_access in Hload'; eauto.
          eapply Mem.valid_access_implies with (p2 := Nonempty) in Hload'; eauto.
          eapply Mem.valid_access_valid_block in Hload'.
          destruct minvalid as (_ & _ & _ & _ & minvalid).
          specialize (minvalid b Hptr_neq Hload').
          assumption.
          constructor.
        * reflexivity.
    - (**r ck =  Mint16unsigned *)
      destruct Mem.load eqn: Hload.
      + eapply Mem.load_unchanged_on in Hload; eauto.
        rewrite Hload.
        reflexivity.
      + destruct (Mem.load Mint16unsigned (bpf_m st1) b (Ptrofs.unsigned ofs)) eqn: Hload'.
        *
          eapply Mem.load_unchanged_on_1 with (chunk := Mint16unsigned) (ofs := Ptrofs.unsigned ofs) in munchange; eauto.
          rewrite Hload' in munchange.
          rewrite Hload in munchange.
          inversion munchange.

          eapply Mem.load_valid_access in Hload'; eauto.
          eapply Mem.valid_access_implies with (p2 := Nonempty) in Hload'; eauto.
          eapply Mem.valid_access_valid_block in Hload'.
          destruct minvalid as (_ & _ & _ & _ & minvalid).
          specialize (minvalid b Hptr_neq Hload').
          assumption.
          constructor.
        * reflexivity.
    - (**r ck =  Mint32 *)
      destruct Mem.load eqn: Hload.
      + eapply Mem.load_unchanged_on in Hload; eauto.
        rewrite Hload.
        reflexivity.
      + destruct (Mem.load Mint32 (bpf_m st1) b (Ptrofs.unsigned ofs)) eqn: Hload'.
        *
          eapply Mem.load_unchanged_on_1 with (chunk := Mint32) (ofs := Ptrofs.unsigned ofs) in munchange; eauto.
          rewrite Hload' in munchange.
          rewrite Hload in munchange.
          inversion munchange.

          eapply Mem.load_valid_access in Hload'; eauto.
          eapply Mem.valid_access_implies with (p2 := Nonempty) in Hload'; eauto.
          eapply Mem.valid_access_valid_block in Hload'.
          destruct minvalid as (_ & _ & _ & _ & minvalid).
          specialize (minvalid b Hptr_neq Hload').
          assumption.
          constructor.
        * reflexivity.
    - (**r ck =  Mint64 *)
      destruct Mem.load eqn: Hload.
      + eapply Mem.load_unchanged_on in Hload; eauto.
      + destruct (Mem.load Mint64 (bpf_m st1) b (Ptrofs.unsigned ofs)) eqn: Hload'.
        *
          eapply Mem.load_unchanged_on_1 with (chunk := Mint64) (ofs := Ptrofs.unsigned ofs) in munchange; eauto.
          rewrite Hload' in munchange.
          rewrite Hload in munchange.
          inversion munchange.

          eapply Mem.load_valid_access in Hload'; eauto.
          eapply Mem.valid_access_implies with (p2 := Nonempty) in Hload'; eauto.
          eapply Mem.valid_access_valid_block in Hload'.
          destruct minvalid as (_ & _ & _ & _ & minvalid).
          specialize (minvalid b Hptr_neq Hload').
          assumption.
          constructor.
        * reflexivity.
  Qed.

  Lemma store_equiv3:
    forall st0 st1 b ofs ck v m0
    (Hbefore: Rel flag_blk regs_blk st_blk st0 st1)
    (Hstore: Mem.store ck (State.bpf_m st0) b ofs v = Some m0),
      exists m1,
        Mem.store ck (ConcreteState.bpf_m st1) b ofs v = Some m1 /\
        Rel flag_blk regs_blk st_blk (State.upd_mem m0 st0) (ConcreteState.upd_mem m1 st1).
  Proof.
    intros.

    assert (Hptr: b <> flag_blk /\ b <> regs_blk /\ b <> st_blk). {
      destruct Hbefore.
      unfold Mem.store in Hstore.
      destruct Mem.valid_access_dec eqn: Hvalid; inversion Hstore.
      clear - minvalid v0.
      destruct minvalid as (Hflag_blk & Hregs_blk & Hst_blk & minvalid & _).
      split.
      - intro Hf.
        subst b.
        apply Hflag_blk.
        eapply Mem.valid_access_valid_block.
        eapply Mem.valid_access_implies; eauto.
        constructor.
      - split.
        + intro Hf.
          subst b.
          apply Hregs_blk.
          eapply Mem.valid_access_valid_block.
          eapply Mem.valid_access_implies; eauto.
          constructor.
        + intro Hf.
          subst b.
          apply Hst_blk.
          eapply Mem.valid_access_valid_block.
          eapply Mem.valid_access_implies; eauto.
          constructor.
    }

    destruct Hbefore.

    destruct mflags as (Hflag_blk & mflags).
    rewrite Hflag_blk in *.
    destruct mregs as (Hregs_blk & mregs).
    rewrite Hregs_blk in *.


    (**r We firstly prove exists such a memory m1 *)

    assert (Hvalid_blk': Mem.valid_block (State.bpf_m st0) b). {
      apply Mem.store_valid_access_3 in Hstore.
      assert (Hstore' : Mem.valid_access (State.bpf_m st0) ck b ofs Nonempty). {
        eapply Mem.valid_access_implies; eauto.
        constructor.
      }
      eapply Mem.valid_access_valid_block in Hstore'; eauto.
    }
    assert (Hvalid_blk: Mem.valid_block (ConcreteState.bpf_m st1) b). {
      eapply Mem.valid_block_unchanged_on; eauto.
    }

    assert (Hvalid_access: Mem.valid_access (ConcreteState.bpf_m st1) ck b ofs Writable). {
      destruct minvalid as ( _ & _ & _ & _ & Hvalid).
      specialize (Hvalid b Hptr Hvalid_blk).
      destruct munchange.

      eapply Mem.store_valid_access_3 in Hstore as Hvalid_acc; eauto.
      eapply Mem.valid_access_store with (v:= v) in Hvalid_acc as Hres; eauto.

      unfold Mem.valid_access in *.
      destruct Hvalid_acc as (Hvalid_acc & Haligh).
      split; [| assumption].
      unfold Mem.range_perm in *.
      intros.
      specialize (Hvalid_acc ofs0 H).
      specialize (unchanged_on_perm b ofs0 Cur Writable Hptr Hvalid).
      apply unchanged_on_perm; assumption.
    }
    eapply Mem.valid_access_store with (v:= v) in Hvalid_access; eauto.
    destruct Hvalid_access as (m1 & Hstore_m1).
    exists m1.
    split; [assumption |].

    (**r Then we prove the relation *)

    split.
    - (**r munchange *)
      destruct munchange.
      unfold State.upd_mem, upd_mem; simpl.
      split.
      + eapply Mem.nextblock_store in Hstore_m1; auto.
        rewrite Hstore_m1.
        eapply Mem.nextblock_store in Hstore; auto.
        rewrite Hstore.
        assumption.
      + intros.
        eapply Mem.store_valid_block_2 in Hstore as Hvalid_block; eauto.
        specialize (unchanged_on_perm _ ofs0 k p H Hvalid_block).
        eapply store_perm_iff with (b0:=b0) (ofs0:=ofs0) (k:=k) (p:=p) in Hstore as Hperm_1; eauto.
        eapply store_perm_iff with (b0:=b0) (ofs0:=ofs0) (k:=k) (p:=p) in Hstore_m1 as Hperm_2; eauto.
        intuition.
      + intros.
        eapply Mem.perm_store_2 in Hstore as Hperm; eauto.
        specialize (unchanged_on_contents _ ofs0 H Hperm).
        clear unchanged_on_nextblock unchanged_on_perm H0 Hperm.

        destruct (b0 =? b)%positive eqn: Hblk_eq; [rewrite Pos.eqb_eq in Hblk_eq | rewrite Pos.eqb_neq in Hblk_eq].
        * (**r b0 = b *)
          subst.
          destruct (ofs0 =? ofs)%Z eqn: Hofs_eq; [rewrite Z.eqb_eq in Hofs_eq | rewrite Z.eqb_neq in Hofs_eq].
          ** (**r ofs0 = ofs *)
            subst.
            eapply store_store_same_block; eauto.
          ** (**r ofs0 <> ofs *)
            rewrite Z.lt_gt_cases in Hofs_eq.
            destruct Hofs_eq as [Hofs_le | Hofs_ge].
            { (**r ofs0 < ofs*)
              eapply store_store_other_block_same; eauto.
            }
            { (**r ofs < ofs0 *)
              destruct (ofs + size_chunk ck <=? ofs0)%Z eqn: Hge; [rewrite Z.leb_le in Hge | rewrite Z.leb_gt in Hge].
              { (**r ofs + size_chunk chunk <= ofs0 *)
                eapply store_store_other_block_same; eauto.
              }
              { (**r ofs < ofs0 < ofs + size_chunk chunk *)
                eapply store_store_same_block_other; eauto.
              }
            }
        * (**r b0 <> b *)
          eapply store_store_other_block_same; eauto.
    - (**r mpc *)
      unfold State.pc_loc, State.upd_mem, pc_loc, upd_mem.
      assumption.
    - (**r mflags *)
      split; [assumption | ].
      unfold Mem.loadv in *.
      unfold State.flag, State.upd_mem, upd_mem, bpf_m; simpl.
      rewrite Hflag_blk.
      eapply Mem.load_store_other in Hstore_m1; eauto.
      rewrite Hstore_m1.
      assumption.

      left.
      intuition.

    - (**r mregs *)
      split; [assumption | ].
      unfold match_registers in *.
      intros.
      specialize (mregs r).
      destruct mregs as (vl & Hload & Hvl_eq).
      exists vl.
      unfold Mem.loadv in *.
      unfold regs_st, upd_mem.
      rewrite Hregs_blk in *.
      simpl.
      simpl in Hload.
      unfold State.eval_reg in *.
      unfold State.upd_mem; simpl.
      split; [| assumption].
      eapply Mem.load_store_other in Hstore_m1; eauto.
      rewrite Hstore_m1.
      assumption.

      left. intuition.

    - (**r mmrs_num *)
      unfold State.upd_mem, upd_mem; simpl.
      assumption.
    - (**r mbpf_mrs *)
      unfold State.upd_mem, upd_mem; simpl.
      assumption.
    - (**r mins_len *)
      unfold State.upd_mem, upd_mem; simpl.
      assumption.
    - (**r mins *)
      unfold State.upd_mem, upd_mem; simpl.
      assumption.
    - (**r mperm *)
      unfold ptr_range_perm in *.
      unfold upd_mem; simpl.
      rewrite Hflag_blk.
      simpl in mperm.
      destruct mperm as (Hvalid_access0 & Hvalid_access1).
      split.
      + eapply Mem.store_valid_access_1; eauto.
      + intros.
        rewrite Hregs_blk; simpl.
        specialize (Hvalid_access1 r).
        eapply Mem.store_valid_access_1; eauto.
    - (**r minvalid *)
      clear - minvalid Hstore Hstore_m1.
      destruct minvalid as (Hflag_blk & Hregs_blk & Hst_blk & Hblk_neq & minvalid).
      unfold State.upd_mem, upd_mem; simpl.
      split;[
        intro Hf;
        apply Hflag_blk;
        eapply Mem.store_valid_block_2; eauto
        | ].
      split;[
        intro Hf;
        apply Hregs_blk;
        eapply Mem.store_valid_block_2; eauto
        | ].
      split;[
        intro Hf;
        apply Hst_blk;
        eapply Mem.store_valid_block_2; eauto
        | ].
      split; [assumption |].

      intros.
      eapply Mem.store_valid_block_2 in Hstore_m1; eauto.
      specialize (minvalid b0 H Hstore_m1).
      eapply Mem.store_valid_block_1; eauto.
  Qed.


  Lemma store_mem_imm_None_equiv3:
    forall st0 st1 ptr ck v
    (Hptr: exists b ofs, ptr = Vptr b ofs /\ b <> flag_blk /\ b <> regs_blk /\ b <> st_blk)
    (Hbefore: Rel flag_blk regs_blk st_blk st0 st1),
      State.store_mem_imm ptr ck v st0 = None <->
      ConcreteState.store_mem_imm ptr ck v st1 = None.
  Proof.
    intros.
    unfold State.store_mem_imm, ConcreteState.store_mem_imm.
    unfold Mem.storev.
    assert (Hbefore' := Hbefore).
    destruct Hbefore.

    destruct mflags as (Hflag_blk & mflags).
    rewrite Hflag_blk in *.
    destruct mregs as (Hregs_blk & mregs).
    rewrite Hregs_blk in *.

    destruct minvalid as (Hinvalid_flag & Hinvalid_regs & Hinvalid_st & Hinvalid_neq & minvalid).
    destruct Hptr as (b0 & ofs & Hptr & Hptr_neq).
    subst ptr.
    specialize (minvalid b0 Hptr_neq).

    eapply unchanged_on_store_None with (chunk := ck) (ofs := Ptrofs.unsigned ofs) (v := rBPFAST.vint_to_vint_or_vlong ck v) in minvalid as HNone; eauto.

    destruct ck.
    6:{
      destruct Mem.store eqn: Hstore.
      eapply store_equiv3 in Hstore; eauto.
      destruct Hstore as (m1 & Hstore & HR).
      rewrite Hstore.
      split; intro HF; inversion HF.
      destruct HNone.
      assert (HNone: Mem.store Mint64 (bpf_m st1) b0 (Ptrofs.unsigned ofs)
      (rBPFAST.vint_to_vint_or_vlong Mint64 v) = None). {
        apply H.
        reflexivity.
      }
      rewrite HNone.
      intuition.
    }
    5:{
      destruct Mem.store eqn: Hstore.
      eapply store_equiv3 in Hstore; eauto.
      destruct Hstore as (m1 & Hstore & HR).
      rewrite Hstore.
      split; intro HF; inversion HF.
      destruct HNone.
      assert (HNone: Mem.store Mint32 (bpf_m st1) b0 (Ptrofs.unsigned ofs)
      (rBPFAST.vint_to_vint_or_vlong Mint32 v) = None). {
        apply H.
        reflexivity.
      }
      rewrite HNone.
      intuition.
    }
    4:{
      destruct Mem.store eqn: Hstore.
      eapply store_equiv3 in Hstore; eauto.
      destruct Hstore as (m1 & Hstore & HR).
      rewrite Hstore.
      split; intro HF; inversion HF.
      destruct HNone.
      assert (HNone: Mem.store Mint16unsigned (bpf_m st1) b0 (Ptrofs.unsigned ofs)
      (rBPFAST.vint_to_vint_or_vlong Mint16unsigned v) = None). {
        apply H.
        reflexivity.
      }
      rewrite HNone.
      intuition.
    }
    2:{
      destruct Mem.store eqn: Hstore.
      eapply store_equiv3 in Hstore; eauto.
      destruct Hstore as (m1 & Hstore & HR).
      rewrite Hstore.
      split; intro HF; inversion HF.
      destruct HNone.
      assert (HNone: Mem.store Mint8unsigned (bpf_m st1) b0 (Ptrofs.unsigned ofs)
      (rBPFAST.vint_to_vint_or_vlong Mint8unsigned v) = None). {
        apply H.
        reflexivity.
      }
      rewrite HNone.
      intuition.
    }
    all: intuition.
  Qed.

  Lemma eval_ins_len_equiv3:
    forall st0 st1
    (Hbefore: Rel flag_blk regs_blk st_blk st0 st1),
      State.eval_ins_len st0 = ConcreteState.eval_ins_len st1.
  Proof.
    intros.
    unfold State.eval_ins_len, ConcreteState.eval_ins_len.
    destruct Hbefore.
    rewrite mins_len.
    reflexivity.
  Qed.

  Lemma eval_ins_equiv3:
    forall st0 st1 id
    (Hbefore: Rel flag_blk regs_blk st_blk st0 st1),
      State.eval_ins id st0 = ConcreteState.eval_ins id st1.
  Proof.
    intros.
    unfold State.eval_ins, ConcreteState.eval_ins.
    destruct Hbefore.
    rewrite mins.
    reflexivity.
  Qed.

(** * Other Leafs Lemmas *)
(**
We then prove the rest leafs in the `/monadicmodel2/rBPFMonadOp2.v`

- cmp_ptr32_nullM
- int64_to_dst_reg
- int64_to_src_reg
- get_mem_region
- ...
 *)

(** Starting here, we focus on proving the refinement theorem  
  *)

(** * Read-Only Functions *)
(**
We should all read-only functions never change the state.
 *)

  Lemma upd_flag_none:
    forall st0 st1 st0' flag_blk regs_blk st_blk f
      (Hbefore : Rel flag_blk regs_blk st_blk st0 st1)
      (Hupd : ConcreteState.upd_flag (Vint (int_of_flag f)) st1 = None)
      (Hst : State.upd_flag BPF_ILLEGAL_INSTRUCTION st0 = st0'),
        exists st1' : state,
          None = Some (tt, st1') /\
          Rel flag_blk regs_blk st_blk (State.upd_flag f st0) st1'.
  Proof.
    intros.
    destruct Hbefore as (Hunchanged, Hpc,
      (Hflag_eq, Hflag),
      (Hreg_eq, Hregs), Hnum, Hmrs, Hlen, Hins, Hperm, Hinvalid).
    unfold ConcreteState.upd_flag, upd_flag', Mem.storev in *.

    destruct Hperm as (Hperm & Hperm0).
    unfold ptr_range_perm in *.
    rewrite Hflag_eq in *.

    eapply Mem.valid_access_freeable_any with (p := Writable) in Hperm as Hstore.
    eapply Mem.valid_access_store with
      (v := (Vint (int_of_flag f))) in Hstore.
    destruct Hstore as (m2 & Hstore).
    rewrite Hstore in Hupd.
    inversion Hupd.
  Qed.

  Lemma upd_reg_none:
    forall st0 st1 st0' flag_blk regs_blk st_blk r i
      (Hbefore : Rel flag_blk regs_blk st_blk st0 st1)
      (Hupd : State.upd_reg r (Vlong i) st0 = st0')
      (Hst : ConcreteState.upd_reg r (Vlong i) st1 = None),
        exists st1' : state,
          None = Some (tt, st1') /\
          Rel flag_blk regs_blk st_blk (State.upd_reg r (Vlong i) st0) st1'.
  Proof.
    intros.
    destruct Hbefore as (Hunchanged, Hpc,
      (Hflag_eq, Hflag),
      (Hreg_eq, Hregs), Hnum, Hmrs, Hlen, Hins, Hperm, Hinvalid).
    unfold ConcreteState.upd_reg, upd_reg', Mem.storev in *.

    destruct Hperm as (_ & Hperm).
    specialize (Hperm r).
    unfold ptr_range_perm in Hperm.
    rewrite Hreg_eq in *.
    unfold Val.add, Archi.ptr64 in *.

    eapply Mem.valid_access_freeable_any with (p := Writable) in Hperm as Hstore.
    eapply Mem.valid_access_store in Hstore.
    destruct Hstore as (m2 & Hstore).
    rewrite Hstore in Hst.
    inversion Hst.
  Qed.

  Lemma step_opcode_alu64_ref:
    forall d s r op st0 st1 st0'
      (Hbefore: Rel flag_blk regs_blk st_blk st0 st1)
      (Hst: rBPFInterpreter.step_opcode_alu64 d s r op st0 = Some (tt, st0')),
        exists st1',
          rBPFInterpreter2.step_opcode_alu64 d s r op st1 = Some (tt, st1') /\
          Rel flag_blk regs_blk st_blk st0' st1'.
  Proof.
    unfold rBPFInterpreter.step_opcode_alu64, rBPFInterpreter2.step_opcode_alu64, bindM.
    unfold rBPFInterpreter.get_opcode_alu64, rBPFInterpreter2.get_opcode_alu64, bindM, returnM.
    intros.

Ltac match_match_destruct_inversion :=
  let HX := fresh "HX" in
  match goal with
  | |- context [match match ?X with | _ => _ end with | _ => _ end] =>
    destruct X eqn: HX
  | |- context [match ?X with | _ => _ end] =>
    destruct X eqn: HX
  end.

Ltac unfold_H0H1_destruct_apply_H Hst H0 H1 H :=
  unfold H0, H1 in *;
  match_match_destruct_inversion; inversion Hst;
  try match_match_destruct_inversion;
  [
    eexists; split;
    [ reflexivity |
      eapply H; eauto] |
  ].

Ltac if_unfold_H0H1_destruct_apply_H2 Hst H0 H1 H2 H3 H4 H5 :=
  match goal with
  | |- context [if ?X then _ else _] =>
    destruct X;
    [ unfold_H0H1_destruct_apply_H Hst H0 H1 H2 |
      unfold_H0H1_destruct_apply_H Hst H3 H4 H5 ]
  end.

    destruct byte_to_opcode_alu64; unfold rBPFInterpreter.reg64_to_reg32, reg64_to_reg32, returnM in *.
    14:{
      unfold_H0H1_destruct_apply_H Hst
        rBPFMonadOp.upd_flag upd_flag upd_flag_equiv3.
      eapply upd_flag_none; eauto.
    }

    all: try if_unfold_H0H1_destruct_apply_H2 Hst
      rBPFMonadOp.upd_reg  upd_reg  upd_reg_equiv3
      rBPFMonadOp.upd_flag upd_flag upd_flag_equiv3.
    all: try
      unfold_H0H1_destruct_apply_H Hst
        rBPFMonadOp.upd_reg upd_reg upd_reg_equiv3.
    all: try (eapply upd_reg_none; eauto).
    all: eapply upd_flag_none; eauto.
  Qed.

  Lemma step_opcode_alu32_ref:
    forall d s r op st0 st1 st0'
      (Hbefore: Rel flag_blk regs_blk st_blk st0 st1)
      (Hst: rBPFInterpreter.step_opcode_alu32 d s r op st0 = Some (tt, st0')),
        exists st1',
          rBPFInterpreter2.step_opcode_alu32 d s r op st1 = Some (tt, st1') /\
          Rel flag_blk regs_blk st_blk st0' st1'.
  Proof.
    unfold rBPFInterpreter.step_opcode_alu32, rBPFInterpreter2.step_opcode_alu32, bindM.
    unfold rBPFInterpreter.get_opcode_alu32, rBPFInterpreter2.get_opcode_alu32, bindM, returnM.
    intros.

    destruct byte_to_opcode_alu32; unfold rBPFInterpreter.reg64_to_reg32, reg64_to_reg32, returnM in *.
    14:{
      unfold_H0H1_destruct_apply_H Hst
        rBPFMonadOp.upd_flag upd_flag upd_flag_equiv3.

      eapply upd_flag_none; eauto.
    }

    all: try if_unfold_H0H1_destruct_apply_H2 Hst
      rBPFMonadOp.upd_reg  upd_reg  upd_reg_equiv3
      rBPFMonadOp.upd_flag upd_flag upd_flag_equiv3.
    all: try
      unfold_H0H1_destruct_apply_H Hst
        rBPFMonadOp.upd_reg upd_reg upd_reg_equiv3.
    all: try (eapply upd_reg_none; eauto).
    all: eapply upd_flag_none; eauto.
  Qed.


Axiom lemma_bpf_get_call_ref :
  forall i st0 st1
    (Hbefore: Rel flag_blk regs_blk st_blk st0 st1),
    exists ptr,
      rBPFMonadOp._bpf_get_call (Vint i) st0 = Some (ptr, st0) /\
      rBPFMonadOp2._bpf_get_call (Vint i) st1 = Some (ptr, st1) /\ (**r show: same input i, same output, and state is never modified *)
      ( ptr = Vnullptr \/
        (exists b ofs, ptr = Vptr b ofs /\
          ((Mem.valid_pointer (State.bpf_m st0) b (Ptrofs.unsigned ofs)
          || Mem.valid_pointer (State.bpf_m st0) b (Ptrofs.unsigned ofs - 1)) = true)%bool /\
          ((Mem.valid_pointer (bpf_m st1) b (Ptrofs.unsigned ofs)
          || Mem.valid_pointer (bpf_m st1) b (Ptrofs.unsigned ofs - 1)) = true)%bool)).

Axiom lemma_exec_function_ref :
  forall b ofs st0 st1
    (Hbefore: Rel flag_blk regs_blk st_blk st0 st1),
    exists v st0' st1',
      rBPFMonadOp.exec_function (Vptr b ofs) st0 = Some (Vint v, st0') /\
      rBPFMonadOp2.exec_function (Vptr b ofs) st1 = Some (Vint v, st1') /\
      Rel flag_blk regs_blk st_blk st0' st1'  /\ (**r assume: same input, same output; the new states preserve the simulation relation *)
      cmp_ptr32_null (State.eval_mem st0) (Vptr b ofs) = Some false /\
      cmp_ptr32_null (ConcreteState.eval_mem st1) (Vptr b ofs) = Some false.


  Lemma step_opcode_branch_ref:
    forall d s pc ofs op st0 st1 st0'
      (Hbefore: Rel flag_blk regs_blk st_blk st0 st1)
      (Hs_vl: exists vl, s = Vlong vl)
      (Hst: rBPFInterpreter.step_opcode_branch d s pc ofs op st0 = Some (tt, st0')),
        exists st1',
          rBPFInterpreter2.step_opcode_branch d s pc ofs op st1 = Some (tt, st1') /\
          Rel flag_blk regs_blk st_blk st0' st1'.
  Proof.
    unfold rBPFInterpreter.step_opcode_branch, rBPFInterpreter2.step_opcode_branch, bindM.
    unfold rBPFInterpreter.get_opcode_branch, rBPFInterpreter2.get_opcode_branch, bindM, returnM.
    intros.

    destruct Hs_vl as (vl & Hvl_eq). subst.

    destruct byte_to_opcode_branch; unfold rBPFInterpreter.reg64_to_reg32, reg64_to_reg32, returnM in *.
    15:{
      unfold_H0H1_destruct_apply_H Hst
      rBPFMonadOp.upd_flag upd_flag upd_flag_equiv3.

      eapply upd_flag_none; eauto.
    }

    all: try match goal with
      | |- context [if ?X then _ else _] =>
        destruct X;
        [ unfold rBPFMonadOp.upd_pc, upd_pc in *;
          erewrite ins_len_equiv3 in Hst; eauto;
          match goal with
          | |- context [if ?X then _ else _] =>
            destruct X; inversion Hst
          end;
          eexists; split;
          [ reflexivity |
            eapply upd_pc_equiv3; eauto] |
          inversion Hst; subst; eexists; split;
          [ reflexivity |
            assumption]]
      end.

    - match goal with
      | |- context [if ?X then _ else _] =>
        destruct X;
        [ unfold rBPFMonadOp.upd_pc, upd_pc in *;
          erewrite ins_len_equiv3 in Hst; eauto;
          match goal with
          | |- context [if ?X then _ else _] =>
            destruct X; inversion Hst
          end;
          eexists; split;
          [ reflexivity |
            eapply upd_pc_equiv3; eauto]|
            unfold_H0H1_destruct_apply_H Hst
            rBPFMonadOp.upd_flag upd_flag upd_flag_equiv3 ]
      end.

      eapply upd_flag_none; eauto.
    -
      assert (Hcall := lemma_bpf_get_call_ref).
      assert (Hexec := lemma_exec_function_ref).
      unfold rBPFValues.val_intsoflongu in *.
      specialize (Hcall (Int.repr (Int64.unsigned vl)) st0 st1 Hbefore).

      destruct Hcall as (ptr & Hcall0 & Hcall1 & Hcall0_ptr).

      match goal with
      | |- context [if ?X then _ else _] =>
        destruct X
      end.
      + rewrite Hcall0, Hcall1 in *.
        unfold rBPFMonadOp.cmp_ptr32_nullM, cmp_ptr32_nullM in *.
        unfold rBPFValues.cmp_ptr32_null in *.

        destruct Hcall0_ptr as [Hnull | Hptr].
        * (**r ptr = Vnullptr *)
          subst ptr.
          simpl in *.
          change (Int.eq Int.zero Int.zero) with true in *.
          simpl in *.

          unfold_H0H1_destruct_apply_H Hst
          rBPFMonadOp.upd_flag upd_flag upd_flag_equiv3.

          eapply upd_flag_none; eauto.
        * (**r ptr = Vptr b ofs *)
          destruct Hptr as (b & ofs0 & Hptr & Hvalid0 & Hvalid1).
          subst ptr.
          unfold Val.cmpu_bool, Vnullptr in *.
          simpl in *.
          change (Int.eq Int.zero Int.zero) with true in *.
          simpl in *.
          unfold State.eval_mem, ConcreteState.eval_mem in *.
          rewrite Hvalid0, Hvalid1 in *.

          specialize (Hexec b ofs0 st0 st1 Hbefore).
          clear Hvalid0 Hvalid1.
          destruct Hexec as (v & st2 & st3 & Hexec0 & Hexec1 & Hrel & Hvalid0 & Hvalid1).
          rewrite Hexec0, Hexec1 in *.

          unfold rBPFMonadOp.upd_reg, upd_reg in *.
          simpl in *.
          inversion Hst.

          unfold_H0H1_destruct_apply_H Hst
            rBPFMonadOp.upd_reg upd_reg upd_reg_equiv3.

          eapply upd_reg_none; eauto.
      + unfold rBPFMonadOp.upd_flag, upd_flag in *.
        inversion Hst.

        unfold_H0H1_destruct_apply_H Hst
        rBPFMonadOp.upd_flag upd_flag upd_flag_equiv3.

        eapply upd_flag_none; eauto.
    - match goal with
      | |- context [if ?X then _ else _] =>
        destruct X
      end.
      all:
          unfold_H0H1_destruct_apply_H Hst
          rBPFMonadOp.upd_flag upd_flag upd_flag_equiv3.

      all: eapply upd_flag_none; eauto.
  Qed.


  Lemma step_opcode_mem_ld_imm_ref:
    forall i d r op st0 st1 st0'
      (Hbefore: Rel flag_blk regs_blk st_blk st0 st1)
      (Hst: rBPFInterpreter.step_opcode_mem_ld_imm i d r op st0 = Some (tt, st0')),
        exists st1',
          rBPFInterpreter2.step_opcode_mem_ld_imm i d r op st1 = Some (tt, st1') /\
          Rel flag_blk regs_blk st_blk st0' st1'.
  Proof.
    unfold rBPFInterpreter.step_opcode_mem_ld_imm, rBPFInterpreter2.step_opcode_mem_ld_imm, bindM.
    unfold rBPFInterpreter.get_opcode_mem_ld_imm, rBPFInterpreter2.get_opcode_mem_ld_imm, bindM, returnM.
    intros.

    destruct byte_to_opcode_mem_ld_imm.
    3:{
      unfold_H0H1_destruct_apply_H Hst
      rBPFMonadOp.upd_flag upd_flag upd_flag_equiv3.

      eapply upd_flag_none; eauto.
    }
    all: unfold_H0H1_destruct_apply_H Hst
          rBPFMonadOp.upd_reg upd_reg upd_reg_equiv3;
        eapply upd_reg_none; eauto.
  Qed.


  Lemma step_opcode_mem_ld_reg_ref:
    forall addr r op st0 st1 st0'
      (Hbefore: Rel flag_blk regs_blk st_blk st0 st1)
      (Hmem: MemInv.memory_inv st0)
      (Hst: rBPFInterpreter.step_opcode_mem_ld_reg (Vint addr) r op st0 = Some (tt, st0')),
        exists st1',
          rBPFInterpreter2.step_opcode_mem_ld_reg (Vint addr) r op st1 = Some (tt, st1') /\
          Rel flag_blk regs_blk st_blk st0' st1'.
  Proof.
    unfold rBPFInterpreter.step_opcode_mem_ld_reg, rBPFInterpreter2.step_opcode_mem_ld_reg, bindM.
    unfold rBPFInterpreter.get_opcode_mem_ld_reg, rBPFInterpreter2.get_opcode_mem_ld_reg, bindM, returnM.
    intros.

    destruct byte_to_opcode_mem_ld_reg.
    5:{
      unfold_H0H1_destruct_apply_H Hst
      rBPFMonadOp.upd_flag upd_flag upd_flag_equiv3.
      eapply upd_flag_none; eauto.
    }
    all:
      rewrite <- equivalence_between_check_mem in Hst;
      destruct Semantics.check_mem eqn: Hcheck_mem;[| inversion Hst];
      destruct p;
      rewrite CheckMem.check_memM_P in Hcheck_mem; auto; try constructor;
      inversion Hcheck_mem;
      subst s v;
      clear Hcheck_mem;
      erewrite check_memM_P; eauto; try constructor.


      (**r here we need the fact: check_memP = check_memP2 *)
    all:
      rewrite <- check_memP_check_memP2 with (st0 := st0) (flag_blk := flag_blk) (regs_blk := regs_blk) (st_blk := st_blk); auto; try constructor;
      unfold rBPFMonadOp.cmp_ptr32_nullM, cmp_ptr32_nullM in *;
      unfold ConcreteState.eval_mem, State.eval_mem in *;

      eapply cmp_ptr32_null_check_memP_Some with (perm := Readable) in Hmem as Hmem'; eauto; try constructor.

      all:
        destruct Hmem' as (res & Hcmp0 & Hcmp1);
        rewrite Hcmp0, Hcmp1 in *;
        unfold rBPFMonadOp.upd_flag, upd_flag in *.

      all:
        destruct res; inversion Hst;
          [ unfold_H0H1_destruct_apply_H Hst
      rBPFMonadOp.upd_flag upd_flag upd_flag_equiv3;
            eapply upd_flag_none; eauto |
          ].

      all:
        unfold rBPFMonadOp.load_mem, load_mem in *;
        rewrite load_mem_equiv3 with (st1 := st1) in H0; auto;
          [
            destruct ConcreteState.load_mem; inversion H0;
            destruct v; inversion H1;
            unfold_H0H1_destruct_apply_H Hst
              rBPFMonadOp.upd_reg upd_reg upd_reg_equiv3;
            eapply upd_reg_none; eauto|
          ].

      all:
        clear - Hbefore Hmem Hcmp0;
        eapply mem_inv_check_mem_valid_pointer with (perm := Readable) in Hmem; eauto; try constructor;

        destruct Hmem as [Hptr | Hnull];
          [
            destruct Hptr as (b &ofs & Hck & Hvalid_ptr & Hvalid_blk);
            rewrite Hck in *;
            eexists; eexists; split;
              [
                reflexivity | ] |
            (**r which is impossible because of Hcmp0 = false *)
            rewrite Hnull in *;
            simpl in Hcmp0;
            inversion Hcmp0
          ].

        all:
          destruct Hbefore;
          destruct minvalid as (Hflag_blk & Hregs_blk & Hst_blk & minvalid & _).
        all:
          split; [
            intro Hf; subst b; apply Hflag_blk; assumption
            | ].
        all:
          split; intro Hf; subst b; [apply Hregs_blk | apply Hst_blk]; assumption.
  Qed.


  Lemma step_opcode_mem_st_imm_ref:
    forall i addr op st0 st1 st0'
      (Hbefore: Rel flag_blk regs_blk st_blk st0 st1)
      (Hmem: MemInv.memory_inv st0)
      (Hst: rBPFInterpreter.step_opcode_mem_st_imm i (Vint addr) op st0 = Some (tt, st0')),
        exists st1',
          rBPFInterpreter2.step_opcode_mem_st_imm i (Vint addr) op st1 = Some (tt, st1') /\
          Rel flag_blk regs_blk st_blk st0' st1'.
  Proof.
    unfold rBPFInterpreter.step_opcode_mem_st_imm, rBPFInterpreter2.step_opcode_mem_st_imm, bindM.
    unfold rBPFInterpreter.get_opcode_mem_st_imm, rBPFInterpreter2.get_opcode_mem_st_imm, bindM, returnM.
    intros.

    destruct byte_to_opcode_mem_st_imm.
    5:{
      unfold_H0H1_destruct_apply_H Hst
      rBPFMonadOp.upd_flag upd_flag upd_flag_equiv3;
      eapply upd_flag_none; eauto.
    }

    all:
      rewrite <- equivalence_between_check_mem in Hst;
      destruct Semantics.check_mem eqn: Hcheck_mem;[| inversion Hst];
      destruct p;
      rewrite CheckMem.check_memM_P in Hcheck_mem; auto; try constructor;
      inversion Hcheck_mem;
      subst s v;
      clear Hcheck_mem;
      erewrite check_memM_P; eauto; try constructor.

    (**r here we need the fact: check_memP = check_memP2 *)
    all:
      rewrite <- check_memP_check_memP2 with (st0 := st0) (flag_blk := flag_blk) (regs_blk := regs_blk) (st_blk := st_blk); auto; try constructor;
      unfold rBPFMonadOp.cmp_ptr32_nullM, cmp_ptr32_nullM in *;
      unfold ConcreteState.eval_mem, State.eval_mem in *;

      eapply cmp_ptr32_null_check_memP_Some with (perm := Writable) in Hmem as Hmem'; eauto; try constructor.

      all:
        destruct Hmem' as (res & Hcmp0 & Hcmp1);
        rewrite Hcmp0, Hcmp1 in *;
        unfold rBPFMonadOp.upd_flag, upd_flag in *.

      all:
        destruct res; inversion Hst;
          [ unfold_H0H1_destruct_apply_H Hst
              rBPFMonadOp.upd_flag upd_flag upd_flag_equiv3;
            eapply upd_flag_none; eauto |
          ].

      all:
        unfold rBPFMonadOp.store_mem_imm, store_mem_imm in *;
        unfold State.store_mem_imm, ConcreteState.store_mem_imm in *;
        unfold Mem.storev in *.

      all:
        destruct check_memP; inversion H0;
        destruct Mem.store eqn: Hstore; inversion H0;
        eapply store_equiv3 in Hstore; eauto.

      all: destruct Hstore as (m1 & Hstore & Hrel); rewrite Hstore;
           eexists; split; [reflexivity | assumption].
  Qed.


  Lemma step_opcode_mem_st_reg_ref:
    forall r addr op st0 st1 st0'
      (Hbefore: Rel flag_blk regs_blk st_blk st0 st1)
      (Hmem: MemInv.memory_inv st0)
      (Hst: rBPFInterpreter.step_opcode_mem_st_reg r (Vint addr) op st0 = Some (tt, st0')),
        exists st1',
          rBPFInterpreter2.step_opcode_mem_st_reg r (Vint addr) op st1 = Some (tt, st1') /\
          Rel flag_blk regs_blk st_blk st0' st1'.
  Proof.
    unfold rBPFInterpreter.step_opcode_mem_st_reg, rBPFInterpreter2.step_opcode_mem_st_reg, bindM.
    unfold rBPFInterpreter.get_opcode_mem_st_reg, rBPFInterpreter2.get_opcode_mem_st_reg, bindM, returnM.
    intros.

    destruct byte_to_opcode_mem_st_reg.
    5:{
      unfold_H0H1_destruct_apply_H Hst
      rBPFMonadOp.upd_flag upd_flag upd_flag_equiv3;
      eapply upd_flag_none; eauto.
    }

    all:
      rewrite <- equivalence_between_check_mem in Hst;
      destruct Semantics.check_mem eqn: Hcheck_mem;[| inversion Hst];
      destruct p;
      rewrite CheckMem.check_memM_P in Hcheck_mem; auto; try constructor;
      inversion Hcheck_mem;
      subst s v;
      clear Hcheck_mem;
      erewrite check_memM_P; eauto; try constructor.

    (**r here we need the fact: check_memP = check_memP2 *)
    all:
      rewrite <- check_memP_check_memP2 with (st0 := st0) (flag_blk := flag_blk) (regs_blk := regs_blk) (st_blk := st_blk); auto; try constructor;
      unfold rBPFMonadOp.cmp_ptr32_nullM, cmp_ptr32_nullM in *;
      unfold ConcreteState.eval_mem, State.eval_mem in *;

      eapply cmp_ptr32_null_check_memP_Some with (perm := Writable) in Hmem as Hmem'; eauto; try constructor.

      all:
        destruct Hmem' as (res & Hcmp0 & Hcmp1);
        rewrite Hcmp0, Hcmp1 in *;
        unfold rBPFMonadOp.upd_flag, upd_flag in *.

      all:
        destruct res; inversion Hst;
          [ unfold_H0H1_destruct_apply_H Hst
              rBPFMonadOp.upd_flag upd_flag upd_flag_equiv3;
            eapply upd_flag_none; eauto |
          ].

      all:
        unfold rBPFMonadOp.store_mem_reg, store_mem_reg in *;
        unfold State.store_mem_reg, ConcreteState.store_mem_reg in *;
        unfold Mem.storev in *.

      all:
        destruct check_memP; inversion H0;
        destruct Mem.store eqn: Hstore; inversion H0;
        eapply store_equiv3 in Hstore; eauto.

      all: destruct Hstore as (m1 & Hstore & Hrel); rewrite Hstore;
           eexists; split; [reflexivity | assumption].
  Qed.

  Lemma eval_reg_none:
    forall st0 st1 st0' flag_blk regs_blk st_blk r
      (Hbefore : Rel flag_blk regs_blk st_blk st0 st1)
      (Hst : ConcreteState.eval_reg r st1 = None),
        exists st1' : state,
          None = Some (tt, st1') /\ Rel flag_blk regs_blk st_blk st0' st1'.
  Proof.
    intros.
    destruct Hbefore as (Hunchanged, Hpc,
      (Hflag_eq, Hflag),
      (Hreg_eq, Hregs), Hnum, Hmrs, Hlen, Hins, Hperm, Hinvalid).
    unfold ConcreteState.eval_reg, Mem.loadv in *.

    destruct Hperm as (_ & Hperm).
    specialize (Hperm r).
    unfold ptr_range_perm in Hperm.
    rewrite Hreg_eq in *.
    unfold Val.add, Archi.ptr64 in *.

    eapply Mem.valid_access_freeable_any with (p := Readable) in Hperm as Hload.
    eapply Mem.valid_access_load in Hload.
    destruct Hload as (v & Hload).
    rewrite Hload in Hst.
    inversion Hst.
  Qed.

  Lemma step_ref:
    forall st0 st1 st0'
      (Hbefore: Rel flag_blk regs_blk st_blk st0 st1)
      (Hmem: MemInv.memory_inv st0)
      (Hst: rBPFInterpreter.step st0 = Some (tt, st0')),
        exists st1',
          rBPFInterpreter2.step st1 = Some (tt, st1') /\
          Rel flag_blk regs_blk st_blk st0' st1'.
  Proof.
    unfold rBPFInterpreter.step, rBPFInterpreter2.step.
    unfold bindM.
    intros.
    unfold rBPFMonadOp.eval_pc, rBPFMonadOp.eval_ins in Hst.
    unfold eval_pc, eval_ins.
    rewrite eval_pc_equiv3 with (st1 := st1) in Hst; auto.
    rewrite ins_len_equiv3 with (st1 := st1) in Hst; auto.

    destruct Int.cmpu; [| inversion Hst].
    unfold rBPFInterpreter.get_opcode_ins, returnM in Hst.
    unfold get_opcode_ins.

    unfold rBPFInterpreter.get_opcode, returnM in Hst.
    unfold get_opcode, returnM.

    unfold rBPFInterpreter.get_dst, returnM in Hst.
    unfold get_dst, returnM.


    unfold rBPFMonadOp.int64_to_dst_reg, returnM in Hst.
    unfold int64_to_dst_reg, returnM.

    rewrite eval_ins_equiv3 with (st1 := st1) in Hst; auto.
    destruct ConcreteState.eval_ins; [| inversion Hst].
    destruct BinrBPF.int64_to_dst_reg'; [| inversion Hst].

    destruct byte_to_opcode.

    - (**r BPF_ALU64 *)
      unfold rBPFMonadOp.eval_reg, rBPFInterpreter.get_src64, bindM in Hst.
      unfold eval_reg, get_src64, bindM.

      destruct Int.eq.
      + unfold rBPFInterpreter.get_immediate, returnM in Hst.
        unfold get_immediate, returnM.
        unfold rBPFInterpreter.eval_immediate, returnM in Hst.
        unfold eval_immediate, returnM.

        destruct ConcreteState.eval_reg eqn: Hreg.
        rewrite eval_reg_equiv3 with (st1 := st1) (v := v) in Hst; eauto.

        eapply step_opcode_alu64_ref; eauto.

        eapply eval_reg_none; eauto.
      + unfold rBPFInterpreter.get_src, get_src in *.
        unfold rBPFMonadOp.int64_to_src_reg, int64_to_src_reg in *.
        destruct BinrBPF.int64_to_src_reg'; [| inversion Hst].

        unfold rBPFMonadOp.eval_reg, eval_reg, returnM in *.
        destruct ConcreteState.eval_reg eqn: Hreg.
        *
          rewrite eval_reg_equiv3 with (st1 := st1) (v := v) in Hst; eauto.
          destruct (ConcreteState.eval_reg r0 st1) eqn: Hreg'.
          rewrite eval_reg_equiv3 with (st1 := st1) (v := v0) in Hst; eauto.
          eapply step_opcode_alu64_ref; eauto.
          eapply eval_reg_none; eauto.
        * eapply eval_reg_none; eauto.

    - (**r BPF_ALU32 *)
      unfold rBPFMonadOp.eval_reg, eval_reg in *.
      unfold rBPFInterpreter.reg64_to_reg32, reg64_to_reg32, returnM in *.
      unfold rBPFInterpreter.get_src32, get_src32, bindM in *.
      destruct Int.eq.
      + unfold rBPFInterpreter.get_immediate, get_immediate, returnM in *.
        destruct ConcreteState.eval_reg eqn: Hreg.
        rewrite eval_reg_equiv3 with (st1 := st1) (v := v) in Hst; eauto.
        eapply step_opcode_alu32_ref; eauto.
        eapply eval_reg_none; eauto.
      + unfold rBPFInterpreter.get_src, get_src in *.
        unfold rBPFMonadOp.int64_to_src_reg, int64_to_src_reg in *.
        destruct BinrBPF.int64_to_src_reg'; [| inversion Hst].

        unfold rBPFMonadOp.eval_reg, eval_reg, returnM in *.
        destruct ConcreteState.eval_reg eqn: Hreg.
        *
          rewrite eval_reg_equiv3 with (st1 := st1) (st0 := st0) (v := v) (r := r) in Hst; eauto.
          destruct (ConcreteState.eval_reg r0 st1) eqn: Hreg'.
          {
            rewrite eval_reg_equiv3 with (st1 := st1) (st0 := st0) (v := v0) (r := r0) in Hst; eauto.
            unfold rBPFInterpreter.reg64_to_reg32, reg64_to_reg32 in *.
            unfold returnM, val_intuoflongu in *.
            eapply step_opcode_alu32_ref; eauto.
          }
          {
            eapply eval_reg_none; eauto.
          }
        * eapply eval_reg_none; eauto.


    - (**r BPF_Branch *)
      unfold rBPFMonadOp.eval_reg, eval_reg in *.
      unfold rBPFInterpreter.get_offset, get_offset, returnM in *.
      unfold rBPFInterpreter.get_src64, get_src64 in *.
      destruct Int.eq.
      + unfold rBPFInterpreter.get_immediate, get_immediate, bindM, returnM in *.
        unfold rBPFInterpreter.eval_immediate, eval_immediate, returnM in *.

        destruct ConcreteState.eval_reg eqn: Hreg.
        * rewrite eval_reg_equiv3 with (st1 := st1) (v := v) in Hst; eauto.
          eapply step_opcode_branch_ref; eauto.
          unfold sint32_to_vint, BinrBPF.get_immediate.
          eexists; reflexivity.
        * eapply eval_reg_none; eauto.
      + unfold rBPFInterpreter.get_src, get_src, bindM, returnM in *.
        unfold rBPFMonadOp.int64_to_src_reg, int64_to_src_reg, returnM in *.
        destruct BinrBPF.int64_to_src_reg'; [| inversion Hst].

        unfold rBPFMonadOp.eval_reg, eval_reg in *.

        destruct ConcreteState.eval_reg eqn: Hreg.
        *
          rewrite eval_reg_equiv3 with (st1 := st1) (st0 := st0) (v := v) (r := r) in Hst; eauto.
          destruct (ConcreteState.eval_reg r0 st1) eqn: Hreg'.
          {
            rewrite eval_reg_equiv3 with (st1 := st1) (st0 := st0) (v := v0) (r := r0) in Hst; eauto.
            unfold rBPFInterpreter.reg64_to_reg32, reg64_to_reg32 in *.
            unfold returnM, val_intuoflongu in *.
            eapply step_opcode_branch_ref; eauto.

            assert (Hreg_some : exists vl, State.eval_reg r0 st0 = Vlong vl). {
              assert (Hr := Hbefore).
              destruct Hbefore.
              clear - Hr flag_blk st_blk mregs.
              unfold ConcreteState.eval_reg.
              clear - Hr flag_blk st_blk mregs.
              unfold match_registers in mregs.
              destruct mregs as (Hreg_eq & mregs).
              rewrite Hreg_eq in *.
              specialize (mregs r0).
              destruct mregs as (vl & Hreg & Hvl_eq).
              erewrite eval_reg_equiv3 with (st1 := st1) (v := Vlong vl); eauto.
              unfold ConcreteState.eval_reg.
              rewrite Hreg_eq in *.
              rewrite Hreg.
              reflexivity.
            }

            destruct Hreg_some as (vl & Hreg_some).
            destruct Hbefore as (_, _, _, (_ & Hbefore), _, _, _,_ , _, _).
            unfold match_registers in Hbefore.
            specialize (Hbefore r0).
            destruct Hbefore as (vl' & Hload & Heval_reg).
            rewrite Hreg_some in Heval_reg.
            inversion Heval_reg; subst vl'; clear Heval_reg.
            unfold ConcreteState.eval_reg in Hreg'.
            rewrite Hload in Hreg'.
            inversion Hreg'.
            exists vl.
            reflexivity.
          }
          {
            eapply eval_reg_none; eauto.
          }
        * eapply eval_reg_none; eauto.


    - (**r BPF_Mem_ld_imm *)
      unfold rBPFMonadOp.eval_reg, eval_reg in *.
      unfold rBPFInterpreter.get_immediate, get_immediate, returnM in *.

      destruct ConcreteState.eval_reg eqn: Hreg.
      + rewrite eval_reg_equiv3 with (st1 := st1) (v := v) in Hst; eauto.
        eapply step_opcode_mem_ld_imm_ref; eauto.
      + eapply eval_reg_none; eauto.


    - (**r BPF_Mem_ld_reg *)
      unfold rBPFInterpreter.get_src, get_src, bindM, returnM in *.
      unfold rBPFMonadOp.int64_to_src_reg, int64_to_src_reg, returnM in *.
      destruct BinrBPF.int64_to_src_reg'; [| inversion Hst].
      unfold rBPFMonadOp.eval_reg, eval_reg, returnM in *.
      unfold rBPFInterpreter.get_offset, get_offset, returnM in *.
      unfold rBPFInterpreter.get_addr_ofs, get_addr_ofs, returnM in *.

      destruct ConcreteState.eval_reg eqn: Hreg.
      + rewrite eval_reg_equiv3 with (st1 := st1) (v := v) in Hst; eauto.
        unfold val_intuoflongu in *.
        assert (Hreg_some: exists vl, ConcreteState.eval_reg r0 st1 = Some (Vlong vl)). {
          destruct Hbefore.
          clear - mregs.
          unfold ConcreteState.eval_reg.
          clear - mregs.
          unfold match_registers in mregs.
          destruct mregs as (Hreg_eq & mregs).
          rewrite Hreg_eq in *.
          specialize (mregs r0).
          destruct mregs as (vl & Hreg & Hvl_eq).
          rewrite Hreg.
          eexists; reflexivity.
        }
        destruct Hreg_some as (vl & Hreg_some).
        rewrite Hreg_some in *.
        inversion Hreg.
        subst v.
        simpl in *.
        eapply step_opcode_mem_ld_reg_ref; eauto.
      + eapply eval_reg_none; eauto.

    - (**r BPF_Mem_st_imm *)
      unfold rBPFMonadOp.eval_reg, eval_reg, bindM, returnM in *.
      unfold rBPFInterpreter.get_offset, get_offset, returnM in *.
      unfold rBPFInterpreter.get_immediate, get_immediate, returnM in *.
      unfold rBPFInterpreter.get_addr_ofs, get_addr_ofs, returnM in *.

      destruct ConcreteState.eval_reg eqn: Hreg.
      + rewrite eval_reg_equiv3 with (st1 := st1) (v := v) in Hst; eauto.
        unfold val_intuoflongu in *.
        assert (Hreg_some: exists vl, ConcreteState.eval_reg r st1 = Some (Vlong vl)). {
          destruct Hbefore.
          clear - mregs.
          unfold ConcreteState.eval_reg.
          clear - mregs.
          unfold match_registers in mregs.
          destruct mregs as (Hreg_eq & mregs).
          rewrite Hreg_eq in *.
          specialize (mregs r).
          destruct mregs as (vl & Hreg & Hvl_eq).
          rewrite Hreg.
          eexists; reflexivity.
        }
        destruct Hreg_some as (vl & Hreg_some).
        rewrite Hreg_some in *.
        inversion Hreg.
        subst v.
        simpl in *.
        eapply step_opcode_mem_st_imm_ref; eauto.
      + eapply eval_reg_none; eauto.


    - (**r BPF_Mem_st_reg *)
      unfold rBPFMonadOp.eval_reg, eval_reg, bindM, returnM in *.
      unfold rBPFInterpreter.get_src, get_src, bindM, returnM in *.
      unfold rBPFMonadOp.int64_to_src_reg, int64_to_src_reg, bindM, returnM in *.
      destruct BinrBPF.int64_to_src_reg'; [| inversion Hst].
      unfold rBPFInterpreter.get_offset, get_offset, returnM in *.
      unfold rBPFInterpreter.get_addr_ofs, get_addr_ofs, returnM in *.

       destruct ConcreteState.eval_reg eqn: Hreg.
       +
          rewrite eval_reg_equiv3 with (st1 := st1) (st0 := st0) (v := v) (r := r) in Hst; eauto.
          destruct (ConcreteState.eval_reg r0 st1) eqn: Hreg'.
          *
            rewrite eval_reg_equiv3 with (st1 := st1) (st0 := st0) (v := v0) (r := r0) in Hst; eauto.

            unfold val_intuoflongu in *.
            assert (Hreg_some: exists vl, ConcreteState.eval_reg r st1 = Some (Vlong vl)). {
              destruct Hbefore.
              clear - mregs.
              unfold ConcreteState.eval_reg.
              clear - mregs.
              unfold match_registers in mregs.
              destruct mregs as (Hreg_eq & mregs).
              rewrite Hreg_eq in *.
              specialize (mregs r).
              destruct mregs as (vl & Hreg & Hvl_eq).
              rewrite Hreg.
              eexists; reflexivity.
            }
            destruct Hreg_some as (vl & Hreg_some).
            rewrite Hreg_some in *.
            inversion Hreg.
            subst v.
            simpl in *.
            eapply step_opcode_mem_st_reg_ref; eauto.
          * eapply eval_reg_none; eauto.
      + eapply eval_reg_none; eauto.

    - (**r BPF_ILLEGAL_INS *)
      unfold_H0H1_destruct_apply_H Hst
      rBPFMonadOp.upd_flag upd_flag upd_flag_equiv3.

      eapply upd_flag_none; eauto.
  Qed.

  Lemma step_some_tt:
    forall st0 u s
    (Hstep : rBPFInterpreter.step st0 = Some (u, s)),
      u = tt.
  Proof.
    intros.
    unfold rBPFInterpreter.step in Hstep.
    unfold rBPFMonadOp.eval_pc, bindM, returnM in *.
    unfold rBPFMonadOp.eval_ins, bindM, returnM in *.
    destruct Int.cmpu; inversion Hstep.
    clear Hstep.
    unfold rBPFInterpreter.get_dst, bindM, returnM in *.
    unfold rBPFMonadOp.int64_to_dst_reg, bindM, returnM in *.
    destruct State.eval_ins; [| inversion H0].
    destruct BinrBPF.int64_to_dst_reg'; [| inversion H0].
    destruct byte_to_opcode.
    - unfold rBPFInterpreter.get_src64, bindM, returnM in *.
      destruct Int.eq.
      + unfold rBPFInterpreter.get_immediate, bindM, returnM in *.
        unfold rBPFInterpreter.eval_immediate, bindM, returnM in *.
        unfold rBPFInterpreter.step_opcode_alu64, bindM, returnM in *.
        unfold rBPFInterpreter.get_opcode_alu64, bindM, returnM in *.
        destruct byte_to_opcode_alu64.
        all: try unfold rBPFInterpreter.reg64_to_reg32, bindM, returnM in *.
        all:
          try unfold rBPFMonadOp.upd_reg, bindM, returnM in *.
        all:  try
          match goal with
          | H: (if ?X then _ else _) _ = _ |- _ =>
            destruct X; inversion H
          end.
        all: try
          match goal with
          | H: match match ?X with |_ => _ end with |_ => _ end = _ |- _ =>
            destruct X; inversion H;
            reflexivity
          end.
        all: try reflexivity.
        unfold rBPFMonadOp.upd_flag, bindM, returnM in *.
        inversion H0. reflexivity.
        + unfold rBPFInterpreter.get_src, rBPFMonadOp.int64_to_src_reg, bindM, returnM in *.
          destruct BinrBPF.int64_to_src_reg'; [| inversion H0].
          unfold rBPFMonadOp.eval_reg, bindM, returnM in *.
          unfold rBPFInterpreter.step_opcode_alu64, bindM, returnM in *.
          unfold rBPFInterpreter.get_opcode_alu64, bindM, returnM in *.
          destruct byte_to_opcode_alu64.
          all: try unfold rBPFInterpreter.reg64_to_reg32, bindM, returnM in *.
          all:
            try unfold rBPFMonadOp.upd_reg, bindM, returnM in *.
          all:  try
            match goal with
            | H: (if ?X then _ else _) _ = _ |- _ =>
              destruct X; inversion H
            end.
          all: try
            match goal with
            | H: match match ?X with |_ => _ end with |_ => _ end = _ |- _ =>
              destruct X; inversion H;
              reflexivity
            end.
          all: try reflexivity.
          unfold rBPFMonadOp.upd_flag, bindM, returnM in *.
          inversion H0. reflexivity.
      - unfold rBPFInterpreter.get_src32, bindM, returnM in *.
        destruct Int.eq.
        + unfold rBPFInterpreter.get_immediate, bindM, returnM in *.
          unfold rBPFInterpreter.step_opcode_alu32, bindM, returnM in *.
          unfold rBPFInterpreter.get_opcode_alu32, bindM, returnM in *.
          destruct byte_to_opcode_alu32.
          all:
            try unfold rBPFMonadOp.upd_reg, bindM, returnM in *.
          all:  try
            match goal with
            | H: (if ?X then _ else _) _ = _ |- _ =>
              destruct X; inversion H
            end.
          all: try
            match goal with
            | H: match match ?X with |_ => _ end with |_ => _ end = _ |- _ =>
              destruct X; inversion H;
              reflexivity
            end.
          all: try reflexivity.
          unfold rBPFMonadOp.upd_flag, bindM, returnM in *.
          inversion H0. reflexivity.
        + unfold rBPFInterpreter.get_src, rBPFMonadOp.int64_to_src_reg, bindM, returnM in *.
          destruct BinrBPF.int64_to_src_reg'; [| inversion H0].
          unfold rBPFMonadOp.eval_reg, bindM, returnM in *.
          unfold rBPFInterpreter.reg64_to_reg32, bindM, returnM in *.
          unfold rBPFInterpreter.step_opcode_alu32, bindM, returnM in *.
          unfold rBPFInterpreter.get_opcode_alu32, bindM, returnM in *.
          destruct byte_to_opcode_alu32.
          all: try unfold rBPFInterpreter.reg64_to_reg32, bindM, returnM in *.
          all:
            try unfold rBPFMonadOp.upd_reg, bindM, returnM in *.
          all:  try
            match goal with
            | H: (if ?X then _ else _) _ = _ |- _ =>
              destruct X; inversion H
            end.
          all: try
            match goal with
            | H: match match ?X with |_ => _ end with |_ => _ end = _ |- _ =>
              destruct X; inversion H;
              reflexivity
            end.
          all: try reflexivity.
          unfold rBPFMonadOp.upd_flag, bindM, returnM in *.
          inversion H0. reflexivity.
    - unfold rBPFInterpreter.get_src64, bindM, returnM in *.
      destruct Int.eq.
      + unfold rBPFInterpreter.get_immediate, bindM, returnM in *.
        unfold rBPFInterpreter.eval_immediate, bindM, returnM in *.
        unfold rBPFInterpreter.step_opcode_branch, bindM, returnM in *.
        unfold rBPFInterpreter.get_opcode_branch, bindM, returnM in *.
        destruct byte_to_opcode_branch.
        all:
          try unfold rBPFMonadOp.upd_pc, rBPFMonadOp.upd_flag, bindM, returnM in *.
        all:  try
          match goal with
          | H: (if ?X then _ else _) _ = _ |- _ =>
            destruct X; inversion H
          end.
        all:  try
          match goal with
          | H: match (if ?X then _ else _) with |_ => _ end = _ |- _ =>
            destruct X; inversion H
          end.
        all: try reflexivity.
        destruct rBPFMonadOp._bpf_get_call; [| inversion H1].
        destruct p.
        unfold rBPFMonadOp.cmp_ptr32_nullM in *.
        destruct cmp_ptr32_null; [| inversion H1].
        destruct b.
        inversion H1. reflexivity.
        destruct rBPFMonadOp.exec_function; [| inversion H1].
        destruct p.
        unfold rBPFMonadOp.upd_reg in *.
        destruct Val.longofintu; inversion H1. reflexivity.
        inversion H0. reflexivity.
      + unfold rBPFInterpreter.get_src, rBPFMonadOp.int64_to_src_reg, bindM, returnM in *.
        destruct BinrBPF.int64_to_src_reg'; [| inversion H0].
        unfold rBPFMonadOp.eval_reg, bindM, returnM in *.
        unfold rBPFInterpreter.step_opcode_branch, bindM, returnM in *.
        unfold rBPFInterpreter.get_opcode_branch, bindM, returnM in *.
        destruct byte_to_opcode_branch.
        all:
          try unfold rBPFMonadOp.upd_pc, rBPFMonadOp.upd_flag, bindM, returnM in *.
        all:  try
          match goal with
          | H: (if ?X then _ else _) _ = _ |- _ =>
            destruct X; inversion H
          end.
        all:  try
          match goal with
          | H: match (if ?X then _ else _) with |_ => _ end = _ |- _ =>
            destruct X; inversion H
          end.
        all: try reflexivity.
        destruct rBPFMonadOp._bpf_get_call; [| inversion H1].
        destruct p.
        unfold rBPFMonadOp.cmp_ptr32_nullM in *.
        destruct cmp_ptr32_null; [| inversion H1].
        destruct b.
        inversion H1. reflexivity.
        destruct rBPFMonadOp.exec_function; [| inversion H1].
        destruct p.
        unfold rBPFMonadOp.upd_reg in *.
        destruct Val.longofintu; inversion H1. reflexivity.
        inversion H0. reflexivity.
    - unfold rBPFInterpreter.step_opcode_mem_ld_imm, bindM, returnM in *.
      unfold rBPFInterpreter.get_opcode_mem_ld_imm, bindM, returnM in *.
      destruct byte_to_opcode_mem_ld_imm.
      3:{
        inversion H0.
        reflexivity.
      }
      all:
        destruct rBPFMonadOp.upd_reg; inversion H0;
        destruct p;
        inversion H0; reflexivity.
    - unfold rBPFInterpreter.get_src, bindM, returnM in *.
      unfold rBPFMonadOp.int64_to_src_reg, bindM, returnM in *.
      destruct BinrBPF.int64_to_src_reg'; [| inversion H0].
      unfold rBPFInterpreter.step_opcode_mem_ld_reg, bindM, returnM in *.
      unfold rBPFInterpreter.get_opcode_mem_ld_reg, bindM, returnM in *.
      destruct byte_to_opcode_mem_ld_reg.
      5:{ inversion H0; reflexivity. }
      all:
        destruct rBPFInterpreter.check_mem; [| inversion H0];
        destruct p;
        destruct rBPFMonadOp.cmp_ptr32_nullM; [| inversion H0];
        destruct p;
        destruct b; [inversion H0; reflexivity |].
      all:
        destruct rBPFMonadOp.load_mem; [| inversion H0];
        destruct p.
      all:
        unfold rBPFMonadOp.upd_reg, bindM, returnM in *.
      all: destruct v0; inversion H0; try reflexivity.
    - unfold rBPFInterpreter.step_opcode_mem_st_imm, bindM, returnM in *.
      unfold rBPFInterpreter.get_opcode_mem_st_imm, bindM, returnM in *.
      destruct byte_to_opcode_mem_st_imm.
      5:{ inversion H0; reflexivity. }
      all:
        destruct rBPFInterpreter.check_mem; [| inversion H0];
        destruct p;
        destruct rBPFMonadOp.cmp_ptr32_nullM; [| inversion H0];
        destruct p;
        destruct b; [inversion H0; reflexivity |].
      all:
        destruct rBPFMonadOp.store_mem_imm; [| inversion H0];
        destruct p.
      all: inversion H0; try reflexivity.
    - unfold rBPFInterpreter.get_src, bindM, returnM in *.
      unfold rBPFMonadOp.int64_to_src_reg, bindM, returnM in *.
      destruct BinrBPF.int64_to_src_reg'; [| inversion H0].
      unfold rBPFInterpreter.step_opcode_mem_st_reg, bindM, returnM in *.
      unfold rBPFInterpreter.get_opcode_mem_st_reg, bindM, returnM in *.
      destruct byte_to_opcode_mem_st_reg.
      5:{ inversion H0; reflexivity. }
      all:
        destruct rBPFInterpreter.check_mem; [| inversion H0];
        destruct p;
        destruct rBPFMonadOp.cmp_ptr32_nullM; [| inversion H0];
        destruct p;
        destruct b; [inversion H0; reflexivity |].
      all:
        destruct rBPFMonadOp.store_mem_reg; [| inversion H0];
        destruct p.
      all: inversion H0; try reflexivity.
    - inversion H0; try reflexivity.
  Qed.

  Lemma bpf_interpreter_aux_ref:
    forall f st0 st1 st0'
      (Hbefore: Rel flag_blk regs_blk st_blk st0 st1)
      (Hmem: MemInv.memory_inv st0)
      (Hst: rBPFInterpreter.bpf_interpreter_aux f st0 = Some (tt, st0')),
        exists st1',
          rBPFInterpreter2.bpf_interpreter_aux f st1 = Some (tt, st1') /\
          Rel flag_blk regs_blk st_blk st0' st1'.
  Proof.
    induction f.
    intros.

    simpl in *.
    unfold_H0H1_destruct_apply_H Hst
    rBPFMonadOp.upd_flag upd_flag upd_flag_equiv3.

    eapply upd_flag_none; eauto.

    simpl in *.
    intros.
    unfold rBPFMonadOp.eval_ins_len, eval_ins_len, bindM, returnM in *.
    unfold rBPFMonadOp.eval_pc, eval_pc, bindM, returnM in *.


    rewrite ! eval_pc_equiv3 with (st1 := st1) in Hst; eauto.
    rewrite ! eval_ins_len_equiv3 with (st1 := st1) in Hst; eauto.
    destruct Int.ltu.
    2:{
      unfold_H0H1_destruct_apply_H Hst
      rBPFMonadOp.upd_flag upd_flag upd_flag_equiv3.

      eapply upd_flag_none; eauto.
    }

    destruct rBPFInterpreter.step eqn: Hstep; [| inversion Hst].
    destruct p.
    assert (Heq:= step_some_tt).

    specialize (Heq st0 u s Hstep).

    subst u.
    assert (Hstep0 := Hstep).
    eapply step_ref in Hstep; eauto.
    destruct Hstep as (st1' & Hstep & Hrel).
    rewrite Hstep.
    unfold rBPFMonadOp.eval_flag, eval_flag, bindM, returnM in *.
    rewrite <- eval_flag_equiv3 with (st0 := s); eauto.
    unfold comp_eq_32.
    unfold flag_eq in *.

    destruct bpf_flag_eq eqn: Heq.
    - 
      rewrite e.
      change (Int.eq (int_of_flag BPF_OK) (int_of_flag BPF_OK)) with true.
      rewrite ! eval_pc_equiv3 with (st1 := st1') in Hst; eauto.
      rewrite ! eval_ins_len_equiv3 with (st1 := st1') in Hst; eauto.
      simpl.
      destruct Int.ltu.
      + unfold rBPFMonadOp.upd_pc_incr, upd_pc_incr, bindM, returnM in *.
        rewrite ! eval_pc_equiv3 with (st1 := st1') in Hst; eauto.
        assert (Heq0: State.ins_len s = ins_len st1'). {
          destruct Hrel.
          assumption.
        }
        rewrite Heq0 in Hst.
        simpl in *.
        unfold ConcreteState.eval_pc in *.
        destruct Int.ltu; [| inversion Hst].
        specialize (IHf (State.upd_pc_incr s) (ConcreteState.upd_pc_incr st1') st0').

        assert (Hrel' : Rel flag_blk regs_blk st_blk (State.upd_pc_incr s) (ConcreteState.upd_pc_incr st1')). {
          clear - Hrel.
          eapply upd_pc_incr_equiv3; eauto.
        }
        assert (Hmem' : MemInv.memory_inv (State.upd_pc_incr s)). {
          clear - Hbefore Hmem Hrel Hstep0.
          rename Hstep0 into Hstep.

          eapply MemInv.mem_inv_upd_pc_incr with (st1 := s); eauto.

          unfold rBPFInterpreter.step in Hstep.
          unfold rBPFMonadOp.eval_pc, bindM, returnM in *.
          unfold rBPFMonadOp.eval_ins, bindM, returnM in *.
          destruct Int.cmpu; inversion Hstep.
          clear Hstep.

          unfold rBPFInterpreter.get_dst, bindM, returnM in *.
          unfold rBPFMonadOp.int64_to_dst_reg, bindM, returnM in *.
          destruct State.eval_ins; [| inversion H0].
          destruct BinrBPF.int64_to_dst_reg'; [| inversion H0].
          destruct byte_to_opcode.
          - unfold rBPFInterpreter.get_src64, bindM, returnM in *.
            destruct Int.eq.
            + unfold rBPFInterpreter.get_immediate, bindM, returnM in *.
              unfold rBPFInterpreter.eval_immediate, bindM, returnM in *.
              unfold rBPFInterpreter.step_opcode_alu64, bindM, returnM in *.
              unfold rBPFInterpreter.get_opcode_alu64, bindM, returnM in *.
              destruct byte_to_opcode_alu64.
              all: try unfold rBPFInterpreter.reg64_to_reg32, bindM, returnM in *.
              all:
                try unfold rBPFMonadOp.upd_reg, bindM, returnM in *.
              all:  try
                match goal with
                | H: (if ?X then _ else _) _ = _ |- _ =>
                  destruct X; inversion H
                end.
              all: try
                match goal with
                | H: match match ?X with |_ => _ end with |_ => _ end = _ |- _ =>
                  destruct X; inversion H;
                  eapply MemInv.mem_inv_upd_reg; eauto
                end.
              all: try eapply MemInv.mem_inv_upd_flag; eauto.
              unfold rBPFMonadOp.upd_flag, bindM, returnM in *.
              inversion H0; reflexivity.

            + unfold rBPFInterpreter.get_src, rBPFMonadOp.int64_to_src_reg, bindM, returnM in *.
              destruct BinrBPF.int64_to_src_reg'; [| inversion H0].
              unfold rBPFMonadOp.eval_reg, bindM, returnM in *.
              unfold rBPFInterpreter.step_opcode_alu64, bindM, returnM in *.
              unfold rBPFInterpreter.get_opcode_alu64, bindM, returnM in *.
              destruct byte_to_opcode_alu64.
              all: try unfold rBPFInterpreter.reg64_to_reg32, bindM, returnM in *.
              all:
                try unfold rBPFMonadOp.upd_reg, bindM, returnM in *.
              all:  try
                match goal with
                | H: (if ?X then _ else _) _ = _ |- _ =>
                  destruct X; inversion H
                end.
              all: try
                match goal with
                | H: match match ?X with |_ => _ end with |_ => _ end = _ |- _ =>
                  destruct X; inversion H;
                  eapply MemInv.mem_inv_upd_reg; eauto
                end.
              all: try eapply MemInv.mem_inv_upd_flag; eauto.
              unfold rBPFMonadOp.upd_flag, bindM, returnM in *.
              inversion H0; reflexivity.

          - unfold rBPFInterpreter.get_src32, bindM, returnM in *.
            destruct Int.eq.
            + unfold rBPFInterpreter.get_immediate, bindM, returnM in *.
              unfold rBPFInterpreter.step_opcode_alu32, bindM, returnM in *.
              unfold rBPFInterpreter.get_opcode_alu32, bindM, returnM in *.
              destruct byte_to_opcode_alu32.
              all:
                try unfold rBPFMonadOp.upd_reg, bindM, returnM in *.
              all:  try
                match goal with
                | H: (if ?X then _ else _) _ = _ |- _ =>
                  destruct X; inversion H
                end.
              all: try
                match goal with
                | H: match match ?X with |_ => _ end with |_ => _ end = _ |- _ =>
                  destruct X; inversion H;
                  eapply MemInv.mem_inv_upd_reg; eauto
                end.
              all: try eapply MemInv.mem_inv_upd_flag; eauto.
              unfold rBPFMonadOp.upd_flag, bindM, returnM in *.
              inversion H0; reflexivity.
            + unfold rBPFInterpreter.get_src, rBPFMonadOp.int64_to_src_reg, bindM, returnM in *.
              destruct BinrBPF.int64_to_src_reg'; [| inversion H0].
              unfold rBPFMonadOp.eval_reg, bindM, returnM in *.
              unfold rBPFInterpreter.reg64_to_reg32, bindM, returnM in *.
              unfold rBPFInterpreter.step_opcode_alu32, bindM, returnM in *.
              unfold rBPFInterpreter.get_opcode_alu32, bindM, returnM in *.
              destruct byte_to_opcode_alu32.
              all: try unfold rBPFInterpreter.reg64_to_reg32, bindM, returnM in *.
              all:
                try unfold rBPFMonadOp.upd_reg, bindM, returnM in *.
              all:  try
                match goal with
                | H: (if ?X then _ else _) _ = _ |- _ =>
                  destruct X; inversion H
                end.
              all: try
                match goal with
                | H: match match ?X with |_ => _ end with |_ => _ end = _ |- _ =>
                  destruct X; inversion H;
                  eapply MemInv.mem_inv_upd_reg; eauto
                end.
              all: try eapply MemInv.mem_inv_upd_flag; eauto.
              unfold rBPFMonadOp.upd_flag, bindM, returnM in *.
              inversion H0; reflexivity.
          - unfold rBPFInterpreter.get_src64, bindM, returnM in *.
            destruct Int.eq.
            + unfold rBPFInterpreter.get_immediate, bindM, returnM in *.
              unfold rBPFInterpreter.eval_immediate, bindM, returnM in *.
              unfold rBPFInterpreter.step_opcode_branch, bindM, returnM in *.
              unfold rBPFInterpreter.get_opcode_branch, bindM, returnM in *.
              destruct byte_to_opcode_branch.
              all:
                try unfold rBPFMonadOp.upd_pc, rBPFMonadOp.upd_flag, bindM, returnM in *.
              all:  try
                match goal with
                | H: (if ?X then _ else _) _ = _ |- _ =>
                  destruct X; inversion H
                end.
              all:  try
                match goal with
                | H: match (if ?X then _ else _) with |_ => _ end = _ |- _ =>
                  destruct X; inversion H
                end.
              all: try subst s; try assumption.
              set (Hcall:= rBPFMonadOp.lemma_bpf_get_call).
              specialize (Hcall
                (Int.repr (Int64.unsigned (Int64.repr (Int.signed (BinrBPF.get_immediate i)))))).
              specialize (Hcall st0).
              destruct Hcall as (ptr & Hcall & Hptr).
              rewrite Hcall in *.
              unfold rBPFMonadOp.cmp_ptr32_nullM in *.

              destruct Hptr as [Hnull | Hptr].
              * subst ptr.
                simpl in H1.
                change (Int.eq Int.zero Int.zero) with true in H1; simpl in H1.
                inversion H1.
                eapply MemInv.mem_inv_upd_flag; eauto.
              * destruct Hptr as (b & ofs & Hptr & _).
                subst ptr.
                destruct cmp_ptr32_null; [| inversion H1].
                destruct b0.
                inversion H1.
                eapply MemInv.mem_inv_upd_flag; eauto.
                destruct rBPFMonadOp.exec_function eqn: exec; [| inversion H1].
                destruct p.
                eapply call_inv_1 in exec.
                unfold rBPFMonadOp.upd_reg in *.
                destruct v; inversion H1.
                eapply MemInv.mem_inv_upd_reg; eauto.
                assumption.
              * inversion H0; eapply MemInv.mem_inv_upd_flag; eauto.
            + unfold rBPFInterpreter.get_src, rBPFMonadOp.int64_to_src_reg, bindM, returnM in *.
              destruct BinrBPF.int64_to_src_reg'; [| inversion H0].
              unfold rBPFMonadOp.eval_reg, bindM, returnM in *.
              unfold rBPFInterpreter.step_opcode_branch, bindM, returnM in *.
              unfold rBPFInterpreter.get_opcode_branch, bindM, returnM in *.
              destruct byte_to_opcode_branch.
              all:
                try unfold rBPFMonadOp.upd_pc, rBPFMonadOp.upd_flag, bindM, returnM in *.
              all:  try
                match goal with
                | H: (if ?X then _ else _) _ = _ |- _ =>
                  destruct X; inversion H
                end.
              all:  try
                match goal with
                | H: match (if ?X then _ else _) with |_ => _ end = _ |- _ =>
                  destruct X; inversion H
                end.
              all: try subst s; try assumption.
              set (Hcall:= rBPFMonadOp.lemma_bpf_get_call).
              unfold val_intsoflongu in H1.

              assert (Hreg: exists vl, State.eval_reg r0 st0 = Vlong vl). {
                assert (Hr := Hbefore).
                destruct Hbefore.
                clear - Hr flag_blk st_blk mregs.
                unfold ConcreteState.eval_reg.
                clear - Hr flag_blk st_blk mregs.
                unfold match_registers in mregs.
                destruct mregs as (Hreg_eq & mregs).
                rewrite Hreg_eq in *.
                specialize (mregs r0).
                destruct mregs as (vl & Hreg & Hvl_eq).
                erewrite eval_reg_equiv3 with (st1 := st1) (v := Vlong vl); eauto.
                unfold ConcreteState.eval_reg.
                rewrite Hreg_eq in *.
                rewrite Hreg.
                reflexivity.
              }
              destruct Hreg as (vl & Hreg).
              rewrite Hreg in *.

              specialize (Hcall (Int.repr (Int64.unsigned vl)) st0).
              destruct Hcall as (ptr & Hcall & Hptr).
              rewrite Hcall in *.
              unfold rBPFMonadOp.cmp_ptr32_nullM in *.

              destruct Hptr as [Hnull | Hptr].
              * subst ptr.
                simpl in H1.
                change (Int.eq Int.zero Int.zero) with true in H1; simpl in H1.
                inversion H1.
                eapply MemInv.mem_inv_upd_flag; eauto.
              * destruct Hptr as (b & ofs & Hptr & _).
                subst ptr.
                destruct cmp_ptr32_null; [| inversion H1].
                destruct b0.
                inversion H1.
                eapply MemInv.mem_inv_upd_flag; eauto.
                destruct rBPFMonadOp.exec_function eqn: exec; [| inversion H1].
                destruct p.
                eapply call_inv_1 in exec.
                unfold rBPFMonadOp.upd_reg in *.
                destruct v; inversion H1.
                eapply MemInv.mem_inv_upd_reg; eauto.
                assumption.
              * inversion H0; eapply MemInv.mem_inv_upd_flag; eauto.
          - unfold rBPFInterpreter.step_opcode_mem_ld_imm, bindM, returnM in *.
            unfold rBPFInterpreter.get_opcode_mem_ld_imm, bindM, returnM in *.
            destruct byte_to_opcode_mem_ld_imm.
            3:{
              inversion H0.
              eapply MemInv.mem_inv_upd_flag; eauto.
            }
            all:
            unfold rBPFMonadOp.upd_reg in *;
            match goal with
            | H: match match ?X with |_ => _ end with |_ => _ end = _ |- _ =>
              destruct X; inversion H;
              eapply MemInv.mem_inv_upd_reg; eauto
            end.
          - unfold rBPFInterpreter.get_src, bindM, returnM in *.
            unfold rBPFMonadOp.int64_to_src_reg, bindM, returnM in *.
            destruct BinrBPF.int64_to_src_reg'; [| inversion H0].
            unfold rBPFInterpreter.step_opcode_mem_ld_reg, bindM, returnM in *.
            unfold rBPFInterpreter.get_opcode_mem_ld_reg, bindM, returnM in *.

            assert (Hreg: exists vl, State.eval_reg r0 st0 = Vlong vl). {
              assert (Hr := Hbefore).
              destruct Hbefore.
              clear - Hr mregs.
              unfold ConcreteState.eval_reg.
              clear - Hr mregs.
              unfold match_registers in mregs.
              destruct mregs as (Hreg_eq & mregs).
              rewrite Hreg_eq in *.
              specialize (mregs r0).
              destruct mregs as (vl & Hreg & Hvl_eq).
              rewrite eval_reg_equiv3 with (st1 := st1) (v := Vlong vl); eauto.
              unfold ConcreteState.eval_reg.
              rewrite Hreg_eq, Hreg.
              reflexivity.
            }
            destruct Hreg as (vl & Hreg).
            rewrite Hreg in *.

            destruct byte_to_opcode_mem_ld_reg.
            5:{ inversion H0; eapply MemInv.mem_inv_upd_flag; eauto. }

            all:
              rewrite <- equivalence_between_check_mem in *;
              simpl in H0;
              rewrite CheckMem.check_memM_P in *; auto; try apply perm_refl.
            all: unfold rBPFMonadOp.cmp_ptr32_nullM in *;
              destruct cmp_ptr32_null; [| inversion H0].

            all:
              destruct b; [inversion H0; eapply MemInv.mem_inv_upd_flag; eauto |].
            all: unfold rBPFMonadOp.load_mem in *.
            all:
              destruct State.load_mem; inversion H0.
            all: destruct v; inversion H1.
            all: eapply MemInv.mem_inv_upd_reg; eauto.
          - unfold rBPFInterpreter.step_opcode_mem_st_imm, bindM, returnM in *.
            unfold rBPFInterpreter.get_opcode_mem_st_imm, bindM, returnM in *.

            assert (Hreg: exists vl, State.eval_reg r st0 = Vlong vl). {
              assert (Hr := Hbefore).
              destruct Hbefore.
              clear - Hr mregs.
              unfold ConcreteState.eval_reg.
              clear - Hr mregs.
              unfold match_registers in mregs.
              destruct mregs as (Hreg_eq & mregs).
              rewrite Hreg_eq in *.
              specialize (mregs r).
              destruct mregs as (vl & Hreg & Hvl_eq).
              rewrite eval_reg_equiv3 with (st1 := st1) (v := Vlong vl); eauto.
              unfold ConcreteState.eval_reg.
              rewrite Hreg_eq, Hreg.
              reflexivity.
            }
            destruct Hreg as (vl & Hreg).
            rewrite Hreg in *.

            destruct byte_to_opcode_mem_st_imm.
            5:{ inversion H0; eapply MemInv.mem_inv_upd_flag; eauto. }

            all:
              rewrite <- equivalence_between_check_mem in *;
              simpl in H0;
              rewrite CheckMem.check_memM_P in *; auto; try apply perm_W_R.
            all: unfold rBPFMonadOp.cmp_ptr32_nullM in *;
              destruct cmp_ptr32_null; [| inversion H0].

            all:
              destruct b; [inversion H0; eapply MemInv.mem_inv_upd_flag; eauto |].
            all: unfold rBPFMonadOp.store_mem_imm in *.
            all:
              destruct State.store_mem_imm eqn: Hstore; inversion H0.
            all: subst s0; eapply MemInv.mem_inv_store_imm in Hstore; eauto.
            all: reflexivity.
          - unfold rBPFInterpreter.get_src, bindM, returnM in *.
            unfold rBPFMonadOp.int64_to_src_reg, bindM, returnM in *.
            destruct BinrBPF.int64_to_src_reg'; [| inversion H0].
            unfold rBPFInterpreter.step_opcode_mem_st_reg, bindM, returnM in *.
            unfold rBPFInterpreter.get_opcode_mem_st_reg, bindM, returnM in *.

            assert (Hreg: exists vl, State.eval_reg r st0 = Vlong vl). {
              assert (Hr := Hbefore).
              destruct Hbefore.
              clear - Hr mregs.
              unfold ConcreteState.eval_reg.
              clear - Hr mregs.
              unfold match_registers in mregs.
              destruct mregs as (Hreg_eq & mregs).
              rewrite Hreg_eq in *.
              specialize (mregs r).
              destruct mregs as (vl & Hreg & Hvl_eq).
              rewrite eval_reg_equiv3 with (st1 := st1) (v := Vlong vl); eauto.
              unfold ConcreteState.eval_reg.
              rewrite Hreg_eq, Hreg.
              reflexivity.
            }
            destruct Hreg as (vl & Hreg).
            rewrite Hreg in *.

            assert (Hreg0: exists vl, State.eval_reg r0 st0 = Vlong vl). {
              assert (Hr := Hbefore).
              destruct Hbefore.
              clear - Hr mregs.
              unfold ConcreteState.eval_reg.
              clear - Hr mregs.
              unfold match_registers in mregs.
              destruct mregs as (Hreg_eq & mregs).
              rewrite Hreg_eq in *.
              specialize (mregs r0).
              destruct mregs as (vl & Hreg & Hvl_eq).
              rewrite eval_reg_equiv3 with (st1 := st1) (v := Vlong vl); eauto.
              unfold ConcreteState.eval_reg.
              rewrite Hreg_eq, Hreg.
              reflexivity.
            }
            destruct Hreg0 as (vl0 & Hreg0).
            rewrite Hreg0 in *.
            destruct byte_to_opcode_mem_st_reg.
            5:{ inversion H0; eapply MemInv.mem_inv_upd_flag; eauto. }

            all:
              rewrite <- equivalence_between_check_mem in *;
              simpl in H0;
              rewrite CheckMem.check_memM_P in *; auto; try apply perm_W_R.
            all: unfold rBPFMonadOp.cmp_ptr32_nullM in *;
              destruct cmp_ptr32_null; [| inversion H0].

            all:
              destruct b; [inversion H0; eapply MemInv.mem_inv_upd_flag; eauto |].
            all: unfold rBPFMonadOp.store_mem_reg in *.
            all:
              destruct State.store_mem_reg eqn: Hstore; inversion H0.
            all: subst s0; eapply MemInv.mem_inv_store_reg in Hstore; eauto.
            all: reflexivity.
          - inversion H0; eapply MemInv.mem_inv_upd_flag; eauto.
        }

        specialize (IHf Hrel' Hmem' Hst).
        destruct IHf as (st1'0 & Hbpf & Hrel'').
        exists st1'0.
        intuition.
      + 
        unfold_H0H1_destruct_apply_H Hst
        rBPFMonadOp.upd_flag upd_flag upd_flag_equiv3.
        eapply upd_flag_none; eauto.

    - assert (Hneq: Int.eq (int_of_flag (State.eval_flag s)) (int_of_flag BPF_OK) = false). {
        unfold State.eval_flag in *.
        destruct (State.flag s) eqn: Hflag.
        2:{ exfalso; apply n; reflexivity. }
        all: reflexivity.
      }
      rewrite Hneq.
      eexists; split; [reflexivity | ].
      inversion Hst.
      subst s.
      assumption.
  Qed.

  Lemma bpf_aux_some_tt:
    forall f st u s
    (Hbpf : rBPFInterpreter.bpf_interpreter_aux f st =
       Some (u, s)),
      u = tt.
  Proof.
    induction f;
    intros.

    simpl in *.
    unfold rBPFMonadOp.upd_flag in *.
    inversion Hbpf.
    reflexivity.

    simpl in *.
    unfold rBPFMonadOp.eval_ins_len, rBPFMonadOp.eval_pc, bindM, returnM in *.
    destruct Int.ltu.
    2:{ unfold rBPFMonadOp.upd_flag in *.
        inversion Hbpf.
        reflexivity.
    }
    destruct rBPFInterpreter.step eqn: Hstep.
    -
      destruct p.
      eapply step_some_tt in Hstep.
      subst u0.
      unfold rBPFMonadOp.eval_flag, bindM, returnM in *.
      destruct flag_eq.
      + destruct Int.ltu.
        * unfold rBPFMonadOp.upd_pc_incr in *.
          destruct Int.cmpu; [| inversion Hbpf].
          eapply IHf; eauto.
        * unfold rBPFMonadOp.upd_flag in *.
          inversion Hbpf.
          reflexivity.
      + inversion Hbpf.
        reflexivity.
  - inversion Hbpf.
  Qed.

  Theorem bpf_interpreter_ref:
    forall f st0 st1 st0' res
      (Hbefore: Rel flag_blk regs_blk st_blk st0 st1)
      (Hmem: MemInv.memory_inv st0)
      (Hst: rBPFInterpreter.bpf_interpreter f st0 = Some (res, st0')),
        exists st1',
          rBPFInterpreter2.bpf_interpreter f st1 = Some (res, st1') /\
          Rel flag_blk regs_blk st_blk st0' st1'.
  Proof.
    intros.
    unfold rBPFInterpreter.bpf_interpreter, bpf_interpreter, bindM, returnM in *.
    destruct rBPFInterpreter.bpf_interpreter_aux eqn: Hbpf; [| inversion Hst].
    destruct p.
    assert (Heq:= bpf_aux_some_tt).
    specialize (Heq f st0 u s Hbpf).
    subst u.

    eapply bpf_interpreter_aux_ref in Hbpf; eauto.

    destruct Hbpf as (st1' & Hbpf & Hrel').
    rewrite Hbpf.
    unfold eval_flag.
    unfold comp_eq_32.
    rewrite <- eval_flag_equiv3 with (st0 := s); eauto.
    unfold rBPFMonadOp.eval_flag in Hst.
    unfold flag_eq in *.
    destruct bpf_flag_eq eqn: Heq.
    - 
      rewrite e.
      change (Int.eq (int_of_flag BPF_SUCC_RETURN) (int_of_flag BPF_SUCC_RETURN)) with true.
      unfold rBPFMonadOp.eval_reg in Hst.
      simpl.

      inversion Hst.
      subst s.

      unfold eval_reg.

      destruct ConcreteState.eval_reg eqn: Hreg.
      + eapply eval_reg_equiv3 with (st0 := st0') in Hreg; eauto.
        subst v.
        exists st1'.
        split; [reflexivity | assumption].
      + eapply eval_reg_none with (st0' := st0') in Hreg; eauto.
        destruct Hreg as (st & Hf & _).
        inversion Hf.

    - assert (Hneq: Int.eq (int_of_flag (State.eval_flag s)) (int_of_flag BPF_SUCC_RETURN) = false). {
        unfold State.eval_flag in *.
        destruct (State.flag s) eqn: Hflag.
        1:{ exfalso; apply n; reflexivity. }
        all: reflexivity.
      }
      rewrite Hneq.
      inversion Hst.
      subst res s.
      exists st1'.
      split; [reflexivity | ].
      assumption.
  Qed.

End Equivalence_Theorem3.
Close Scope Z_scope.