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

From Coq Require Import List ZArith Lia.
Import ListNotations.

From compcert.cfrontend Require Csyntax Ctypes Cop.
From compcert Require Import Integers Values Maps Memtype Memory Memdata.

Open Scope Z_scope.

(** permission_eq_eq: permission_eq -> permission_eq -> bool
  *)

Definition perm_ge (x y: permission): bool := if (Mem.perm_order_dec x y) then true else false.

(** * Some extra  CompCert Coqlib lemmas *)

Lemma proj_sumbool_false:
  forall (P Q: Prop) (a: {P}+{Q}), Coqlib.proj_sumbool a = false -> Q.
Proof.
  intros.
  destruct a; simpl.
  simpl in *.
  inversion H.
  auto.
Qed.

Lemma proj_sumbool_is_false:
  forall (P Q: Prop) (a: {P}+{~P}), ~P -> Coqlib.proj_sumbool a = false.
Proof.
  intros.
  unfold Coqlib.proj_sumbool.
  destruct a; simpl.
  congruence.
  auto.
Qed.


(** * Some extra CompCert Memory lemmas *)

Lemma store_perm_iff:
  forall chunk m1 m2 b ofs addr b0 ofs0 k p
  (Hstore : Mem.store chunk m1 b ofs addr = Some m2),
      Mem.perm m1 b0 ofs0 k p <-> Mem.perm m2 b0 ofs0 k p.
Proof.
  intros.
  split; intro.
  - eapply Mem.perm_store_1 with (k:=k) (p:=p) in Hstore; eauto.
  - eapply Mem.perm_store_2 with (k:=k) (p:=p) in Hstore; eauto.
Qed.

(**r the proof code comes from MisakaCenter (QQ), thx *)
Lemma mem_get_in:
  forall l (n:nat) q c,
  lt n (List.length l) ->
    ZMap.get (q + (Z.of_nat n)) (Mem.setN l q c) = (nth_default Undef l n).
Proof.
  induction l; simpl in *; intros.
  lia.
  induction n; simpl.
  - unfold nth_default; simpl.
    rewrite Mem.setN_outside; try lia.
    rewrite Z.add_0_r.
    rewrite ZMap.gss; auto.
  - assert (Heq: nth_default Undef (a::l) (S n) = nth_default Undef l n) by auto.
    rewrite Heq; clear Heq.
    rewrite <- IHl with (q := q+1) (c:=ZMap.set q a c).
    assert (Heq: q + Z.pos (Pos.of_succ_nat n) = q + 1 + Z.of_nat n) by lia.
    rewrite Heq; clear Heq.
    reflexivity.
    lia.
Qed.

Lemma store_range_perm:
  forall chunk m1 m2 b0 b1 ofs addr low high k p
    (Hblk_neq: b0 <> b1)
    (Hstore : Mem.store chunk m1 b0 ofs addr = Some m2)
    (Hrange_perm : Mem.range_perm m1 b1 low high k p),
      Mem.range_perm m2 b1 low high k p.
Proof.
  intros.
  unfold Mem.range_perm in *.
  intros.
  specialize (Hrange_perm ofs0 H).
  eapply Mem.perm_store_1; eauto.
Qed.

Lemma store_valid_access_None:
  forall chunk m b ofs v,
  Mem.store chunk m b ofs v = None <-> ~ Mem.valid_access m chunk b ofs Writable.
Proof.
  intros.
  Global Transparent Mem.store.
  unfold Mem.store.
  destruct Mem.valid_access_dec eqn: Hdec.
  intuition.
  inversion H.

  intuition.
Qed.

Lemma unchanged_on_store_None:
  forall P m0 m1 chunk b ofs v
    (Hunchanged_on : Mem.unchanged_on P m0 m1)
    (Hvalid_block_implies : Mem.valid_block m1 b -> Mem.valid_block m0 b)
    (Hprop: forall i, ofs <= i < ofs + size_chunk chunk -> P b i),
      Mem.store chunk m0 b ofs v = None <-> Mem.store chunk m1 b ofs v = None.
Proof.
  intros.
  repeat rewrite store_valid_access_None.

  split; intros Hinvalid HF; apply Hinvalid; clear Hinvalid;
    unfold Mem.valid_access in *; destruct HF as (Hrange & HF).
  - split; [clear HF | assumption].
    unfold Mem.range_perm in *.
    intros.
    specialize (Hrange ofs0 H).
    eapply Mem.perm_unchanged_on_2; eauto.
    apply Hvalid_block_implies.
    eapply Mem.perm_valid_block; eauto.
  - split; [clear HF | assumption].
    unfold Mem.range_perm in *.
    intros.
    specialize (Hrange ofs0 H).
    eapply Mem.perm_unchanged_on; eauto.
Qed.

Lemma unchanged_on_valid_pointer:
  forall P m0 m1 b ofs
    (Hunchanged_on : Mem.unchanged_on P m0 m1)
    (Hvalid: Mem.valid_block m0 b)
    (Hprop: forall i, ofs <= i < ofs + 1 -> P b i),
    Mem.valid_pointer m0 b ofs =
    Mem.valid_pointer m1 b ofs.
Proof.
  intros.
  destruct Mem.valid_pointer eqn: Hvptr.
  - symmetry.
    rewrite Mem.valid_pointer_valid_access in *.
    unfold Mem.valid_access in *.
    intuition.
    clear H0.
    unfold Mem.range_perm in *.
    intros.
    specialize (H ofs0 H0).
    eapply Mem.perm_unchanged_on; eauto.
  - symmetry.
    rewrite <- Bool.not_true_iff_false in *.
    intro Hf.
    apply Hvptr.
    rewrite Mem.valid_pointer_valid_access in *.
    unfold Mem.valid_access in *.
    intuition.
    clear H0 H1.
    unfold Mem.range_perm in *.
    intros.
    specialize (H ofs0 H0).
    eapply Mem.perm_unchanged_on_2; eauto.
Qed.

Lemma store_store_same_block:
  forall m m0 m1 m2 chunk b ofs addr
    (Hstore : Mem.store chunk m b ofs addr = Some m0)
    (Hstore_m2 : Mem.store chunk m1 b ofs addr = Some m2)
    (Hunchanged_on_contents :
        ZMap.get ofs (PMap.get b (Mem.mem_contents m1)) =
        ZMap.get ofs (PMap.get b (Mem.mem_contents m))),
      ZMap.get ofs (PMap.get b (Mem.mem_contents m2)) =
      ZMap.get ofs (PMap.get b (Mem.mem_contents m0)).
Proof.
  intros.
  apply Mem.store_mem_contents in Hstore as Hcontents0; auto.
  apply Mem.store_mem_contents in Hstore_m2 as Hcontents1; auto.
  rewrite Hcontents0, Hcontents1.
  repeat rewrite PMap.gss.
  clear - Hunchanged_on_contents.
  generalize (encode_val chunk addr).
  intros.
  destruct l.
  - simpl.
    assumption.
  - simpl.
    rewrite Mem.setN_other; [|intros; lia].
    rewrite Mem.setN_other; [|intros; lia].
    repeat rewrite ZMap.gss.
    reflexivity.
Qed.

Lemma store_store_same_block_other:
  forall m m0 m1 m2 chunk b ofs ofs0 addr
    (Hstore : Mem.store chunk m b ofs addr = Some m0)
    (Hstore_m2 : Mem.store chunk m1 b ofs addr = Some m2)
    (Hother: ofs < ofs0 < ofs + size_chunk chunk)
    (Hunchanged_on_contents :
      ZMap.get ofs0 (PMap.get b (Mem.mem_contents m1)) =
      ZMap.get ofs0 (PMap.get b (Mem.mem_contents m))),
      ZMap.get ofs0 (PMap.get b (Mem.mem_contents m2)) =
      ZMap.get ofs0 (PMap.get b (Mem.mem_contents m0)).
Proof.
  intros.
  apply Mem.store_mem_contents in Hstore as Hcontents0; auto.
  apply Mem.store_mem_contents in Hstore_m2 as Hcontents1; auto.
  rewrite Hcontents0, Hcontents1.
  repeat rewrite PMap.gss.

  assert (Hlen: List.length (encode_val chunk addr) = size_chunk_nat chunk) by apply encode_val_length.
  revert Hlen.
  generalize (encode_val chunk addr).
  unfold size_chunk_nat.
  intros.
  assert (Hofs0_eq: exists n, 0 < Z.of_nat n < size_chunk chunk /\ ofs0 = ofs+ Z.of_nat n). {
    clear - Hother.
    assert (Heq: Z.of_nat (Z.to_nat (ofs0 - ofs)) = ofs0 - ofs). {
      rewrite Z2Nat.id.
      reflexivity.
      lia.
    }
    exists (Z.to_nat(ofs0 - ofs)).
    lia.
  }
  destruct Hofs0_eq as (z & Hz_range & Hofs0_eq); subst.
  repeat rewrite mem_get_in.
  reflexivity.
  lia.
  lia.
Qed.

Lemma store_store_other_block_same:
  forall m m0 m1 m2 chunk b ofs addr
    (Hstore : Mem.store chunk m b ofs addr = Some m0)
    (Hstore_m2 : Mem.store chunk m1 b ofs addr = Some m2),
    forall b0 ofs0
    (Hother: b0 <> b \/ ofs0 < ofs \/ ofs + size_chunk chunk <= ofs0)
    (Hunchanged_on_contents :
      ZMap.get ofs0 (PMap.get b0 (Mem.mem_contents m1)) =
      ZMap.get ofs0 (PMap.get b0 (Mem.mem_contents m))),
      ZMap.get ofs0 (PMap.get b0 (Mem.mem_contents m2)) =
      ZMap.get ofs0 (PMap.get b0 (Mem.mem_contents m0)).
Proof.
  intros.
  apply Mem.store_mem_contents in Hstore as Hcontents0; auto.
  apply Mem.store_mem_contents in Hstore_m2 as Hcontents1; auto.
  rewrite Hcontents0, Hcontents1.
  destruct (b0 =? b)%positive eqn: Hblk_eq; [rewrite Pos.eqb_eq in Hblk_eq | rewrite Pos.eqb_neq in Hblk_eq].
  - subst.
    repeat rewrite PMap.gss.
    destruct Hother as [Hfalse | Hother]; [intuition|].
    repeat rewrite Mem.setN_outside.
    + assumption.
    + rewrite encode_val_length.
      unfold size_chunk_nat, size_chunk.
      unfold size_chunk in Hother.
      destruct Hother as [Hle | Hge].
      * left.
        lia.
      * right.
        destruct chunk; lia.
    + rewrite encode_val_length.
      unfold size_chunk_nat, size_chunk.
      unfold size_chunk in Hother.
      destruct Hother as [Hle | Hge].
      * left.
        lia.
      * right.
        destruct chunk; lia.
  - repeat (rewrite PMap.gso; [| lia]).
    assumption.
Qed.

Lemma load_valid_block:
  forall m chunk b ofs v
    (Hload: Mem.load chunk m b ofs = Some v),
      Mem.valid_block m b.
Proof.
  intros.
  eapply Mem.load_valid_access in Hload.
  assert (HNonempty: Mem.valid_access m chunk b ofs Nonempty). {
    eapply Mem.valid_access_implies; [apply Hload | ].
    constructor.
  }
  eapply Mem.valid_access_valid_block.
  apply HNonempty.
Qed.

Lemma store_unchanged_on_2:
  forall m0 m1 m2 m3 chunk b ofs v b1
  (Hblk_neq: b <> b1)
  (Hunchanged : Mem.unchanged_on (fun (b : block) (_ : Z) => b <> b1) m0 m1)
  (Hstore0 : Mem.store chunk m0 b ofs v = Some m2)
  (Hstore1 : Mem.store chunk m1 b ofs v = Some m3),
    Mem.unchanged_on (fun (b : block) (_ : Z) => b <> b1) m2 m3.
Proof.
  intros.
  assert (Hr := Hunchanged).
  destruct Hr.
  split.
  - (**r unchanged_on_nextblock *)
    apply Mem.nextblock_store in Hstore0, Hstore1.
    rewrite Hstore0, Hstore1.
    assumption.
  - (**r unchanged_on_perm *)
    intros.
    eapply Mem.store_valid_block_2 in Hstore0 as Hvalid_block; [ | apply H0].
    specialize (unchanged_on_perm b0 ofs0 k p H Hvalid_block).
    split; intro Hperm.
    + eapply Mem.perm_store_1; [apply Hstore1 | ].
      eapply Mem.perm_store_2 in Hperm; [ | apply Hstore0].
      eapply Mem.perm_unchanged_on; eauto.
    + eapply Mem.perm_store_1; [apply Hstore0 | ].
      eapply Mem.perm_store_2 in Hperm; [ | apply Hstore1].
      eapply Mem.perm_unchanged_on_2; eauto.
  - (**r unchanged_on_contents *)
    intros.
    eapply Mem.perm_store_2 in Hstore0 as Hperm; [ | apply H0].
    specialize (unchanged_on_contents b0 ofs0 H Hperm).
    destruct (b0 =? b)%positive eqn: Hblk_eq;
      [rewrite Pos.eqb_eq in Hblk_eq | rewrite Pos.eqb_neq in Hblk_eq].
    + subst b0.
      destruct (ofs0 =? ofs)%Z eqn: Hofs_eq;
        [rewrite Z.eqb_eq in Hofs_eq | rewrite Z.eqb_neq in Hofs_eq].
      * subst ofs0.
        eapply store_store_same_block; eauto.
      *
        assert (Hofs_cases:
          (ofs < ofs0 < ofs + size_chunk chunk)%Z \/
          (ofs0 < ofs \/ ofs + size_chunk chunk <= ofs0)%Z) by lia.
        destruct Hofs_cases as [Hcase0 | Hcase1].
        {
          eapply store_store_same_block_other; eauto.
        }
        {
          eapply store_store_other_block_same; eauto.
        }
    + eapply store_store_other_block_same; eauto.
Qed.

Lemma unchanged_on_valid_access:
  forall (P : block -> Z -> Prop) m0 m1 chunk b ofs perm
    (Hblk_neq : forall ofs0, (ofs <= ofs0 < ofs + size_chunk chunk)%Z -> P b ofs0)
    (Hunchanged : Mem.unchanged_on P m0 m1)
    (Haccess : Mem.valid_access m0 chunk b ofs perm),
      Mem.valid_access m1 chunk b ofs perm.
Proof.
  intros.
  unfold Mem.valid_access in *.
  destruct Haccess as (Haccess & Halign).
  split; [clear Halign | assumption].
  unfold Mem.range_perm in *.
  intros.
  specialize (Haccess ofs0 H).
  eapply Mem.perm_unchanged_on; eauto.
Qed.

Lemma unchanged_on_store:
  forall (P : block -> Z -> Prop) m0 m1 m2 chunk b ofs v
  (Hblk_neq: forall ofs0, (ofs <= ofs0 < ofs + size_chunk chunk)%Z -> P b ofs0)
  (Hunchanged : Mem.unchanged_on P m0 m1)
  (Hstore0 : Mem.store chunk m0 b ofs v = Some m2),
    exists m3, Mem.store chunk m1 b ofs v = Some m3.
Proof.
  intros.
  assert (Hvalid: Mem.valid_access m1 chunk b ofs Writable). {
    eapply Mem.store_valid_access_3 in Hstore0 as Haccess.
    eapply unchanged_on_valid_access; eauto.
  }
  eapply Mem.valid_access_store in Hvalid; eauto.
  destruct Hvalid as (m3 & Hstore1).
  exists m3.
  apply Hstore1.
Qed.

Lemma valid_pointer_implies_valid_block:
  forall m b ofs
  (Hvalid : Mem.valid_pointer m b ofs = true),
    Mem.valid_block m b.
Proof.
  intros.
  apply Mem.valid_pointer_valid_access in Hvalid.
  eapply Mem.valid_access_valid_block; eauto.
Qed.
