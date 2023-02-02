From compcert Require Import Integers.

From Coq Require Import List ZArith Lia.
Open Scope Z_scope.

Lemma bitfield_insert_unsigned_bitfield_extract_same:
  forall i p v t pos width
    (Hrange: 0 <= pos /\ 0 < width /\ pos+width <= Int.zwordsize)
    (Hpre: Int.unsigned_bitfield_extract pos width p = v)
    (Hinsert: Int.bitfield_insert pos width i v = t),
      Int.unsigned_bitfield_extract pos width t = v.
Proof.
  intros.
  destruct Hrange as (Hrange0 & Hrange1 & Hrange2).
  subst.
  apply Int.same_bits_eq; intros.
  repeat rewrite Int.bits_unsigned_bitfield_extract; try lia.
  destruct Coqlib.zlt eqn: Hlt; [| reflexivity].
  rewrite Int.bits_bitfield_insert; try lia.
  unfold Coqlib.proj_sumbool.
  rewrite Coqlib.zle_true; [| lia].
  rewrite Coqlib.zlt_true; [| lia].
  simpl.
  rewrite Int.bits_unsigned_bitfield_extract; try lia.
  rewrite Z.add_simpl_r.
  rewrite Hlt.
  reflexivity.
Qed.


Lemma bitfield_insert_unsigned_bitfield_extract_same_outside:
  forall i p v t pos0 pos1 width0 width1
    (Hrange: pos0+width0 <= pos1 \/ pos1+width1 <= pos0)
    (Hrange0: 0 <= pos0 /\ 0 < width0 /\ pos0+width0 <= Int.zwordsize)
    (Hrange1: 0 <= pos1 /\ 0 < width1 /\ pos1+width1 <= Int.zwordsize)
    (Hpre: Int.unsigned_bitfield_extract pos1 width1 i = v)
    (Hinsert: Int.bitfield_insert pos0 width0 i p = t),
      Int.unsigned_bitfield_extract pos1 width1 t = v.
Proof.
  intros.
  destruct Hrange0 as (Hrange0_0 & Hrange0_1 & Hrange0_2).
  destruct Hrange1 as (Hrange1_0 & Hrange1_1 & Hrange1_2).
  subst.
  apply Int.same_bits_eq; intros.
  repeat rewrite Int.bits_unsigned_bitfield_extract; try lia.
  destruct Coqlib.zlt; [| reflexivity].
  rewrite Int.bits_bitfield_insert; try lia.
  unfold Coqlib.proj_sumbool.
  destruct Hrange as [Hrange | Hrange].
  - (**r pos0 + width0 <= pos1 *)
    rewrite Coqlib.zle_true; [| lia].
    rewrite Coqlib.zlt_false; [| lia].
    simpl.
    reflexivity.
  - (**r pos1 + width1 <= pos0 *)
    rewrite Coqlib.zle_false; [| lia].
    rewrite Coqlib.zlt_true; [| lia].
    simpl.
    reflexivity.
Qed.


Lemma unsigned_bitfield_extract_unsigned_bitfield_extract_zero_outside:
  forall i v pos0 pos1 width0 width1
    (Hrange: pos0+width0 <= pos1)
    (Hrange0: 0 <= pos0 /\ 0 < width0 /\ pos0+width0 <= Int.zwordsize)
    (Hrange1: 0 <= pos1 /\ 0 < width1 /\ pos1+width1 <= Int.zwordsize)
    (Hpre: Int.unsigned_bitfield_extract pos0 width0 i = v),
      Int.unsigned_bitfield_extract pos1 width1 v = Int.zero.
Proof.
  intros.
  destruct Hrange0 as (Hrange0_0 & Hrange0_1 & Hrange0_2).
  destruct Hrange1 as (Hrange1_0 & Hrange1_1 & Hrange1_2).
  subst.
  apply Int.same_bits_eq; intros.
  rewrite Int.bits_unsigned_bitfield_extract; try lia.
  destruct Coqlib.zlt; [| rewrite Int.bits_zero; reflexivity].

  rewrite Int.bits_unsigned_bitfield_extract; try lia.
  destruct Coqlib.zlt; rewrite Int.bits_zero; [lia | reflexivity].
Qed.

Lemma unsigned_bitfield_extract_range_low:
  forall i v pos width
    (Hrange: 0 <= pos /\ 0 < width /\ pos+width <= Int.zwordsize)
    (Hpre: Int.unsigned_bitfield_extract pos width i = v),
      0 <= Int.unsigned v <= (two_p width) - 1.
Proof.
  intros.
  destruct Hrange as (Hrange0 & Hrange1 & Hrange2).
  subst.
  split.
  - change 0 with (Int.unsigned Int.zero).
    apply Int.bits_le.
    intros.
    rewrite Int.bits_zero in *.
    intuition.
  - rewrite <- Int.unsigned_repr.
    + apply Int.bits_le.
      intros.
      rewrite Int.testbit_repr; [| assumption].
      rewrite Zbits.Ztestbit_two_p_m1; try lia.
      rewrite Int.bits_unsigned_bitfield_extract in H0; try lia.
      destruct Coqlib.zlt; lia.
    + assert (Hrange: 1 <= two_p width <= Int.modulus).
      * rewrite Int.modulus_power.
        split.
        { assert (Htwo_p:= Coqlib.two_p_strict width).
          assert (Hwidth: width >= 0) by lia.
          specialize (Htwo_p Hwidth).
          lia.
        }
        { apply Coqlib.two_p_monotone.
          lia.
        }
      * change Int.max_unsigned with 4294967295 in *.
        change Int.modulus with 4294967296 in *.
        lia.
Qed.

Lemma Int_unsigned_bitfield_extract_zero_ext_narrow:
  forall k m n v,
    0 <= m -> 0 <= k -> m + k <= n -> n <= 64 ->
    Int.unsigned_bitfield_extract k m (Int.zero_ext n v) = Int.unsigned_bitfield_extract k m v.
Proof.
  unfold Int.unsigned_bitfield_extract.
  intros.
  assert (Heq: n = n - k + Int.unsigned (Int.repr k)). {
    rewrite Int.unsigned_repr.
    lia.
    change Int.max_unsigned with 4294967295.
    lia.
  }
  rewrite Heq; clear Heq.
  rewrite Int.shru_zero_ext; [| lia].
  rewrite Int.zero_ext_narrow.
  reflexivity.
  lia.
Qed.