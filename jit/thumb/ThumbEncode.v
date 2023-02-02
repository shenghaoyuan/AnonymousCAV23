From compcert Require Import Integers.

From Coq Require Import ZArith.

Definition encode_arm32 (v ins: int) (from size: nat): int :=
  Int.bitfield_insert (Z.of_nat from) (Z.of_nat size) ins v.