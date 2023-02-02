From compcert Require Import Integers.
From Coq Require Import ZArith.

Definition int_of_nat (n: nat) := Int.repr (Z.of_nat n).
Definition int16_of_nat (n: nat) := Int.repr (Z.of_nat n).
Definition nat_of_int (i: int) := Z.to_nat (Int.unsigned i).
Definition int64_of_nat (n: nat) := Int64.repr (Z.of_nat n).

Definition nat_1: nat := 1.
Definition nat_2: nat := 2.
Definition nat_3: nat := 3.
Definition nat_4: nat := 4.
Definition nat_7: nat := 7.
Definition nat_8: nat := 8.
Definition nat_10: nat := 10.
Definition nat_11: nat := 11.
Definition nat_12: nat := 12.
Definition nat_16: nat := 16.
Definition nat_24: nat := 24.
Definition nat_27: nat := 27.
Definition nat_28: nat := 28.
Definition nat_32: nat := 32.