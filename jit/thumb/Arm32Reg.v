From compcert.lib Require Import Integers.
From compcert.arm Require Import AsmSyntax.

From bpf.comm Require Import Regs.

From Coq Require Import ZArith.

Definition ireg_eqb (r0 r1: ireg): bool :=
  match r0, r1 with
  | IR0, IR0
  | IR1, IR1
  | IR2, IR2
  | IR3, IR3
  | IR4, IR4
  | IR5, IR5
  | IR6, IR6
  | IR7, IR7
  | IR8, IR8
  | IR9, IR9
  | IR10, IR10
  | IR11, IR11
  | IR12, IR12
  | IR13, IR13
  | IR14, IR14 => true
  | _, _ => false
  end.

Definition reg_ireg_eqb (r0: reg) (r1: ireg): bool :=
  match r0, r1 with
  | R0, IR0
  | R1, IR1
  | R2, IR2
  | R3, IR3
  | R4, IR4
  | R5, IR5
  | R6, IR6
  | R7, IR7
  | R8, IR8
  | R9, IR9
  | R10, IR10 => true
  | _, _ => false
  end.


Definition reg_of_ireg (r: ireg): option reg :=
  match r with
  | IR0 => Some R0
  | IR1 => Some R1
  | IR2 => Some R2
  | IR3 => Some R3
  | IR4 => Some R4
  | IR5 => Some R5
  | IR6 => Some R6
  | IR7 => Some R7
  | IR8 => Some R8
  | IR9 => Some R9
  | IR10 => Some R10
  | IR11
  | IR12
  | IR13
  | IR14 => None
  end.

Definition ireg_of_reg (r: reg): ireg :=
  match r with
  | R0 => IR0
  | R1 => IR1
  | R2 => IR2
  | R3 => IR3
  | R4 => IR4
  | R5 => IR5
  | R6 => IR6
  | R7 => IR7
  | R8 => IR8
  | R9 => IR9
  | R10 => IR10
  end.


Definition ireg2nat (r: ireg): nat :=
  match r with
  | IR0 => 0
  | IR1 => 1
  | IR2 => 2
  | IR3 => 3
  | IR4 => 4
  | IR5 => 5
  | IR6 => 6
  | IR7 => 7
  | IR8 => 8
  | IR9 => 9
  | IR10 => 10
  | IR11 => 11
  | IR12 => 12
  | IR13 => 13
  | IR14 => 14
  end.

Definition int_of_ireg (r: ireg): int := Int.repr (Z.of_nat (ireg2nat r)).

Definition int16_of_ireg (r: ireg): int := Int.repr (Z.of_nat (ireg2nat r)).