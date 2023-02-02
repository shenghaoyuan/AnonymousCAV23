Require Import List.
Import ListNotations.

From compcert.cfrontend Require Csyntax Ctypes Cop.
From compcert Require Import Integers Values.

From dx Require Import ResultMonad IR.
From dx.Type Require Import Bool Nat.

From bpf.dxcomm Require Import CoqIntegers DxIntegers.
From bpf.jit.monadicJIT Require Import JITNat.

From Coq Require Import ZArith.

Open Scope nat_scope.

Definition C_NAT_1: Csyntax.expr :=
  Csyntax.Eval (Vint (Int.repr (Z.of_nat 1))) C_U32.

Definition C_NAT_2: Csyntax.expr :=
  Csyntax.Eval (Vint (Int.repr (Z.of_nat 2))) C_U32.

Definition C_NAT_3: Csyntax.expr :=
  Csyntax.Eval (Vint (Int.repr (Z.of_nat 3))) C_U32.

Definition C_NAT_4: Csyntax.expr :=
  Csyntax.Eval (Vint (Int.repr (Z.of_nat 4))) C_U32.

Definition C_NAT_7: Csyntax.expr :=
  Csyntax.Eval (Vint (Int.repr (Z.of_nat 7))) C_U32.

Definition C_NAT_8: Csyntax.expr :=
  Csyntax.Eval (Vint (Int.repr (Z.of_nat 8))) C_U32.

Definition C_NAT_10: Csyntax.expr :=
  Csyntax.Eval (Vint (Int.repr (Z.of_nat 10))) C_U32.

Definition C_NAT_11: Csyntax.expr :=
  Csyntax.Eval (Vint (Int.repr (Z.of_nat 11))) C_U32.

Definition C_NAT_12: Csyntax.expr :=
  Csyntax.Eval (Vint (Int.repr (Z.of_nat 12))) C_U32.

Definition C_NAT_16: Csyntax.expr :=
  Csyntax.Eval (Vint (Int.repr (Z.of_nat 16))) C_U32.

Definition C_NAT_24: Csyntax.expr :=
  Csyntax.Eval (Vint (Int.repr (Z.of_nat 24))) C_U32.

Definition C_NAT_27: Csyntax.expr :=
  Csyntax.Eval (Vint (Int.repr (Z.of_nat 27))) C_U32.

Definition C_NAT_28: Csyntax.expr :=
  Csyntax.Eval (Vint (Int.repr (Z.of_nat 28))) C_U32.

Definition C_NAT_32: Csyntax.expr :=
  Csyntax.Eval (Vint (Int.repr (Z.of_nat 32))) C_U32.

Definition Const_NAT_1        := constant natSymbolType nat_1     C_NAT_1.
Definition Const_NAT_2        := constant natSymbolType nat_2     C_NAT_2.
Definition Const_NAT_3        := constant natSymbolType nat_3     C_NAT_3.
Definition Const_NAT_4        := constant natSymbolType nat_4     C_NAT_4.
Definition Const_NAT_7        := constant natSymbolType nat_7     C_NAT_7.
Definition Const_NAT_8        := constant natSymbolType nat_8     C_NAT_8.
Definition Const_NAT_10       := constant natSymbolType nat_10    C_NAT_10.
Definition Const_NAT_11       := constant natSymbolType nat_11    C_NAT_11.
Definition Const_NAT_12       := constant natSymbolType nat_12    C_NAT_12.
Definition Const_NAT_16       := constant natSymbolType nat_16    C_NAT_16.
Definition Const_NAT_24       := constant natSymbolType nat_24    C_NAT_24.
Definition Const_NAT_27       := constant natSymbolType nat_27    C_NAT_27.
Definition Const_NAT_28       := constant natSymbolType nat_28    C_NAT_28.
Definition Const_NAT_32       := constant natSymbolType nat_32    C_NAT_32.

Definition natTouint32SymbolType :=
  MkCompilableSymbolType [natCompilableType] (Some uint32CompilableType).

Definition Const_int_of_nat :=
  MkPrimitive natTouint32SymbolType
                int_of_nat
                (fun es => match es with
                           | [e1] => Ok (e1)
                           | _       => Err PrimitiveEncodingFailed
                           end).

Definition natTouint16SymbolType :=
  MkCompilableSymbolType [natCompilableType] (Some uint16CompilableType).

Definition Const_int16_of_nat :=
  MkPrimitive natTouint16SymbolType
                int16_of_nat
                (fun es => match es with
                           | [e1] => Ok (e1)
                           | _       => Err PrimitiveEncodingFailed
                           end).

Definition natToint64SymbolType :=
  MkCompilableSymbolType [natCompilableType] (Some int64CompilableType).

Definition Const_int64_of_nat :=
  MkPrimitive natToint64SymbolType
                int64_of_nat
                (fun es => match es with
                           | [e1] => Ok (Csyntax.Ecast e1 C_U64)
                           | _       => Err PrimitiveEncodingFailed
                           end).

Definition uint32TonatSymbolType :=
  MkCompilableSymbolType [uint32CompilableType] (Some natCompilableType).

Definition Const_nat_of_int :=
  MkPrimitive uint32TonatSymbolType
                nat_of_int
                (fun es => match es with
                           | [e1] => Ok (e1)
                           | _       => Err PrimitiveEncodingFailed
                           end).

Definition natTonatTonatSymbolType :=
  MkCompilableSymbolType [natCompilableType; natCompilableType] (Some natCompilableType).

Definition C_NAT_add (x y: Csyntax.expr): Csyntax.expr :=
  Csyntax.Ebinop Cop.Oadd x y C_U32.

Definition Const_nat_add :=
  MkPrimitive natTonatTonatSymbolType
                Nat.add
                (fun es => match es with
                           | [e1;e2] => Ok (C_NAT_add e1 e2)
                           | _       => Err PrimitiveEncodingFailed
                           end).

Definition C_NAT_mul (x y: Csyntax.expr): Csyntax.expr :=
  Csyntax.Ebinop Cop.Omul x y C_U32.

Definition Const_nat_mul :=
  MkPrimitive natTonatTonatSymbolType
                Nat.mul
                (fun es => match es with
                           | [e1;e2] => Ok (C_NAT_mul e1 e2)
                           | _       => Err PrimitiveEncodingFailed
                           end).

Definition C_NAT_div (x y: Csyntax.expr): Csyntax.expr :=
  Csyntax.Ebinop Cop.Odiv x y C_U32.

Definition Const_nat_div :=
  MkPrimitive natTonatTonatSymbolType
                Nat.div
                (fun es => match es with
                           | [e1;e2] => Ok (C_NAT_div e1 e2)
                           | _       => Err PrimitiveEncodingFailed
                           end).

Close Scope nat_scope.

Module Exports.
  Definition Const_NAT_1        := Const_NAT_1.
  Definition Const_NAT_2        := Const_NAT_2.
  Definition Const_NAT_3        := Const_NAT_3.
  Definition Const_NAT_4        := Const_NAT_4.
  Definition Const_NAT_7        := Const_NAT_7.
  Definition Const_NAT_8        := Const_NAT_8.
  Definition Const_NAT_10       := Const_NAT_10.
  Definition Const_NAT_11       := Const_NAT_11.
  Definition Const_NAT_12       := Const_NAT_12.
  Definition Const_NAT_16       := Const_NAT_16.
  Definition Const_NAT_24       := Const_NAT_24.
  Definition Const_NAT_27       := Const_NAT_27.
  Definition Const_NAT_28       := Const_NAT_28.
  Definition Const_NAT_32       := Const_NAT_32.
  Definition Const_int_of_nat   := Const_int_of_nat.
  Definition Const_int16_of_nat := Const_int16_of_nat.
  Definition Const_int64_of_nat := Const_int64_of_nat.
  Definition Const_nat_of_int   := Const_nat_of_int.
  Definition Const_nat_add      := Const_nat_add.
  Definition Const_nat_mul      := Const_nat_mul.
  Definition Const_nat_div      := Const_nat_div.
End Exports.