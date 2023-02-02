From compcert.cfrontend Require Csyntax Ctypes Cop.
From compcert.common Require Values Memory.
From compcert.lib Require Import Integers.
From compcert.arm Require Import AsmSyntax.

From dx Require Import ResultMonad IR.
From dx.Type Require Import Bool Nat.

From bpf.dxcomm Require Import CoqIntegers DxIntegers DxValues.
From bpf.dxmodel Require Import DxRegs.
From bpf.jit.thumb Require Import Arm32Reg.

From Coq Require Import List ZArith.
Import ListNotations.

Definition iregCompilableType :=
  MkCompilableType ireg C_U32.

Definition iregSymbolType :=
  MkCompilableSymbolType nil (Some iregCompilableType).

Definition Const_IR0 := constant iregSymbolType IR0 C_U32_zero.

Definition Const_IR1 := constant iregSymbolType IR1 C_U32_one.

Definition Const_IR2 := constant iregSymbolType IR2 C_U32_2.

Definition Const_IR3 := constant iregSymbolType IR3 C_U32_3.

Definition Const_IR4 := constant iregSymbolType IR4 C_U32_4.

Definition Const_IR5 := constant iregSymbolType IR5 C_U32_5.

Definition Const_IR6 := constant iregSymbolType IR6 C_U32_6.

Definition Const_IR7 := constant iregSymbolType IR7 C_U32_7.

Definition Const_IR8 := constant iregSymbolType IR8 C_U32_8.

Definition Const_IR9 := constant iregSymbolType IR9 C_U32_9.

Definition Const_IR10 := constant iregSymbolType IR10 C_U32_10.

Definition Const_IR11 := constant iregSymbolType IR11 C_U32_11.

Definition Const_IR12 := constant iregSymbolType IR12 C_U32_12.

Definition Const_IR13 := constant iregSymbolType IR13 C_U32_13.

Definition Const_IR14 := constant iregSymbolType IR14 C_U32_14.

Definition iregToiregToboolSymbolType :=
  MkCompilableSymbolType [iregCompilableType; iregCompilableType] (Some boolCompilableType).

Definition Const_ireg_eqb :=
  MkPrimitive iregToiregToboolSymbolType
                ireg_eqb
                (fun es => match es with
                           | [r0; r1] => Ok ( Csyntax.Ebinop Cop.Oeq r0 r1 C_U32)
                           | _       => Err PrimitiveEncodingFailed
                           end).

Definition iregTonatSymbolType :=
  MkCompilableSymbolType [iregCompilableType] (Some natCompilableType).

Definition Const_ireg2nat :=
  MkPrimitive iregTonatSymbolType
                ireg2nat
                (fun es => match es with
                           | [r] => Ok (r)
                           | _       => Err PrimitiveEncodingFailed
                           end).

Definition iregTointSymbolType :=
  MkCompilableSymbolType [iregCompilableType] (Some uint32CompilableType).

Definition Const_int_of_ireg :=
  MkPrimitive iregTointSymbolType
                int_of_ireg
                (fun es => match es with
                           | [r] => Ok (r)
                           | _       => Err PrimitiveEncodingFailed
                           end).

Definition iregToint16SymbolType :=
  MkCompilableSymbolType [iregCompilableType] (Some uint16CompilableType).

Definition Const_int16_of_ireg :=
  MkPrimitive iregToint16SymbolType
                int16_of_ireg
                (fun es => match es with
                           | [r] => Ok (r)
                           | _       => Err PrimitiveEncodingFailed
                           end).

Definition regToiregSymbolType :=
  MkCompilableSymbolType [regCompilableType] (Some iregCompilableType).

Definition Const_ireg_of_reg :=
  MkPrimitive regToiregSymbolType
                ireg_of_reg
                (fun es => match es with
                           | [r] => Ok r
                           | _       => Err PrimitiveEncodingFailed
                           end).

Definition regToiregToboolSymbolType :=
  MkCompilableSymbolType [regCompilableType; iregCompilableType] (Some boolCompilableType).

Definition Const_reg_ireg_eqb :=
  MkPrimitive regToiregToboolSymbolType
                reg_ireg_eqb
                (fun es => match es with
                           | [r0; r1] => Ok ( Csyntax.Ebinop Cop.Oeq r0 r1 C_U32)
                           | _       => Err PrimitiveEncodingFailed
                           end).



Close Scope Z_scope.

Module Exports.
  Definition iregCompilableType     := iregCompilableType.
  Definition Const_IR0              := Const_IR0.
  Definition Const_IR1              := Const_IR1.
  Definition Const_IR2              := Const_IR2.
  Definition Const_IR3              := Const_IR3.
  Definition Const_IR4              := Const_IR4.
  Definition Const_IR5              := Const_IR5.
  Definition Const_IR6              := Const_IR6.
  Definition Const_IR7              := Const_IR7.
  Definition Const_IR8              := Const_IR8.
  Definition Const_IR9              := Const_IR9.
  Definition Const_IR10             := Const_IR10.
  Definition Const_IR11             := Const_IR11.
  Definition Const_IR12             := Const_IR12.
  Definition Const_IR13             := Const_IR13.
  Definition Const_IR14             := Const_IR14.
  Definition Const_ireg_eqb         := Const_ireg_eqb.
  Definition Const_ireg2nat         := Const_ireg2nat.
  Definition Const_int_of_ireg      := Const_int_of_ireg.
  Definition Const_int16_of_ireg    := Const_int16_of_ireg.
  Definition Const_ireg_of_reg      := Const_ireg_of_reg.
  Definition Const_reg_ireg_eqb     := Const_reg_ireg_eqb.
End Exports.