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

From Coq Require Import List.
Import ListNotations.

From dx Require Import ResultMonad IR.
From dx.Type Require Import Bool.

From bpf.comm Require Import Flag.
From bpf.dxcomm Require Import CoqIntegers DxIntegers DxValues.

(******************** Dx Related *******************)

(** bpf_flag -> sint32_t *)


Definition flagCompilableType :=
  MkCompilableType bpf_flag C_U32.

Definition flagSymboalType :=
  MkCompilableSymbolType nil (Some flagCompilableType).

Definition Const_BPF_SUCC_RETURN         := constant flagSymboalType BPF_SUCC_RETURN C_U32_one.          (**r = 1, *)
Definition Const_BPF_OK                  := constant flagSymboalType BPF_OK C_U32_zero.                  (**r = 0, *)
Definition Const_BPF_ILLEGAL_INSTRUCTION := constant flagSymboalType BPF_ILLEGAL_INSTRUCTION C_U32_2.    (**r = 2, *)
Definition Const_BPF_ILLEGAL_MEM         := constant flagSymboalType BPF_ILLEGAL_MEM C_U32_3.            (**r = 3, *)
Definition Const_BPF_ILLEGAL_JUMP        := constant flagSymboalType BPF_ILLEGAL_JUMP C_U32_4.           (**r = 4, *)
Definition Const_BPF_ILLEGAL_CALL        := constant flagSymboalType BPF_ILLEGAL_CALL C_U32_5.           (**r = 5, *)
Definition Const_BPF_ILLEGAL_LEN         := constant flagSymboalType BPF_ILLEGAL_LEN C_U32_6.            (**r = 6, *)
Definition Const_BPF_ILLEGAL_REGISTER    := constant flagSymboalType BPF_ILLEGAL_REGISTER C_U32_7.       (**r = 7  *)
Definition Const_BPF_NO_RETURN           := constant flagSymboalType BPF_NO_RETURN C_U32_8.              (**r = 8, *)
Definition Const_BPF_OUT_OF_BRANCHES     := constant flagSymboalType BPF_OUT_OF_BRANCHES C_U32_9.        (**r = 9, *)
Definition Const_BPF_ILLEGAL_DIV         := constant flagSymboalType BPF_ILLEGAL_DIV C_U32_10.           (**r = 10,*)
Definition Const_BPF_ILLEGAL_SHIFT       := constant flagSymboalType BPF_ILLEGAL_SHIFT C_U32_11.         (**r = 11,*)
Definition Const_BPF_ILLEGAL_ALU         := constant flagSymboalType BPF_ILLEGAL_ALU C_U32_12.           (**r = 12,*)
Definition Const_BPF_ILLEGAL_JIT         := constant flagSymboalType BPF_ILLEGAL_JIT C_U32_13.           (**r = 13,*)
Definition Const_BPF_ILLEGAL_ARM_LEN     := constant flagSymboalType BPF_ILLEGAL_ARM_LEN C_U32_14.       (**r = 14,*)
Definition Const_BPF_ILLEGAL_EP_LEN       := constant flagSymboalType BPF_ILLEGAL_EP_LEN C_U32_15.       (**r = 15,*)

Definition flagToflagToboolSymbolType :=
  MkCompilableSymbolType [flagCompilableType; flagCompilableType] (Some boolCompilableType).

Definition Const_flag_eq :=
  MkPrimitive flagToflagToboolSymbolType
                flag_eq
                (fun es => match es with
                           | [f1; f2] => Ok (Csyntax.Ebinop Cop.Oeq f1 f2 C_U32)
                           | _       => Err PrimitiveEncodingFailed
                           end).

Definition flagTouint32SymbolType :=
  MkCompilableSymbolType [flagCompilableType] (Some uint32CompilableType).

Definition Const_int_of_flag :=
  MkPrimitive flagTouint32SymbolType
                int_of_flag
                (fun es => match es with
                           | [f1] => Ok f1
                           | _       => Err PrimitiveEncodingFailed
                           end).

Definition flagTovalu32SymbolType :=
  MkCompilableSymbolType [flagCompilableType] (Some valU32CompilableType).

Definition Const_val_of_flag :=
  MkPrimitive flagTovalu32SymbolType
                val_of_flag
                (fun es => match es with
                           | [f1] => Ok f1
                           | _       => Err PrimitiveEncodingFailed
                           end).


Module Exports.
  Definition flagCompilableType            := flagCompilableType.
  Definition Const_BPF_SUCC_RETURN         := Const_BPF_SUCC_RETURN.
  Definition Const_BPF_OK                  := Const_BPF_OK.
  Definition Const_BPF_ILLEGAL_INSTRUCTION := Const_BPF_ILLEGAL_INSTRUCTION.
  Definition Const_BPF_ILLEGAL_MEM         := Const_BPF_ILLEGAL_MEM.
  Definition Const_BPF_ILLEGAL_JUMP        := Const_BPF_ILLEGAL_JUMP.
  Definition Const_BPF_ILLEGAL_CALL        := Const_BPF_ILLEGAL_CALL.
  Definition Const_BPF_ILLEGAL_LEN         := Const_BPF_ILLEGAL_LEN.
  Definition Const_BPF_ILLEGAL_REGISTER    := Const_BPF_ILLEGAL_REGISTER.
  Definition Const_BPF_NO_RETURN           := Const_BPF_NO_RETURN.
  Definition Const_BPF_OUT_OF_BRANCHES     := Const_BPF_OUT_OF_BRANCHES.
  Definition Const_BPF_ILLEGAL_DIV         := Const_BPF_ILLEGAL_DIV.
  Definition Const_BPF_ILLEGAL_SHIFT       := Const_BPF_ILLEGAL_SHIFT.
  Definition Const_BPF_ILLEGAL_ALU         := Const_BPF_ILLEGAL_ALU.
  Definition Const_BPF_ILLEGAL_JIT         := Const_BPF_ILLEGAL_JIT.
  Definition Const_BPF_ILLEGAL_ARM_LEN     := Const_BPF_ILLEGAL_ARM_LEN.
  Definition Const_BPF_ILLEGAL_EP_LEN      := Const_BPF_ILLEGAL_EP_LEN.
  Definition Const_flag_eq                 := Const_flag_eq.
  Definition Const_int_of_flag             := Const_int_of_flag.
  Definition Const_val_of_flag             := Const_val_of_flag.
End Exports.