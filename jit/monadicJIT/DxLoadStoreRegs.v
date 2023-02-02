From compcert.cfrontend Require Csyntax Ctypes Cop.
From compcert.common Require Values Memory.
From compcert.lib Require Import Integers.

From dx Require Import ResultMonad IR.
From dx.Type Require Import Bool Nat.

From bpf.comm Require Import Regs.
From bpf.dxcomm Require Import CoqIntegers DxIntegers DxValues.
From bpf.dxmodel Require Import DxRegs.
From bpf.jit.thumb Require Import LoadStoreRegs.

From Coq Require Import List ZArith.
Import ListNotations.


Definition LoadStorePermCompilableType :=
  MkCompilableType LoadStorePerm C_U32.

Definition LoadStorePermSymboalType :=
  MkCompilableSymbolType nil (Some LoadStorePermCompilableType).

Definition Const_NonPerm      := constant LoadStorePermSymboalType NonPerm C_U32_zero.   (**r = 0, *)
Definition Const_LoadPerm     := constant LoadStorePermSymboalType LoadPerm C_U32_one.  (**r = 1, *)
Definition Const_StorePerm    := constant LoadStorePermSymboalType StorePerm C_U32_2.    (**r = 2, *)
Definition Const_LoadAndStore := constant LoadStorePermSymboalType LoadAndStore C_U32_3. (**r = 3, *)

Definition LoadStorePermToLoadStorePermToboolSymbolType :=
  MkCompilableSymbolType [LoadStorePermCompilableType; LoadStorePermCompilableType] (Some boolCompilableType).

Definition Const_LoadStorePerm_eqb :=
  MkPrimitive LoadStorePermToLoadStorePermToboolSymbolType
                LoadStorePerm_eqb
                (fun es => match es with
                           | [f1; f2] => Ok (Csyntax.Ebinop Cop.Oeq f1 f2 C_U32)
                           | _       => Err PrimitiveEncodingFailed
                           end).

Definition C_loadstoreregs: Ctypes.type := Ctypes.Tarray C_U32 11%Z Ctypes.noattr.

Definition loadstoreregsCompilableType := MkCompilableType LoadStoreRegs C_loadstoreregs.

Definition regToLoadStorePermToboolSymbolType :=
  MkCompilableSymbolType [regCompilableType; LoadStorePermCompilableType] (Some boolCompilableType).
(*
Definition Const_is_load_reg :=
  MkPrimitive regToLoadStorePermToboolSymbolType
                is_load_reg
                (fun es => match es with
                           | [f1; f2] => Ok (Csyntax.Ebinop Cop.Oor
                                              (Csyntax.Ebinop Cop.Oeq (Csyntax.Efield  C_loadstoreregs) C_U32_one C_U32)
                                              (Csyntax.Ebinop Cop.Oeq f1 C_U32_3 C_U32)
                                              C_U32)
                           | _       => Err PrimitiveEncodingFailed
                           end).

Definition is_load_reg (r: reg) (ls: LoadStoreRegs) : bool :=
  let perm := eval_LoadStoreRegs ls r in
    if LoadStorePerm_eqb perm LoadPerm then
      true
    else if LoadStorePerm_eqb perm LoadAndStore then
      true
    else
      false. *)




Module Exports.
  Definition LoadStorePermCompilableType  := LoadStorePermCompilableType.
  Definition Const_NonPerm                := Const_NonPerm.
  Definition Const_LoadPerm               := Const_LoadPerm.
  Definition Const_StorePerm              := Const_StorePerm.
  Definition Const_LoadAndStore           := Const_LoadAndStore.
  Definition Const_LoadStorePerm_eqb      := Const_LoadStorePerm_eqb.
  Definition loadstoreregsCompilableType  := loadstoreregsCompilableType.
End Exports.