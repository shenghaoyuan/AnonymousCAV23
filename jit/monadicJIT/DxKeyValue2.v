From Coq Require Import List ZArith.
Import ListNotations.

From compcert.cfrontend Require Csyntax Ctypes Cop.
From compcert.common Require Values Memory.
From compcert.lib Require Import Integers.

From dx Require Import ResultMonad IR.
From dx.Type Require Import Bool Nat.

From bpf.dxcomm Require Import CoqIntegers DxIntegers DxValues.
From bpf.jit.thumb Require Import KeyValue2.

From bpf.jit.monadicJIT Require Import JITIdDef.

(******************** Dx Related *******************)

Definition key_value2_type: Ctypes.type := Ctypes.Tpointer (Ctypes.Tstruct key_value2_id Ctypes.noattr) Ctypes.noattr.

Definition key_value2_def: Ctypes.composite_definition :=
  Ctypes.Composite key_value2_id Ctypes.Struct
    [ Ctypes.Member_plain arm_ofs_id C_U32;
      Ctypes.Member_plain alu32_ofs_id C_U32] Ctypes.noattr.

Definition key_value2CompilableType := MkCompilableType key_value2 key_value2_type.

Definition key_value2TonatCompilableSymbolType :=
  MkCompilableSymbolType [key_value2CompilableType] (Some natCompilableType).

Definition Const_arm_ofs := 
  MkPrimitive key_value2TonatCompilableSymbolType 
              arm_ofs
              (fun es => match es with
                         | [e1] => Ok (Csyntax.Efield
                                      (Csyntax.Ederef e1 key_value2_type) arm_ofs_id C_U32)
                         | _   => Err PrimitiveEncodingFailed
                         end).

Definition Const_alu32_ofs := 
  MkPrimitive key_value2TonatCompilableSymbolType 
              alu32_ofs
              (fun es => match es with
                         | [e1] => Ok (Csyntax.Efield
                                      (Csyntax.Ederef e1 key_value2_type) alu32_ofs_id C_U32)
                         | _   => Err PrimitiveEncodingFailed
                         end).
(*
Definition ListKeyVCompilableType :=
  MkCompilableType ListKeyV.t key_value2_type. *)

Module Exports.
  Definition key_value2CompilableType   := key_value2CompilableType.
  Definition Const_arm_ofs              := Const_arm_ofs.
  Definition Const_alu32_ofs            := Const_alu32_ofs. (*
  Definition ListKeyVCompilableType     := ListKeyVCompilableType. *)
End Exports.
