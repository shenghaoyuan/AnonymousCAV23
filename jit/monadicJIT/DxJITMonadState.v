From compcert.cfrontend Require Csyntax Ctypes Cop.
From compcert.common Require Values Memory AST.
From compcert.lib Require Import Integers.
From compcert.arm Require Import ABinSem.

From dx Require Import ResultMonad IR.
From dx.Type Require Import Bool Nat.

From bpf.comm Require Import ListAsArray Flag Regs MemRegion rBPFAST.
From bpf.dxcomm Require Import CoqIntegers DxIntegers DxValues.
From bpf.dxmodel Require Import DxMemRegion.

From bpf.jit.thumb Require Import LoadStoreRegs KeyValue2 JITState.
From bpf.jit.monadicJIT Require Import JITIdDef DxKeyValue2.

From Coq Require Import List ZArith.
Import ListNotations.

Definition jit_state_type: Ctypes.type := Ctypes.Tpointer (Ctypes.Tstruct jit_state_id Ctypes.noattr) Ctypes.noattr.

Definition jit_state_def: Ctypes.composite_definition := 
  Ctypes.Composite jit_state_id Ctypes.Struct
    [ Ctypes.Member_plain pc_loc_id           C_U32;
      Ctypes.Member_plain flag_id             C_U32_pointer;
      Ctypes.Member_plain regs_st_id          C_U32_pointer;
      Ctypes.Member_plain mrs_num_id          C_U32;
      Ctypes.Member_plain bpf_mrs_id          mem_region_type;
      Ctypes.Member_plain ins_len_id          C_U32;
      Ctypes.Member_plain jit_ins_id          C_U64_pointer;

      Ctypes.Member_plain kv2_id              key_value2_type;
      Ctypes.Member_plain use_IR11_id         Ctypes.type_bool;

      Ctypes.Member_plain load_store_regs_id  C_U32_pointer;
      Ctypes.Member_plain offset_id           C_U32;
      Ctypes.Member_plain arm32_len_id        C_U32;
      Ctypes.Member_plain arm32_id            C_U32_pointer;
      Ctypes.Member_plain jitted_len_id       C_U32;
      Ctypes.Member_plain jitted_list_id      C_U16_pointer] Ctypes.noattr.

Definition jit_stateCompilableType := MkCompilableType jit_state jit_state_type.

Module Exports.
  Definition jit_stateCompilableType := jit_stateCompilableType.
End Exports.
