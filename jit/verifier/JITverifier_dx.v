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

From Coq Require Import BinNums List Ascii String Nat ZArith.
From Coq Require Import Numbers.AltBinNotations.
Import List.ListNotations.

From compcert.cfrontend Require Csyntax Ctypes.
From compcert.common Require Import Errors Values.
From compcert.lib Require Import Integers.
 

From dx Require Import ResultMonad IR CoqIR IRtoC DXModule DumpAsC.
From dx.Type Require Bool Nat.

From bpf.dxcomm Require Import CoqIntegers DxIntegers DxNat DxBinrBPF.
From bpf.verifier.dxmodel Require Import Dxopcode Dxstate Dxmonad Dxverifier.
From bpf.jit.verifier Require Import DxJITVerifier.

(***************************************)

GenerateIntermediateRepresentation SymbolIRs
  M bindM returnM
  Bool.Exports
  Nat.Exports
  DxIntegers.Exports
  DxNat.Exports
  DxBinrBPF.Exports
  Dxopcode.Exports
  Dxstate.Exports
  eval_ins_len
  eval_ins
  __
  is_compcert_udiv
  is_dst_R0
  is_well_dst
  is_well_src
  is_well_jump
  is_not_div_by_zero64
  is_shift_range64
  get_opcode
  get_offset
  jit_verifier_opcode_alu32_imm
  jit_verifier_opcode_alu32_reg
  bpf_verifier_opcode_alu64_imm
  bpf_verifier_opcode_alu64_reg
  bpf_verifier_opcode_branch_imm
  bpf_verifier_opcode_branch_reg
  bpf_verifier_opcode_load_imm
  bpf_verifier_opcode_load_reg
  bpf_verifier_opcode_store_imm
  bpf_verifier_opcode_store_reg
  jit_verifier_aux2
  jit_verifier_aux
  jit_verifier
.

Open Scope string.
Definition dxModuleTest := makeDXModuleWithUserIds
  [ state_struct_def ]
  [ "verifier_state"; "ins_len"; "ins" ] SymbolIRs.
Close Scope string.
