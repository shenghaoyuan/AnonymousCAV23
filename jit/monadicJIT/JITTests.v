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

From bpf.dxcomm Require Import DxIntegers DxValues DxBinrBPF DxNat.
From bpf.dxmodel Require Import DxFlag DxRegs DxMemRegion DxMemType DxOpcode DxAST.
From bpf.jit.thumb Require Import LoadStoreRegs.
From bpf.jit.monadicJIT Require Import JITIdDef DxJITNat DxLoadStoreRegs DxKeyValue2 DxArm32Reg DxJITMonadState DxJITMonad DxMonadCommon DxThumbInsOp DxThumbJIT DxThumbJITOpcode.
From bpf.jit.monadicJIT Require Import DxiBPFInterpreter.

(***************************************)

GenerateIntermediateRepresentation SymbolIRs
  M bindM returnM
  Bool.Exports
  Nat.Exports
  DxIntegers.Exports
  DxValues.Exports
  DxRegs.Exports
  DxBinrBPF.Exports
  DxOpcode.Exports
  DxFlag.Exports
  DxAST.Exports
  DxMemRegion.Exports
  DxMemType.Exports
  DxNat.Exports
  DxJITNat.Exports
  DxLoadStoreRegs.Exports
  DxKeyValue2.Exports
  DxArm32Reg.Exports
  DxThumbInsOp.Exports
  DxThumbJITOpcode.Exports
  eval_pc
  upd_pc
  upd_pc_incr
  eval_flag
  upd_flag
  eval_mrs_num
  eval_reg
  upd_reg
  eval_mrs_regions
  load_mem
  store_mem_imm
  store_mem_reg
  eval_ins_len
  eval_ins
  cmp_ptr32_nullM
  get_dst
  get_src
  get_mem_region
  _bpf_get_call
  exec_function
  upd_IR11_jittedthumb
  add_ins_jittedthumb
  upd_bpf_offset_jittedthumb
  upd_load_store_regs_jittedthumb
  upd_thumb_jittedthumb
  upd_jitted_list
  magic_function
  eval_use_IR11
  eval_offset
  eval_thumb_len
  eval_jitted_len
  is_non_reg
  is_load_reg
  is_store_reg
  decode_thumb
  encode_thumb
  reg_of_ireg
  opcode_reg_of_imm
  eval_thumb_ins
  ins_is_bpf_alu32
  ins_is_bpf_jump
  eval_key_value2_arm_ofs
  eval_key_value2_alu32_ofs
  reset_init_jittedthumb
  add_key_value2
  __
  construct_thumb_b
  construct_thumb2_shift_rd_rm
  jit_alu32_thumb_store_template_ins
  jit_alu32_thumb_load_template_ins
  jit_alu32_thumb_store_template_jit
  jit_alu32_thumb_load_template_jit
  jit_alu32_store_flag
  get_offset
  jit_alu32_pre
  jit_alu32_thumb_upd_save
  jit_alu32_thumb_save
  jit_alu32_thumb_upd_load
  no_reg_load
  jit_alu32_thumb_load
  bpf_alu32_to_thumb_reg
  bpf_alu32_to_thumb_imm
  mov_int_to_reg_binary
  get_immediate
  get_opcode_ins
  nat_to_opcode_alu32
  nat_to_opcode_alu32_reg
  nat_to_opcode_alu32_imm
  bpf_alu32_to_thumb
  get_store_ins_num
  jit_alu32_to_thumb_pass2_aux
  jit_alu32_to_thumb_pass2
  jit_alu32_to_thumb_pass1
  jit_alu32_thumb_upd_store
  jit_alu32_thumb_store
  jit_alu32_store_flag_jit
  jit_alu32_thumb_store_succ_R0
  jit_alu32_thumb_upd_reset
  jit_alu32_thumb_reset
  jit_alu32_post
  copy_thumb_list_from_to_aux
  copy_thumb_list_from_to

  jit_alu32_to_thumb
  jit_alu32_aux
  jit_alu32

  reg64_to_reg32
  eval_immediate
  get_src64
  get_src32
  get_opcode_alu64
  get_opcode_alu32
  get_opcode_branch
  get_opcode_mem_ld_imm
  get_opcode_mem_ld_reg
  get_opcode_mem_st_imm
  get_opcode_mem_st_reg
  get_opcode
  get_add
  get_sub
  get_addr_ofs
  get_start_addr
  get_block_size
  get_block_perm
  is_well_chunk_bool
  check_mem_aux2
  check_mem_aux
  check_mem
  step_opcode_alu64
  step_opcode_alu32
  step_opcode_branch
  step_opcode_mem_ld_imm
  step_opcode_mem_ld_reg
  step_opcode_mem_st_imm
  step_opcode_mem_st_reg
  step
  ibpf_interpreter_aux
  ibpf_interpreter
.

Open Scope string_scope.

Definition dxModuleTest := makeDXModuleWithUserIds 
  [ key_value2_def; mem_region_def; jit_state_def]
  [ "key_value2";
    "arm_ofs"; "alu32_ofs";
    "memory_region";
    "start_addr"; "block_size"; "block_perm"; "block_ptr";
    "jit_state";
    "pc_loc"; "flag"; "regs_st"; "mrs_num"; "bpf_mrs"; "ins_len"; "jit_ins";
    "kv2";
    "is_IR11"; "load_store_regs"; "offset"; "thumb_len"; "thumb";
    "stack_ofs"; "jitted_len"; "jitted_list" ] SymbolIRs.

Close Scope string_scope.