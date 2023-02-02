
From compcert Require Import Integers.

From bpf.comm Require Import BinrBPF.

From Coq Require Import List ZArith.
Open Scope Z_scope.
Open Scope bool_scope.

(**
This module defines all opcodes used by JIT. We only support a rBPF alu32 subset because of the constaint of CompCert
- no shift_imm
- udiv R0 R0 R1
 and llvm
- error of mod32

TODO: we need a stronger verifier to support this constraint
*)

Inductive opcode_alu32_reg: Type :=
  (** ALU32_REG:12 *)
  | BPF_ADD32_REG
  | BPF_SUB32_REG
  | BPF_MUL32_REG
  | BPF_DIV32_REG
  | BPF_OR32_REG
  | BPF_AND32_REG
  | BPF_LSH32_REG
  | BPF_RSH32_REG (* banned by a stronger verifier
  | BPF_MOD32_REG *)
  | BPF_XOR32_REG
  | BPF_MOV32_REG
  | BPF_ARSH32_REG
  | BPF_ALU32_REG_ILLEGAL_INS.

Definition opcode_alu32_reg_eqb (op0 op1: opcode_alu32_reg): bool :=
  match op0, op1 with
  | BPF_ADD32_REG, BPF_ADD32_REG
  | BPF_SUB32_REG, BPF_SUB32_REG
  | BPF_MUL32_REG, BPF_MUL32_REG
  | BPF_DIV32_REG, BPF_DIV32_REG
  | BPF_OR32_REG,  BPF_OR32_REG
  | BPF_AND32_REG, BPF_AND32_REG
  | BPF_LSH32_REG, BPF_LSH32_REG
  | BPF_RSH32_REG, BPF_RSH32_REG
  | BPF_XOR32_REG, BPF_XOR32_REG
  | BPF_MOV32_REG, BPF_MOV32_REG
  | BPF_ARSH32_REG, BPF_ARSH32_REG
  | BPF_ALU32_REG_ILLEGAL_INS, BPF_ALU32_REG_ILLEGAL_INS => true
  | _, _ => false
  end.


Inductive opcode_alu32_imm: Type :=
  (** ALU32_IMM:13 *)
  | BPF_ADD32_IMM
  | BPF_SUB32_IMM
  | BPF_MUL32_IMM (*
  | BPF_DIV32_IMM *)
  | BPF_OR32_IMM
  | BPF_AND32_IMM (*
  | BPF_LSH32_IMM
  | BPF_RSH32_IMM
  | BPF_MOD32_IMM *)
  | BPF_NEG32_IMM
  | BPF_XOR32_IMM
  | BPF_MOV32_IMM (*
  | BPF_ARSH32_IMM *)
  | BPF_ALU32_IMM_ILLEGAL_INS.

Definition opcode_alu32_imm_eqb (op0 op1: opcode_alu32_imm): bool :=
  match op0, op1 with
  | BPF_ADD32_IMM, BPF_ADD32_IMM
  | BPF_SUB32_IMM, BPF_SUB32_IMM
  | BPF_MUL32_IMM, BPF_MUL32_IMM
  | BPF_OR32_IMM,  BPF_OR32_IMM
  | BPF_AND32_IMM, BPF_AND32_IMM
  | BPF_NEG32_IMM, BPF_NEG32_IMM
  | BPF_XOR32_IMM, BPF_XOR32_IMM
  | BPF_MOV32_IMM, BPF_MOV32_IMM
  | BPF_ALU32_IMM_ILLEGAL_INS, BPF_ALU32_IMM_ILLEGAL_INS => true
  | _, _ => false
  end.

Definition nat_to_opcode_alu32_reg (op: nat) : opcode_alu32_reg :=
  if Nat.eqb op (0x0c)%nat then
    BPF_ADD32_REG
  else if Nat.eqb op (0x1c)%nat then
    BPF_SUB32_REG
  else if Nat.eqb op (0x2c)%nat then
    BPF_MUL32_REG
  else if Nat.eqb op (0x3c)%nat then
    BPF_DIV32_REG
  else if Nat.eqb op (0x4c)%nat then
    BPF_OR32_REG
  else if Nat.eqb op (0x5c)%nat then
    BPF_AND32_REG
  else if Nat.eqb op (0x6c)%nat then
    BPF_LSH32_REG
  else if Nat.eqb op (0x7c)%nat then
    BPF_RSH32_REG (*
  else if Nat.eqb op (0x9c)%nat then
    BPF_MOD32_REG *)
  else if Nat.eqb op (0xac)%nat then
    BPF_XOR32_REG
  else if Nat.eqb op (0xbc)%nat then
    BPF_MOV32_REG
  else if Nat.eqb op (0xcc)%nat then
    BPF_ARSH32_REG
  else
    BPF_ALU32_REG_ILLEGAL_INS.

Definition nat_to_opcode_alu32_imm (op: nat) : opcode_alu32_imm :=
  if Nat.eqb op (0x04)%nat then
    BPF_ADD32_IMM
  else if Nat.eqb op (0x14)%nat then
    BPF_SUB32_IMM
  else if Nat.eqb op (0x24)%nat then
    BPF_MUL32_IMM (*
  else if Nat.eqb op (0x34)%nat then
    BPF_DIV32_IMM *)
  else if Nat.eqb op (0x44)%nat then
    BPF_OR32_IMM
  else if Nat.eqb op (0x54)%nat then
    BPF_AND32_IMM (*
  else if Nat.eqb op (0x64)%nat then
    BPF_LSH32_IMM
  else if Nat.eqb op (0x74)%nat then
    BPF_RSH32_IMM
  else if Nat.eqb op (0x94)%nat then
    BPF_MOD32_IMM *)
  else if Nat.eqb op (0x84)%nat then
    BPF_NEG32_IMM
  else if Nat.eqb op (0xa4)%nat then
    BPF_XOR32_IMM
  else if Nat.eqb op (0xb4)%nat then
    BPF_MOV32_IMM (*
  else if Nat.eqb op (0xc4)%nat then
    BPF_ARSH32_IMM *)
  else
    BPF_ALU32_IMM_ILLEGAL_INS.


Inductive opcode_alu32: Type :=
  | ALU32_REG
  | ALU32_IMM
  | ALU32_ILLEGAL_INS.

Definition opcode_alu32_eqb (op0 op1: opcode_alu32): bool :=
  match op0, op1 with
  | ALU32_REG, ALU32_REG
  | ALU32_IMM, ALU32_IMM
  | ALU32_ILLEGAL_INS, ALU32_ILLEGAL_INS => true
  | _, _ => false
  end.


Definition nat_to_opcode_alu32 (op: nat): opcode_alu32 :=
  let opc := Nat.land op 0x07 in
    if Nat.eqb opc 0x4 then
      if Int.eq Int.zero (Int.and (Int.repr (Z.of_nat op)) (Int.repr 8)) then
        ALU32_IMM
      else
        ALU32_REG
    else
      ALU32_ILLEGAL_INS.

Definition ins_is_bpf_alu32 (ins: int64) : bool :=
  let op := get_opcode ins in
    if      Nat.eqb op (Z.to_nat 0x04) || Nat.eqb op (Z.to_nat 0x0c) then
      true
    else if Nat.eqb op (Z.to_nat 0x14) || Nat.eqb op (Z.to_nat 0x1c) then
      true
    else if Nat.eqb op (Z.to_nat 0x24) || Nat.eqb op (Z.to_nat 0x2c) then
      true
    else if (* Nat.eqb op (Z.to_nat 0x34) || *) Nat.eqb op (Z.to_nat 0x3c) then
      true
    else if Nat.eqb op (Z.to_nat 0x44) || Nat.eqb op (Z.to_nat 0x4c) then
      true
    else if Nat.eqb op (Z.to_nat 0x54) || Nat.eqb op (Z.to_nat 0x5c) then
      true
    else if (* Nat.eqb op (Z.to_nat 0x64) || *) Nat.eqb op (Z.to_nat 0x6c) then
      true
    else if (* Nat.eqb op (Z.to_nat 0x74) || *) Nat.eqb op (Z.to_nat 0x7c) then
      true
    else if Nat.eqb op (Z.to_nat 0x84) then
      true (*
    else if Nat.eqb op (Z.to_nat 0x94) || Nat.eqb op (Z.to_nat 0x9c) then
      true *)
    else if Nat.eqb op (Z.to_nat 0xa4) || Nat.eqb op (Z.to_nat 0xac) then
      true
    else if Nat.eqb op (Z.to_nat 0xb4) || Nat.eqb op (Z.to_nat 0xbc) then
      true
    else if (* Nat.eqb op (Z.to_nat 0xc4) ||*) Nat.eqb op (Z.to_nat 0xcc) then
      true
    else
      false
.

Definition ins_is_bpf_jump (ins: int64) : bool :=
  let op := get_opcode ins in
    if      Nat.eqb op (Z.to_nat 0x05) then
      true
    else if Nat.eqb op (Z.to_nat 0x15) || Nat.eqb op (Z.to_nat 0x1d) then
      true
    else if Nat.eqb op (Z.to_nat 0x25) || Nat.eqb op (Z.to_nat 0x2d) then
      true
    else if Nat.eqb op (Z.to_nat 0x35) || Nat.eqb op (Z.to_nat 0x3d) then
      true
    else if Nat.eqb op (Z.to_nat 0x45) || Nat.eqb op (Z.to_nat 0x4d) then
      true
    else if Nat.eqb op (Z.to_nat 0x55) || Nat.eqb op (Z.to_nat 0x5d) then
      true
    else if Nat.eqb op (Z.to_nat 0x65) || Nat.eqb op (Z.to_nat 0x6d) then
      true
    else if Nat.eqb op (Z.to_nat 0x75) || Nat.eqb op (Z.to_nat 0x7d) then
      true
    else if Nat.eqb op (Z.to_nat 0xa5) || Nat.eqb op (Z.to_nat 0xad) then
      true
    else if Nat.eqb op (Z.to_nat 0xb5) || Nat.eqb op (Z.to_nat 0xbd) then
      true
    else if Nat.eqb op (Z.to_nat 0xc5) || Nat.eqb op (Z.to_nat 0xcd) then
      true
    else if Nat.eqb op (Z.to_nat 0xd5) || Nat.eqb op (Z.to_nat 0xdd) then
      true
    else
      false
.

Definition opcode_reg_of_imm (op: opcode_alu32_imm): opcode_alu32_reg :=
  match op with
  | BPF_ADD32_IMM => BPF_ADD32_REG
  | BPF_SUB32_IMM => BPF_SUB32_REG
  | BPF_MUL32_IMM => BPF_MUL32_REG
  | BPF_OR32_IMM  => BPF_OR32_REG
  | BPF_AND32_IMM => BPF_AND32_REG
  | BPF_XOR32_IMM => BPF_XOR32_REG
  | BPF_MOV32_IMM => BPF_MOV32_REG
  | _             => BPF_ALU32_REG_ILLEGAL_INS
  end.

Close Scope bool_scope.
Close Scope Z_scope.