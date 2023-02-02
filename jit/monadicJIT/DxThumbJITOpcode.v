From Coq Require Import List ZArith.
Import ListNotations.

From compcert Require Import Integers Values.

From dx Require Import ResultMonad IR.
From dx.Type Require Import Bool.

From bpf.dxcomm Require Import InfComp GenMatchable CoqIntegers DxIntegers DxNat.

From bpf.jit.thumb Require Import ThumbJITOpcode.


(******************** Dx related *******************)

Open Scope Z_scope.

Definition opcode_alu32_regCompilableType :=
  MkCompilableType opcode_alu32_reg C_U8.

Definition opcode_alu32_regMatchableType : MatchableType:=
  Eval compute in
 (mkEnumMatchableType
    opcode_alu32_regCompilableType  opcode_alu32_reg_eqb
    (     (BPF_ADD32_REG, 0x0c)
       :: (BPF_SUB32_REG, 0x1c)
       :: (BPF_MUL32_REG, 0x2c)
       :: (BPF_DIV32_REG, 0x3c)
       :: (BPF_OR32_REG,  0x4c)
       :: (BPF_AND32_REG, 0x5c)
       :: (BPF_LSH32_REG, 0x6c)
       :: (BPF_RSH32_REG, 0x7c)
       :: (BPF_XOR32_REG, 0xac)
       :: (BPF_MOV32_REG, 0xbc)
       :: (BPF_ARSH32_REG, 0xcc) :: nil)
    BPF_ALU32_REG_ILLEGAL_INS
    (fun m A => opcode_alu32_reg_rect (fun _ => m A))).

Definition opcode_alu32_immCompilableType :=
  MkCompilableType opcode_alu32_imm C_U8.

Definition opcode_alu32_immMatchableType : MatchableType:=
  Eval compute in
 (mkEnumMatchableType
    opcode_alu32_immCompilableType  opcode_alu32_imm_eqb
    (     (BPF_ADD32_IMM, 0x04)
       :: (BPF_SUB32_IMM, 0x14)
       :: (BPF_MUL32_IMM, 0x24)
       :: (BPF_OR32_IMM,  0x44)
       :: (BPF_AND32_IMM, 0x54)
       :: (BPF_NEG32_IMM, 0x84)
       :: (BPF_XOR32_IMM, 0xa4)
       :: (BPF_MOV32_IMM, 0xb4) :: nil)
    BPF_ALU32_IMM_ILLEGAL_INS
    (fun m A => opcode_alu32_imm_rect (fun _ => m A))).

Definition opcode_alu32CompilableType :=
  MkCompilableType opcode_alu32 C_U8.

Definition opcode_alu32MatchableType : MatchableType:=
  Eval compute in
 (mkEnumMatchableType
    opcode_alu32CompilableType  opcode_alu32_eqb
    (     (ALU32_REG, 0x0c)
       :: (ALU32_IMM, 0x04) :: nil)
    ALU32_ILLEGAL_INS
    (fun m A => opcode_alu32_rect (fun _ => m A))).

Definition C_ALU32_REG: Csyntax.expr :=
  Csyntax.Eval (Vint (Int.repr 0x0c)) C_U32.

Definition C_ALU32_IMM: Csyntax.expr :=
  Csyntax.Eval (Vint (Int.repr 0x04)) C_U32.

Definition C_ALU32_ILLEGAL_INS: Csyntax.expr :=
  Csyntax.Eval (Vint (Int.repr 0)) C_U32.


Definition opcode_alu32SymbolType :=
  MkCompilableSymbolType nil (Some opcode_alu32CompilableType).

Definition Const_ALU32_REG        := constant opcode_alu32SymbolType ALU32_REG C_ALU32_REG.
Definition Const_ALU32_IMM        := constant opcode_alu32SymbolType ALU32_IMM C_ALU32_IMM.
Definition Const_ALU32_ILLEGAL_INS:= constant opcode_alu32SymbolType ALU32_ILLEGAL_INS C_ALU32_ILLEGAL_INS.


Instance CINT : CType nat := mkCType _ (cType nat8CompilableType).
Instance COP_alu32 : CType opcode_alu32 := mkCType _ (cType opcode_alu32CompilableType).
Instance COP_alu32_reg : CType opcode_alu32_reg := mkCType _ (cType opcode_alu32_regCompilableType).
Instance COP_alu32_imm : CType opcode_alu32_imm := mkCType _ (cType opcode_alu32_immCompilableType).

Definition Const_nat_to_opcode_alu32_reg :=
  ltac: (mkprimitive nat_to_opcode_alu32_reg
                (fun es => match es with
                           | [e1] => Ok e1
                           | _       => Err PrimitiveEncodingFailed
                           end)).

Definition Const_nat_to_opcode_alu32_imm :=
  ltac: (mkprimitive nat_to_opcode_alu32_imm
                (fun es => match es with
                           | [e1] => Ok e1
                           | _       => Err PrimitiveEncodingFailed
                           end)).

Definition opcode_alu32_immToopcode_alu32_immToboolSymbolType :=
  MkCompilableSymbolType [opcode_alu32_immCompilableType; opcode_alu32_immCompilableType] (Some boolCompilableType).

Definition Const_opcode_alu32_imm_eqb :=
  MkPrimitive opcode_alu32_immToopcode_alu32_immToboolSymbolType
                opcode_alu32_imm_eqb
                (fun es => match es with
                           | [r0; r1] => Ok (Csyntax.Ebinop Cop.Oeq r0 r1 C_U32)
                           | _       => Err PrimitiveEncodingFailed
                           end).

Definition C_U32_0x24 := Csyntax.Eval (Vint (Int.repr 0x24)) C_U32.

Definition opcode_alu32_immSymbolType :=
  MkCompilableSymbolType nil (Some opcode_alu32_immCompilableType).
Definition Const_BPF_MUL32_IMM := constant opcode_alu32_immSymbolType BPF_MUL32_IMM C_U32_0x24.



Close Scope nat_scope.

Module Exports.
  Definition opcode_alu32_regMatchableType  := opcode_alu32_regMatchableType.
  Definition opcode_alu32_immMatchableType  := opcode_alu32_immMatchableType.
  Definition opcode_alu32MatchableType      := opcode_alu32MatchableType.
  Definition Const_ALU32_REG                := Const_ALU32_REG.
  Definition Const_ALU32_IMM                := Const_ALU32_IMM.
  Definition Const_ALU32_ILLEGAL_INS        := Const_ALU32_ILLEGAL_INS.
  Definition Const_nat_to_opcode_alu32_reg  := Const_nat_to_opcode_alu32_reg.
  Definition Const_nat_to_opcode_alu32_imm  := Const_nat_to_opcode_alu32_imm.
  Definition Const_opcode_alu32_imm_eqb     := Const_opcode_alu32_imm_eqb.
  Definition Const_BPF_MUL32_IMM            := Const_BPF_MUL32_IMM.
End Exports.