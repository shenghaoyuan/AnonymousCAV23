From compcert.lib Require Import Integers.
From compcert.common Require Import Values.

From dx Require Import ResultMonad IR.
From dx.Type Require Import Bool Nat.

From bpf.dxcomm Require Import CoqIntegers DxIntegers DxValues.
From bpf.jit.thumb Require Import ThumbInsOp.

From Coq Require Import ZArith.
Open Scope Z_scope.

Definition C_COND_EQ: Csyntax.expr :=
  Csyntax.Eval (Vint COND_EQ) C_U16.

Definition C_COND_NE: Csyntax.expr :=
  Csyntax.Eval (Vint COND_NE) C_U16.

Definition C_COND_CS: Csyntax.expr :=
  Csyntax.Eval (Vint COND_CS) C_U16.

Definition C_COND_CC: Csyntax.expr :=
  Csyntax.Eval (Vint COND_CC) C_U16.

Definition C_COND_MI: Csyntax.expr :=
  Csyntax.Eval (Vint COND_MI) C_U16.

Definition C_COND_PL: Csyntax.expr :=
  Csyntax.Eval (Vint COND_PL) C_U16.

Definition C_COND_VS: Csyntax.expr :=
  Csyntax.Eval (Vint COND_VS) C_U16.

Definition C_COND_VC: Csyntax.expr :=
  Csyntax.Eval (Vint COND_VC) C_U16.

Definition C_COND_HI: Csyntax.expr :=
  Csyntax.Eval (Vint COND_HI) C_U16.

Definition C_COND_LS: Csyntax.expr :=
  Csyntax.Eval (Vint COND_LS) C_U16.

Definition C_COND_GE: Csyntax.expr :=
  Csyntax.Eval (Vint COND_GE) C_U16.

Definition C_COND_LT: Csyntax.expr :=
  Csyntax.Eval (Vint COND_LT) C_U16.

Definition C_COND_GT: Csyntax.expr :=
  Csyntax.Eval (Vint COND_GT) C_U16.

Definition C_COND_LE: Csyntax.expr :=
  Csyntax.Eval (Vint COND_LE) C_U16.

Definition C_COND_AL: Csyntax.expr :=
  Csyntax.Eval (Vint COND_AL) C_U16.

Definition C_ADD_R_OP: Csyntax.expr :=
  Csyntax.Eval (Vint ADD_R_OP) C_U16.

Definition C_ADD_I_OP: Csyntax.expr :=
  Csyntax.Eval (Vint ADD_I_OP) C_U16.

Definition C_AND_R_OP: Csyntax.expr :=
  Csyntax.Eval (Vint AND_R_OP) C_U16.

Definition C_AND_I_OP: Csyntax.expr :=
  Csyntax.Eval (Vint AND_I_OP) C_U16.

Definition C_ASR_R_OP: Csyntax.expr :=
  Csyntax.Eval (Vint ASR_R_OP) C_U16.

Definition C_B_OP: Csyntax.expr :=
  Csyntax.Eval (Vint B_OP) C_U16.

Definition C_CMP_R_OP: Csyntax.expr :=
  Csyntax.Eval (Vint CMP_R_OP) C_U16.

Definition C_CMP_I_OP: Csyntax.expr :=
  Csyntax.Eval (Vint CMP_I_OP) C_U16.

Definition C_EOR_R_OP: Csyntax.expr :=
  Csyntax.Eval (Vint EOR_R_OP) C_U16.

Definition C_EOR_I_OP: Csyntax.expr :=
  Csyntax.Eval (Vint EOR_I_OP) C_U16.

Definition C_LSL_R_OP: Csyntax.expr :=
  Csyntax.Eval (Vint LSL_R_OP) C_U16.

Definition C_LSR_R_OP: Csyntax.expr :=
  Csyntax.Eval (Vint LSR_R_OP) C_U16.

Definition C_MOVW_OP: Csyntax.expr :=
  Csyntax.Eval (Vint MOVW_OP) C_U16.

Definition C_MOVT_OP: Csyntax.expr :=
  Csyntax.Eval (Vint MOVT_OP) C_U16.

Definition C_MOV_R_OP: Csyntax.expr :=
  Csyntax.Eval (Vint MOV_R_OP) C_U16.

Definition C_MUL_OP: Csyntax.expr :=
  Csyntax.Eval (Vint MUL_OP) C_U16.

Definition C_ORR_R_OP: Csyntax.expr :=
  Csyntax.Eval (Vint ORR_R_OP) C_U16.

Definition C_ORR_I_OP: Csyntax.expr :=
  Csyntax.Eval (Vint ORR_I_OP) C_U16.

Definition C_SUB_R_OP: Csyntax.expr :=
  Csyntax.Eval (Vint SUB_R_OP) C_U16.

Definition C_SUB_I_OP: Csyntax.expr :=
  Csyntax.Eval (Vint SUB_I_OP) C_U16.

Definition C_RSB_I_OP: Csyntax.expr :=
  Csyntax.Eval (Vint RSB_I_OP) C_U16.

Definition C_UDIV_OP: Csyntax.expr :=
  Csyntax.Eval (Vint UDIV_OP) C_U16.

Definition C_BX_OP: Csyntax.expr :=
  Csyntax.Eval (Vint BX_OP) C_U16.

Definition C_LDR_I_OP: Csyntax.expr :=
  Csyntax.Eval (Vint LDR_I_OP) C_U16.

Definition C_STR_I_OP: Csyntax.expr :=
  Csyntax.Eval (Vint STR_I_OP) C_U16.

Definition C_BNE_0: Csyntax.expr :=
  Csyntax.Eval (Vint BNE_0) C_U16.

Definition C_BLT_0: Csyntax.expr :=
  Csyntax.Eval (Vint BLT_0) C_U16.

Definition Const_COND_EQ := constant uint16SymbolType COND_EQ C_COND_EQ.

Definition Const_COND_NE := constant uint16SymbolType COND_NE C_COND_NE.

Definition Const_COND_CS := constant uint16SymbolType COND_CS C_COND_CS.

Definition Const_COND_CC := constant uint16SymbolType COND_CC C_COND_CC.

Definition Const_COND_MI := constant uint16SymbolType COND_MI C_COND_MI.

Definition Const_COND_PL := constant uint16SymbolType COND_PL C_COND_PL.

Definition Const_COND_VS := constant uint16SymbolType COND_VS C_COND_VS.

Definition Const_COND_VC := constant uint16SymbolType COND_VC C_COND_VC.

Definition Const_COND_HI := constant uint16SymbolType COND_HI C_COND_HI.

Definition Const_COND_LS := constant uint16SymbolType COND_LS C_COND_LS.

Definition Const_COND_GE := constant uint16SymbolType COND_GE C_COND_GE.

Definition Const_COND_LT := constant uint16SymbolType COND_LT C_COND_LT.

Definition Const_COND_GT := constant uint16SymbolType COND_GT C_COND_GT.

Definition Const_COND_LE := constant uint16SymbolType COND_LE C_COND_LE.

Definition Const_COND_AL := constant uint16SymbolType COND_AL C_COND_AL.

Definition Const_ADD_R_OP   := constant uint16SymbolType ADD_R_OP C_ADD_R_OP.

Definition Const_ADD_I_OP   := constant uint16SymbolType ADD_I_OP C_ADD_I_OP.

Definition Const_AND_R_OP   := constant uint16SymbolType AND_R_OP C_AND_R_OP.

Definition Const_AND_I_OP   := constant uint16SymbolType AND_I_OP C_AND_I_OP.

Definition Const_ASR_R_OP   := constant uint16SymbolType ASR_R_OP C_ASR_R_OP.
Definition Const_B_OP       := constant uint16SymbolType B_OP C_B_OP.

Definition Const_CMP_R_OP   := constant uint16SymbolType CMP_R_OP C_CMP_R_OP.

Definition Const_CMP_I_OP   := constant uint16SymbolType CMP_I_OP C_CMP_I_OP.

Definition Const_EOR_R_OP   := constant uint16SymbolType EOR_R_OP C_EOR_R_OP.

Definition Const_EOR_I_OP   := constant uint16SymbolType EOR_I_OP C_EOR_I_OP.

Definition Const_LSL_R_OP   := constant uint16SymbolType LSL_R_OP C_LSL_R_OP.

Definition Const_LSR_R_OP   := constant uint16SymbolType LSR_R_OP C_LSR_R_OP.

Definition Const_MOV_R_OP   := constant uint16SymbolType MOV_R_OP C_MOV_R_OP.

Definition Const_MOVW_OP    := constant uint16SymbolType MOVW_OP C_MOVW_OP.

Definition Const_MOVT_OP    := constant uint16SymbolType MOVT_OP C_MOVT_OP.

Definition Const_MUL_OP     := constant uint16SymbolType MUL_OP C_MUL_OP.

Definition Const_ORR_R_OP   := constant uint16SymbolType ORR_R_OP C_ORR_R_OP.

Definition Const_ORR_I_OP   := constant uint16SymbolType ORR_I_OP C_ORR_I_OP.

Definition Const_SUB_R_OP   := constant uint16SymbolType SUB_R_OP C_SUB_R_OP.

Definition Const_SUB_I_OP   := constant uint16SymbolType SUB_I_OP C_SUB_I_OP.

Definition Const_RSB_I_OP   := constant uint16SymbolType RSB_I_OP C_RSB_I_OP.

Definition Const_UDIV_OP    := constant uint16SymbolType UDIV_OP C_UDIV_OP.

Definition Const_BX_OP      := constant uint16SymbolType BX_OP C_BX_OP.

Definition Const_LDR_I_OP   := constant uint16SymbolType LDR_I_OP C_LDR_I_OP.

Definition Const_STR_I_OP   := constant uint16SymbolType STR_I_OP C_STR_I_OP.

Definition Const_BNE_0      := constant uint16SymbolType BNE_0 C_BNE_0.

Definition Const_BLT_0      := constant uint16SymbolType BLT_0 C_BLT_0.

Close Scope Z_scope.

Module Exports.
  Definition Const_COND_EQ := Const_COND_EQ.
  Definition Const_COND_NE := Const_COND_NE.
  Definition Const_COND_CS := Const_COND_CS.
  Definition Const_COND_CC := Const_COND_CC.
  Definition Const_COND_MI := Const_COND_MI.
  Definition Const_COND_PL := Const_COND_PL.
  Definition Const_COND_VS := Const_COND_VS.
  Definition Const_COND_VC := Const_COND_VC.
  Definition Const_COND_HI := Const_COND_HI.
  Definition Const_COND_LS := Const_COND_LS.
  Definition Const_COND_GE := Const_COND_GE.
  Definition Const_COND_LT := Const_COND_LT.
  Definition Const_COND_GT := Const_COND_GT.
  Definition Const_COND_LE := Const_COND_LE.
  Definition Const_COND_AL := Const_COND_AL.
  Definition Const_ADD_R_OP   := Const_ADD_R_OP.
  Definition Const_ADD_I_OP   := Const_ADD_I_OP.
  Definition Const_AND_R_OP   := Const_AND_R_OP.
  Definition Const_AND_I_OP   := Const_AND_I_OP.
  Definition Const_ASR_R_OP   := Const_ASR_R_OP.
  Definition Const_B_OP       := Const_B_OP.
  Definition Const_CMP_R_OP   := Const_CMP_R_OP.
  Definition Const_CMP_I_OP   := Const_CMP_I_OP.
  Definition Const_EOR_R_OP   := Const_EOR_R_OP.
  Definition Const_EOR_I_OP   := Const_EOR_I_OP.
  Definition Const_LSL_R_OP   := Const_LSL_R_OP.
  Definition Const_LSR_R_OP   := Const_LSR_R_OP.
  Definition Const_MOV_R_OP   := Const_MOV_R_OP.
  Definition Const_MOVW_OP    := Const_MOVW_OP.
  Definition Const_MOVT_OP    := Const_MOVT_OP.
  Definition Const_MUL_OP     := Const_MUL_OP.
  Definition Const_ORR_R_OP   := Const_ORR_R_OP.
  Definition Const_ORR_I_OP   := Const_ORR_I_OP.
  Definition Const_SUB_R_OP   := Const_SUB_R_OP.
  Definition Const_SUB_I_OP   := Const_SUB_I_OP.
  Definition Const_RSB_I_OP   := Const_RSB_I_OP.
  Definition Const_UDIV_OP    := Const_UDIV_OP.
  Definition Const_BX_OP      := Const_BX_OP.
  Definition Const_LDR_I_OP   := Const_LDR_I_OP.
  Definition Const_STR_I_OP   := Const_STR_I_OP.
  Definition Const_BNE_0      := Const_BNE_0.
  Definition Const_BLT_0      := Const_BLT_0.
End Exports.
