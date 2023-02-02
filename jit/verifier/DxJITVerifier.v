From compcert Require Import Integers Values AST Ctypes.
From Coq Require Import ZArith.
From dx.Type Require Bool Nat.

From bpf.comm Require Import rBPFValues BinrBPF.
From bpf.dxcomm Require Import DxIntegers DxNat.
From bpf.verifier.comm Require Import state.
From bpf.verifier.synthesismodel Require Import opcode_synthesis.
From bpf.verifier.dxmodel Require Import Dxmonad Dxverifier.

Open Scope nat_scope.
Open Scope monad_scope.

Definition jit_verifier_opcode_alu32_imm (op: nat8) (ins: int64) : M bool :=
  match nat_to_opcode_alu32_imm op with
  | DIV32_IMM
  | MOD32_IMM
  | LSH32_IMM
  | RSH32_IMM
  | ARSH32_IMM => returnM false
  | ADD32_IMM
  | SUB32_IMM
  | MUL32_IMM
  | OR32_IMM
  | AND32_IMM
  | NEG32_IMM
  | XOR32_IMM
  | MOV32_IMM => (**r ALU_IMM *)
    returnM true
  | ALU32_IMM_ILLEGAL => returnM false
  end.

Definition is_compcert_udiv (ins: int64): M bool := returnM (is_compcert_udiv' ins).

Definition jit_verifier_opcode_alu32_reg (op: nat8) (ins: int64) : M bool :=
  match nat_to_opcode_alu32_reg op with
  | DIV32_REG => is_compcert_udiv ins
  | MOD32_REG => returnM false
  | LSH32_REG
  | RSH32_REG
  | ARSH32_REG
  | ADD32_REG
  | SUB32_REG
  | MUL32_REG
  | OR32_REG
  | AND32_REG
  | XOR32_REG
  | MOV32_REG => (**r ALU_REG *)
    do b <-- is_well_src ins;
      returnM b
  | ALU32_REG_ILLEGAL => returnM false
  end.

Definition jit_verifier_aux2 (pc len: nat) (op: nat8) (ins: int64) : M bool :=
  match nat_to_opcode op with
  | ALU64  (**r 0xX7 / 0xXf *) =>
    if Int.eq Int.zero (Int.and (nat2int op) int32_8) then
      do b <-- bpf_verifier_opcode_alu64_imm op ins;
      returnM b
    else
      do b <-- bpf_verifier_opcode_alu64_reg op ins;
      returnM b
  | ALU32  (**r 0xX4 / 0xXc *) =>
    if Int.eq Int.zero (Int.and (nat2int op) int32_8) then
      do b <-- jit_verifier_opcode_alu32_imm op ins;
      returnM b
    else
      do b <-- jit_verifier_opcode_alu32_reg op ins;
      returnM b
  | Branch (**r 0xX5 / 0xXd *) =>
    if Int.eq Int.zero (Int.and (nat2int op) int32_8) then
      do b <-- bpf_verifier_opcode_branch_imm pc len op ins;
      returnM b
    else
      do b <-- bpf_verifier_opcode_branch_reg pc len op ins;
      returnM b
  | LD_IMM (**r 0xX8 *)        => do b <-- bpf_verifier_opcode_load_imm op ins; returnM b
  | LD_REG (**r 0xX1/0xX9 *)   => do b <-- bpf_verifier_opcode_load_reg op ins; returnM b
  | ST_IMM (**r 0xX2/0xXa *)   => do b <-- bpf_verifier_opcode_store_imm op ins; returnM b
  | ST_REG (**r 0xX3/0xXb *)   => do b <-- bpf_verifier_opcode_store_reg op ins; returnM b
  | ILLEGAL => returnM false
  end.

Fixpoint jit_verifier_aux (pc len: nat): M bool := (**r pc: len-1, len-2, ... 0 *)
    match pc with
    | O => returnM true
    | S n =>
      do ins <-- eval_ins (nat2int n); (**r len-pc: 0, 1, 2, etc... len -1 *)
      do b   <-- is_well_dst ins;
        if b then
          do op   <-- get_opcode ins;
          do b0    <-- jit_verifier_aux2 n len op ins;
            if b0 then
              jit_verifier_aux n len
            else
              returnM false
        else
          returnM false
    end.

Definition jit_verifier: M bool :=
  do len  <-- eval_ins_len;
  (**r (0, Int.max_unsigned/8): at least one instruction, and at most Int.max_unsigned/8 because of memory region *)
    if Int_leu Int.one (nat2int len) then
      if Int_leu (nat2int len) (Int.divu int32_max_unsigned int32_8) then
        do b <-- jit_verifier_aux len len;
          if b then
            do ins64 <-- eval_ins (nat2int (Nat.sub len nat32_1));
              returnM (Int64.eq ins64 int64_0x95)
          else
            returnM false
      else
        returnM false
    else
      returnM false.

Close Scope monad_scope.
Close Scope nat_scope.
