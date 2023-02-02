From compcert Require Import Integers Values AST Ctypes.
From Coq Require Import ZArith.

From bpf.comm Require Import BinrBPF Monad.
From bpf.verifier.comm Require Import state monad.
From bpf.model Require Import Syntax.
From bpf.verifier.synthesismodel Require Import opcode_synthesis verifier_synthesis.

Open Scope nat_scope.
Open Scope monad_scope.

Definition jit_verifier_opcode_alu32_imm (op: nat) (ins: int64) : M state.state bool :=
  match nat_to_opcode_alu32_imm op with
  | DIV32_IMM
  | MOD32_IMM
  | LSH32_IMM
  | RSH32_IMM
  | ARSH32_IMM => returnM false (**r CompCert BPF back-end should guarantee it *)

  | ADD32_IMM
  | SUB32_IMM
  | MUL32_IMM
  | OR32_IMM
  | AND32_IMM
  | NEG32_IMM
  | XOR32_IMM
  | MOV32_IMM => returnM true
  | ALU32_IMM_ILLEGAL => returnM false
  end.

Definition is_compcert_udiv (ins: int64): M state.state bool := returnM (is_compcert_udiv' ins).

Definition jit_verifier_opcode_alu32_reg (op: nat) (ins: int64) : M state.state bool :=
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
    do b <-  is_well_src ins;
      returnM b
  | ALU32_REG_ILLEGAL => returnM false
  end.

Definition jit_verifier_aux2 (pc len op: nat) (ins: int64) : M state.state bool :=
  match nat_to_opcode op with
  | ALU64  (**r 0xX7 / 0xXf *) =>
    if Int.eq Int.zero (Int.and (Int.repr (Z.of_nat op)) (Int.repr 8)) then
      do b <- bpf_verifier_opcode_alu64_imm op ins;
        returnM b
    else
      do b <- bpf_verifier_opcode_alu64_reg op ins;
        returnM b
  | ALU32  (**r 0xX4 / 0xXc *) =>
    if Int.eq Int.zero (Int.and (Int.repr (Z.of_nat op)) (Int.repr 8)) then
      do b <- jit_verifier_opcode_alu32_imm op ins;
        returnM b
    else
      do b <- jit_verifier_opcode_alu32_reg op ins;
        returnM b
  | Branch (**r 0xX5 / 0xXd *) =>
    if Int.eq Int.zero (Int.and (Int.repr (Z.of_nat op)) (Int.repr 8)) then
      do b <- bpf_verifier_opcode_branch_imm pc len op ins;
        returnM b
    else
      do b <- bpf_verifier_opcode_branch_reg pc len op ins;
        returnM b
  | LD_IMM (**r 0xX8 *)        => do b <- bpf_verifier_opcode_load_imm op ins; returnM b
  | LD_REG (**r 0xX1/0xX9 *)   => do b <- bpf_verifier_opcode_load_reg op ins; returnM b
  | ST_IMM (**r 0xX2/0xXa *)   => do b <- bpf_verifier_opcode_store_imm op ins; returnM b
  | ST_REG (**r 0xX3/0xXb *)   => do b <- bpf_verifier_opcode_store_reg op ins; returnM b
  | ILLEGAL => returnM false
  end.

Fixpoint jit_verifier_aux (pc len: nat): M state.state bool := (**r pc: len-1, len-2, ... 0 *)
    match pc with
    | O => returnM true
    | S n =>
      do ins <-  eval_ins (Int.repr (Z.of_nat n)); (**r len-pc: 0, 1, 2, etc... len -1 *)
      do b   <-  is_well_dst ins;
        if b then
          do op   <-  get_opcode ins;
          do b    <-  jit_verifier_aux2 n len op ins;
            if b then
              jit_verifier_aux n len
            else
              returnM false
        else
          returnM false
    end.

Definition jit_verifier: M state.state bool :=
  do len  <-  eval_ins_len;
  (**r (0, Int.max_unsigned/8): at least one instruction, and at most Int.max_unsigned/8 because of memory region *)
    if negb (Int.ltu (Int.repr (Z.of_nat len)) Int.one) then
      if negb
       (Int.ltu (Int.divu (Int.repr Int.max_unsigned) (Int.repr 8))
          (Int.repr (Z.of_nat len))) then
        do b <-  jit_verifier_aux len len;
          if b then
            do ins64 <-  eval_ins (Int.repr (Z.of_nat (len - 1)));
              returnM (Int64.eq ins64 (Int64.repr 0x95))
          else
            returnM false
      else
        returnM false
    else
      returnM false.

Close Scope monad_scope.
Close Scope nat_scope.