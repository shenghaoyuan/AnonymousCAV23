From Coq Require Import List ZArith Lia.
From compcert Require Import Integers Values AST Memory Memdata.

From bpf.comm Require Import Flag Regs State Monad rBPFMonadOp rBPFMemType rBPFValues LemmaInt.

From bpf.monadicmodel Require Import Opcode.
From bpf.monadicmodel2 Require Import ConcreteState rBPFMonadOp2 rBPFInterpreter2.


Open Scope monad_scope.
Fixpoint step_alu32 (fuel: nat) : M state unit :=
  match fuel with
  | O => returnM tt
  | S n =>
    do pc   <- eval_pc;
    do ins  <- eval_ins pc;
    do op   <- get_opcode_ins ins;
    do opc  <- get_opcode op;
    do dst  <- get_dst ins;
      match opc with
      | op_BPF_ALU32 =>
        do dst64  <- eval_reg dst;
        do dst32  <- reg64_to_reg32 dst64;
        do src32  <- get_src32 op ins;
        do _      <- step_opcode_alu32 dst32 src32 dst op;
        do f      <- eval_flag;
          if comp_eq_32 f (Vint (int_of_flag BPF_OK)) then
            do len  <- eval_ins_len;
            do pc   <- eval_pc;
              if (Int.ltu (Int.add pc Int.one) len) then
                do _ <- upd_pc_incr;
                  step_alu32 n
              else
                upd_flag (Vint (int_of_flag BPF_ILLEGAL_LEN))
          else
            returnM tt
      | _ => upd_flag (Vint (int_of_flag BPF_ILLEGAL_INSTRUCTION))
      end
  end.
Close Scope monad_scope.