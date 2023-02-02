From Coq Require Import List ZArith.
Import ListNotations.

From compcert Require Import Integers Values AST Memory.

From bpf.comm Require Import MemRegion rBPFValues rBPFAST rBPFMemType Flag Regs BinrBPF Monad.
From bpf.monadicmodel Require Import Opcode.
From bpf.monadicmodel2 Require Import ConcreteState rBPFMonadOp2 rBPFInterpreter2.

Open Scope monad_scope.

Definition step: M state unit :=
  do pc   <- eval_pc;
  do ins  <- eval_ins pc;
  do op   <- get_opcode_ins ins;
  do opc  <- get_opcode op;
  do dst  <- get_dst ins;
  match opc with
  | op_BPF_ALU64   =>
    do dst64  <- eval_reg dst;
      (**r #define BPF_INSTRUCTION_ALU_S_MASK      0x08 *)
    do src64  <- get_src64 op ins;
      step_opcode_alu64 dst64 src64 dst op                     (**r 0xX7 / 0xXf *)
  | op_BPF_Branch  =>
    do dst64  <- eval_reg dst;
    do ofs    <- get_offset ins;
      (**r #define BPF_INSTRUCTION_ALU_S_MASK      0x08 *)
    do src64  <- get_src64 op ins;
      step_opcode_branch dst64 src64 pc ofs op                    (**r 0xX5 / 0xXd *)
  | op_BPF_Mem_ld_imm  =>
    do dst64  <- eval_reg dst;
    do imm    <- get_immediate ins;
    step_opcode_mem_ld_imm imm dst64 dst op              (**r 0xX8 *)
  | op_BPF_Mem_ld_reg  =>
    do src    <- get_src ins;
    do src64  <- eval_reg src;
    do ofs    <- get_offset ins;
    do addr   <- get_addr_ofs src64 ofs;
    step_opcode_mem_ld_reg addr dst op       (**r 0xX1/0xX9 *)
  | op_BPF_Mem_st_imm  =>
    do dst64  <- eval_reg dst;
    do ofs    <- get_offset ins;
    do imm    <- get_immediate ins;
    do addr   <- get_addr_ofs dst64 ofs;
    step_opcode_mem_st_imm (sint32_to_vint imm) addr op       (**r 0xX2/0xXa *)
  | op_BPF_Mem_st_reg  =>
    do dst64  <- eval_reg dst;
    do src    <- get_src ins;
    do src64  <- eval_reg src;
    do ofs    <- get_offset ins;
    do addr <- get_addr_ofs dst64 ofs;
    step_opcode_mem_st_reg src64 addr op       (**r 0xX3/0xXb *)
  | _ => upd_flag (Vint (int_of_flag BPF_ILLEGAL_INSTRUCTION))
  end.

Fixpoint star_alu32 (fuel: nat): M state unit :=
  match fuel with
  | O => upd_flag (Vint (int_of_flag BPF_ILLEGAL_LEN))
  | S n =>
    do len  <- eval_ins_len;
    do pc   <- eval_pc;
      if (Int.ltu pc len) then (**r pc < len: pc is less than the length of l *)
        do ins  <- eval_ins pc;
        do op   <- get_opcode_ins ins;
        do opc  <- get_opcode op;
        do dst  <- get_dst ins;
        match opc with
        | op_BPF_ALU32   =>
          do dst64  <- eval_reg dst;
          do dst32  <- reg64_to_reg32 dst64;
          do src32  <- get_src32 op ins;
          do _      <- step_opcode_alu32 dst32 src32 dst op;
            star_alu32 n
        | _ => step
        end
      else
        upd_flag (Vint (int_of_flag BPF_ILLEGAL_LEN))
  end.

Fixpoint bpf_interpreter_aux (fuel: nat) {struct fuel}: M state unit :=
  match fuel with
  | O => upd_flag (Vint (int_of_flag BPF_ILLEGAL_LEN))
  | S n =>
    do len  <- eval_ins_len;
    do pc   <- eval_pc;
      if (Int.ltu pc len) then (**r pc < len: pc is less than the length of l *)
        do ins  <- eval_ins pc;
        do op   <- get_opcode_ins ins;
        do opc  <- get_opcode op;
        do _    <- match opc with
                  | op_BPF_ALU32   => star_alu32 (S n)
                  | _ => step
                  end;
        do f    <- eval_flag;
          if comp_eq_32 f (Vint (int_of_flag BPF_OK)) then
            do len0   <- eval_ins_len;
            do pc0    <- eval_pc;
              if (Int.ltu (Int.add pc0 Int.one) len0) then
                do _  <- upd_pc_incr;
                  bpf_interpreter_aux n
              else
                upd_flag (Vint (int_of_flag BPF_ILLEGAL_LEN))
          else
            returnM tt
      else
        upd_flag (Vint (int_of_flag BPF_ILLEGAL_LEN))
  end.

Definition bpf_interpreter (fuel: nat): M state val :=
  do _        <- bpf_interpreter_aux fuel;
  do f        <- eval_flag;
    if comp_eq_32 f (Vint (int_of_flag BPF_SUCC_RETURN)) then
      do res  <- eval_reg R0;
        returnM res
    else
      returnM (Vlong Int64.zero).

Section Simulation.
  Theorem bpf_interpreter_star_alu32:
    forall fuel st,
      rBPFInterpreter2.bpf_interpreter fuel st = bpf_interpreter fuel st.
  Proof.
  unfold rBPFInterpreter2.bpf_interpreter, bpf_interpreter.
  unfold bindM, returnM.
  induction fuel.
  - intros; simpl.
    reflexivity.
  - intros; simpl.
    unfold bindM, returnM.
    unfold eval_ins_len.
    unfold eval_pc.
    destruct Int.ltu eqn: Hlt; [| reflexivity].
    unfold rBPFInterpreter2.step, step.
    unfold bindM, returnM.
    unfold eval_pc.
    unfold eval_ins.
    destruct Int.cmpu eqn: Hlt1; [| reflexivity].
    destruct ConcreteState.eval_ins eqn: Hins; [| reflexivity].
    unfold get_opcode_ins, bindM, returnM.
    unfold get_opcode, bindM, returnM.
    destruct byte_to_opcode eqn: Hopcode; try rewrite Hlt1, Hins.
    + (**r ALU64 *)
      unfold get_dst, int64_to_dst_reg.
      destruct int64_to_dst_reg'; [| reflexivity].
      rewrite Hopcode.
      unfold eval_reg.
      destruct ConcreteState.eval_reg; [| reflexivity].
      unfold get_src64.
      unfold bindM, returnM.
      destruct Int.eq.
      * unfold get_immediate, eval_immediate, returnM.
        destruct step_opcode_alu64 eqn: Halu64;
        [ destruct p;
          unfold eval_flag;
          destruct ConcreteState.eval_flag;
          [ destruct comp_eq_32;
            [ clear Hlt;
              destruct Int.ltu eqn: Hlt;
              [ destruct upd_pc_incr;
                [ destruct p;
                  unfold eval_flag in IHfuel;
                  apply IHfuel |
                  reflexivity] |
                reflexivity] |
              reflexivity] |
            reflexivity] |
          reflexivity].
      * unfold get_src, int64_to_src_reg.
        destruct int64_to_src_reg'; [| reflexivity].
        unfold eval_reg.
        destruct ConcreteState.eval_reg; [| reflexivity].
        destruct step_opcode_alu64 eqn: Halu64; [| reflexivity].
        destruct p.
        unfold eval_flag.
        destruct ConcreteState.eval_flag; [| reflexivity].
        destruct comp_eq_32; [| reflexivity].
        clear Hlt.
        destruct Int.ltu eqn: Hlt; [| reflexivity].
        destruct upd_pc_incr; [| reflexivity].
        destruct p.
        unfold eval_flag in IHfuel.
        apply IHfuel.
    + (**r ALU32 *)
      unfold get_dst, eval_reg, reg64_to_reg32, get_src32.
      unfold int64_to_dst_reg.
      rewrite Hlt, Hlt1, Hins, Hopcode.
      destruct int64_to_dst_reg'; [| reflexivity].
      destruct ConcreteState.eval_reg; [| reflexivity].
      unfold bindM, returnM.
      destruct Int.eq.
      * unfold get_immediate, eval_flag, returnM.
        destruct step_opcode_alu32 eqn: Halu32; [| reflexivity].
        destruct p.
        destruct ConcreteState.eval_flag eqn: Hflag.
        { destruct comp_eq_32 eqn: Heq.
          - destruct (Int.ltu _ (ConcreteState.eval_ins_len s)) eqn: Hlt2.
            + destruct upd_pc_incr eqn: Hpc.
              destruct p.
              unfold eval_flag in IHfuel.
              rewrite IHfuel.
              clear - Hpc.
              induction fuel.
              * simpl.
                admit.
              * simpl.
                unfold bindM, returnM.
        }
        admit.
      * 
      ...
    + (**r Branch *)
      unfold get_dst, eval_reg, get_offset, get_src64, int64_to_dst_reg.
      destruct int64_to_dst_reg'; [| reflexivity].
      rewrite Hopcode.
      destruct ConcreteState.eval_reg; [| reflexivity].
      unfold bindM, returnM.
      destruct Int.eq.
      * unfold get_immediate, eval_immediate, returnM.
        destruct step_opcode_branch eqn: Hbranch; [| reflexivity].
        destruct p.
        unfold eval_flag.
        destruct ConcreteState.eval_flag; [| reflexivity].
        destruct comp_eq_32; [| reflexivity].
        clear Hlt.
        destruct Int.ltu eqn: Hlt; [| reflexivity].
        destruct upd_pc_incr; [| reflexivity].
        destruct p.
        unfold eval_flag in IHfuel.
        apply IHfuel.
      * unfold get_src, int64_to_src_reg.
        destruct int64_to_src_reg'; [| reflexivity].
        unfold eval_reg.
        destruct ConcreteState.eval_reg; [| reflexivity].
        destruct step_opcode_branch eqn: Hbranch; [| reflexivity].
        destruct p.
        unfold eval_flag.
        destruct ConcreteState.eval_flag; [| reflexivity].
        destruct comp_eq_32; [| reflexivity].
        clear Hlt.
        destruct Int.ltu eqn: Hlt; [| reflexivity].
        destruct upd_pc_incr; [| reflexivity].
        destruct p.
        unfold eval_flag in IHfuel.
        apply IHfuel.
    + (**r Mem_ld_imm *)
      ...
      reflexivity.
      admit.
    + reflexivity.
  Qed.
End Simulation.

Close Scope monad_scope.