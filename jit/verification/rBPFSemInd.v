From compcert Require Import Memory Memtype Integers Values Ctypes AST.
From Coq Require Import ZArith Lia List.

From bpf.comm Require Import Flag rBPFValues Regs MemRegion rBPFAST rBPFMemType.
From bpf.model Require Import Syntax Decode.
From bpf.monadicmodel2 Require Import ConcreteState.


Open Scope Z_scope.
Import ListNotations.

(** * rBPF inductive semantics  *)

Definition eval_src (ri:reg+imm) (st: state): option val :=
  match ri with
  | inl r => eval_reg r st
  | inr i => Some (Val.longofint (sint32_to_vint i))
  end.

Definition eval_src32 (ri:reg+imm) (st: state): option val :=
  match ri with
  | inl r =>
    match eval_reg r st with
    | Some v => Some (val_intuoflongu v)
    | None => None
    end
  | inr i => Some (sint32_to_vint i)
  end.


Definition valid_ofs (ofs: int) (st: state): Prop :=
  Int.cmpu Clt (Int.add (pc_loc st) ofs) (Int.repr (Z.of_nat (ins_len st))) = true.

Definition arch2Z (a: arch):Z :=
  match a with
  | A32 => 32
  | A64 => 64
  end.

(**r bpf_op *)
Definition check_alu (a: arch) (op: binOp) (ri: reg+imm) (st: state): option bpf_flag :=
  match eval_src ri st with
  | Some src =>
    match op with
    | BPF_DIV | BPF_MOD =>
      if comp_ne_32 src Vzero then
        None
      else
        Some BPF_ILLEGAL_DIV
    | BPF_LSH | BPF_RSH | BPF_ARSH =>
      if compu_lt_32 (val_intuoflongu src) (Vint (Int.repr (arch2Z a))) then
        None
      else
        Some BPF_ILLEGAL_SHIFT
    | BPF_ADD | BPF_SUB | BPF_MUL | BPF_OR | BPF_AND | BPF_XOR | BPF_MOV => None
    end
  | None => None
  end.

Definition eval_alu_binary (a: arch) (op: binOp) (rd: reg) (ri: reg+imm) (st: state): option val :=
  match eval_reg rd st with
  | Some dst =>
    match a with
    | A32 =>
      let dst32 := val_intuoflongu dst in
        match eval_src32 ri st with
        | Some src32 =>
          match op with
          | BPF_ADD  => Some (Val.longofintu (Val.add  dst32 src32))
          | BPF_SUB  => Some (Val.longofintu (Val.sub  dst32 src32))
          | BPF_MUL  => Some (Val.longofintu (Val.mul  dst32 src32))
          | BPF_DIV  => match Val.divu dst32 src32 with
                        | Some res => Some (Val.longofintu res)
                        | None     => None
                        end
          | BPF_OR   => Some (Val.longofintu (Val.or   dst32 src32))
          | BPF_AND  => Some (Val.longofintu (Val.and  dst32 src32))
          | BPF_LSH  => Some (Val.longofintu (Val.shl dst32 src32))
          | BPF_RSH  => Some (Val.longofintu (Val.shru dst32 src32))
          | BPF_MOD  => match Val.modu dst32 src32 with
                        | Some res => Some (Val.longofintu res)
                        | None     => None
                        end
          | BPF_XOR  => Some (Val.longofintu (Val.xor  dst32 src32))
          | BPF_MOV  => Some (Val.longofintu src32)
          | BPF_ARSH => Some (Val.longofint (Val.shr  dst32 src32))
          end
        | None => None
        end
    | A64 =>
      match eval_src ri st with
      | Some src =>
        match op with
        | BPF_ADD  => Some (Val.addl  dst src)
        | BPF_SUB  => Some (Val.subl  dst src)
        | BPF_MUL  => Some (Val.mull  dst src)
        | BPF_DIV  => Val.divlu dst src
        | BPF_OR   => Some (Val.orl   dst src)
        | BPF_AND  => Some (Val.andl  dst src)
        | BPF_LSH  => Some (Val.shll dst src)
        | BPF_RSH  => Some (Val.shrlu dst src)
        | BPF_MOD  => Val.modlu dst src
        | BPF_XOR  => Some (Val.xorl  dst src)
        | BPF_MOV  => Some src
        | BPF_ARSH => Some (Val.shr  dst (val_intuoflongu src))
        end
      | None => None
      end
    end
  | None => None
  end.

Inductive rbpf_step: state -> bpf_instruction -> state -> Prop :=

  | step_alu_binary_normal: forall st a op rd ri ret st1
    (Hcheck_alu: check_alu a op ri st = None)
    (Heval_alu: eval_alu_binary a op rd ri st = Some ret)
    (Hupd_reg: upd_reg rd ret st = Some st1),
      rbpf_step st (BPF_BINARY a op rd ri) st1.

Inductive rbpf_sem: state -> list bpf_instruction -> state -> Prop :=
  | sem_alu_binary_refl: forall st,
      rbpf_sem st [] st
  | sem_alu_binary_star: forall st0 st1 st2 hd tl
      (Hone_step: rbpf_step st0 hd st1)
      (Hmany_steps: rbpf_sem st1 tl st2),
      rbpf_sem st0 (hd :: tl) st2.

Close Scope Z_scope.