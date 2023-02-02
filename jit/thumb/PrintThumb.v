From compcert Require Import Integers AST Ctypes.
From compcert.arm Require Import AsmSyntax BinSyntax.

From Coq Require Import ZArith Ascii String HexString List.
Import ListNotations.

From bpf.model Require Import PrintrBPF.

(** This module is used to print arm32 instructions *)

Definition string_of_ireg (r: ireg): string :=
  match r with
  | IR0 => "r0"
  | IR1 => "r1"
  | IR2 => "r2"
  | IR3 => "r3"
  | IR4 => "r4"
  | IR5 => "r5"
  | IR6 => "r6"
  | IR7 => "r7"
  | IR8 => "r8"
  | IR9 => "r9"
  | IR10 => "r10"
  | IR11 => "r11"
  | IR12 => "r12"
  | IR13 => "sp"
  | IR14 => "lr"
  end.

Definition string_of_ptrofs_signed (ofs: ptrofs): string :=
  of_Z (Ptrofs.signed ofs).

Definition string_of_shift_op (sop: shift_op): string :=
  match sop with
  | SOimm i => "#" ++ string_of_int_unsigned i
  | SOreg r => string_of_ireg r
  | _ => "shift op error: not now"
  end.

Definition print_arm32_instruction (ins: instruction) (pc: int) : string :=
  match ins with
  | Padd dst src sop => "add " ++ (string_of_ireg dst) ++ ", " ++ (string_of_ireg src) ++ ", " ++ (string_of_shift_op sop)
  | Pand dst src sop => "and.w " ++ (string_of_ireg dst) ++ ", " ++ (string_of_ireg src) ++ ", " ++ (string_of_shift_op sop)

  | Pasr dst src rop => "asr " ++ (string_of_ireg dst) ++ ", " ++ (string_of_ireg src) ++ ", " ++ (string_of_ireg rop)

  | Pb imm24         => "b.n " ++ (string_of_ptrofs_signed (Ptrofs.add (Ptrofs.add (Ptrofs.mul imm24 (Ptrofs.repr 2)) (Ptrofs.of_int pc)) (Ptrofs.repr 4)))

  | Pbreg dst        => "bx " ++ (string_of_ireg dst)

  | Pcmp dst sop     => "cmp.w " ++ (string_of_ireg dst) ++ ", " ++ (string_of_shift_op sop)

  | Peor dst src sop => "eor " ++ (string_of_ireg dst) ++ ", " ++ (string_of_ireg src) ++ ", " ++ (string_of_shift_op sop)

  | Pldr dst src sop => "ldr.w " ++ (string_of_ireg dst) ++ ", [" ++ (string_of_ireg src) ++ ", " ++ (string_of_shift_op sop) ++ "]"

  | Plsl dst src rop => "lsl.w " ++ (string_of_ireg dst) ++ ", " ++ (string_of_ireg src) ++ ", " ++ (string_of_ireg rop)
  | Plsr dst src rop => "lsr.w " ++ (string_of_ireg dst) ++ ", " ++ (string_of_ireg src) ++ ", " ++ (string_of_ireg rop)

  | Pmov  dst sop    => "mov " ++ (string_of_ireg dst) ++ ", " ++ (string_of_shift_op sop)
  | Pmovw dst imm16  => "movw " ++ (string_of_ireg dst) ++ ", #" ++ (string_of_int_unsigned imm16)
  | Pmovt dst imm16  => "movt " ++ (string_of_ireg dst) ++ ", #" ++ (string_of_int_unsigned imm16)

  | Porr dst src sop => "orr.w " ++ (string_of_ireg dst) ++ ", " ++ (string_of_ireg src) ++ ", " ++ (string_of_shift_op sop)
  | Prsb dst src sop => "rsb.w " ++ (string_of_ireg dst) ++ ", " ++ (string_of_shift_op sop) ++ ", " ++ (string_of_ireg src)
  | Psub dst src sop => "sub.w " ++ (string_of_ireg dst) ++ ", " ++ (string_of_ireg src) ++ ", " ++ (string_of_shift_op sop)

  | Pstr dst src sop => "str.w " ++ (string_of_ireg dst) ++ ", [" ++ (string_of_ireg src) ++ ", " ++ (string_of_shift_op sop) ++ "]"
  | Pudiv            => "div r0, r0, r1"
  | _ => "not yet"
  end.

Definition is_thumb (ins: instruction): bool :=
  match ins with
  | Padd _ _ sop
  | Pcmp _ sop
  | Pmov _ sop   => match sop with | SOreg _ => true | _ => false end
  | Pb _
  | Pbreg _      => true
  | _ => false
  end.

Fixpoint print_arm32_prog_aux (id: int) (pc: nat) (l: list instruction): list string :=
  match l with
  | [] => []
  | hd :: tl =>
    let ins_string := print_arm32_instruction hd id in
      if is_thumb hd then
        List.app [((of_Z (Int.unsigned id)) ++ ": " ++ ins_string)%string] (print_arm32_prog_aux (Int.add id (Int.repr 2)) (S pc) tl)
      else
        List.app [((of_Z (Int.unsigned id)) ++ ": " ++ ins_string)%string] (print_arm32_prog_aux (Int.add id (Int.repr 4)) (S pc) tl)
  end.

(**r phyical_start_addr is used to set the real-world start_address of jitted code: for debugging *)
Definition print_arm32_prog (l: list instruction) (phyical_start_addr: int): list string :=
  print_arm32_prog_aux phyical_start_addr 0 l.
