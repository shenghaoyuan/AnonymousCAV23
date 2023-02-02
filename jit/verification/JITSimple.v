From compcert Require Import Integers.
From compcert.arm Require Import AsmSyntax BinSyntax BinDecode.

From bpf.comm Require Import Flag BinrBPF ListAsArray Regs.
From bpf.model Require Import Encode Syntax.
From bpf.jit.thumb Require Import KeyValue2 LoadStoreRegs JITState.
From bpf.jit.thumb Require Import ThumbDecode Arm32Reg ThumbJITOpcode ThumbInsOp.

From Coq Require Import List ZArith Arith String.
Import ListNotations.
Open Scope Z_scope.
Open Scope bool_scope.
Open Scope asm.

(** List reprensent of LoadStoreRegs *)
(*
Lemma int64_repr_int_unsigned_same:
  forall x y,
    
    Int64.repr (Int.unsigned (Int.repr x)) = Int64.repr (Int.unsigned (Int.repr y)) ->
      x = y.
Proof.
  intros.
  Search Int64.repr.
  Transparent Int64.repr.
  injection H as Heq.
  rewrite ! Int64.Z_mod_modulus_eq in Heq.
  rewrite ! Zmod_small in Heq.
  Compute Int64.modulus.
Qed. *)

Fixpoint list_in_bool {A:Type} (eq: A -> A -> bool) (a:A) (l:list A) : bool :=
  match l with
    | [] => false
    | b :: m =>
      if eq a b then
        true
      else
        list_in_bool eq a m
  end.

Fixpoint app_no_repeat {A} (eq: A -> A -> bool) (l0 l1: list A): list A :=
  match l0 with
  | [] => l1
  | hd :: tl =>
    if list_in_bool eq hd l1 then
      app_no_repeat eq tl l1
    else
      hd :: (app_no_repeat eq tl l1)
  end.

Definition jit_alu32_load_aux_list (ins: bpf_instruction): option (list reg) :=
  match ins with
  | BPF_BINARY a bop dst src =>
    match a with
    | A32 =>
      match bop with
      | BPF_ADD | BPF_SUB | BPF_MUL | BPF_DIV | BPF_OR | BPF_AND | BPF_XOR | BPF_MOV
      | BPF_LSH | BPF_RSH | BPF_ARSH =>
        match src with
        | inl r => if reg_eqb dst r then Some [dst] else Some [dst; r]
        | inr i => Some [dst]
        end
      | BPF_MOD => None
      end
    | A64 => None
    end
  | _ => None
  end.

Definition jit_alu32_store_aux_list (ins: bpf_instruction): option reg :=
  match ins with
  | BPF_BINARY a bop _ src =>
    match a with
    | A32 =>
      match bop with
      | BPF_ADD | BPF_SUB | BPF_MUL | BPF_DIV | BPF_OR | BPF_AND | BPF_XOR | BPF_MOV
      | BPF_LSH | BPF_RSH | BPF_ARSH =>
        match src with
        | inl r => Some r
        | inr i => None
        end
      | BPF_MOD => None
      end
    | A64 => None
    end
  | _ => None
  end.

Fixpoint jit_alu32_load_list (l: list bpf_instruction): option (list reg) :=
  match l with
  | [] => Some []
  | hd :: tl =>
    match jit_alu32_load_list tl with
    | Some nl =>
      match jit_alu32_load_aux_list hd with
      | Some rl => Some (app_no_repeat reg_eqb rl nl)
      | None => None
      end
    | None => None
    end
  end.

Fixpoint jit_alu32_store_list (l: list bpf_instruction): option (list reg) :=
  match l with
  | [] => Some []
  | hd :: tl =>
    match jit_alu32_store_list tl with
    | Some nl =>
      match jit_alu32_store_aux_list hd with
      | Some r => if list_in_bool reg_eqb r nl then Some nl else Some (r :: nl)
      | None => None
      end
    | None => None
    end
  end.

Definition jit_alu32_use_IR11_aux (ins: bpf_instruction): bool :=
  match ins with
  | BPF_BINARY a bop _ src =>
    match a with
    | A32 =>
      match src with
      | inl r => false
      | inr i =>
        match bop with
        | BPF_ADD | BPF_SUB | BPF_OR | BPF_AND | BPF_XOR | BPF_MOV =>
          if (Int.cmp Cle Int.zero i) && (Int.cmp Cle i (Int.repr 255)) then
            false
          else
            true
        | BPF_MUL => true
        | BPF_DIV | BPF_LSH | BPF_RSH | BPF_MOD| BPF_ARSH => false
        end
      end
    | A64 => false
    end
  | _ => false
  end.

Fixpoint jit_alu32_use_IR11 (l: list bpf_instruction): bool :=
  match l with
  | [] => false
  | hd :: tl =>
    if jit_alu32_use_IR11_aux hd then
      true
    else
      jit_alu32_use_IR11 tl
  end.


Definition construct_thumb2_shift_rd_rm (rd rm: int): int :=
  let ins_rd := encode_arm32 rd rm 8 4 in
    encode_arm32 (Int.repr 0xf) ins_rd 12 4.

Definition jit_alu32_thumb_load_store_template_jit (op rt rn imm12: int) (st: jit_state): option jit_state :=
  let str_low   := encode_arm32 rn op 0 4 in
  let str_high  := encode_arm32 rt imm12 12 4 in
    match upd_jitted_list str_low st with
    | Some str_st => upd_jitted_list str_high str_st
    | None => None
    end.

(** * Pre Stage: ldr r12 [r1, #8] *)
Definition jit_alu32_pre (st: jit_state): option jit_state :=
  (* the allocation will do `STR IR12 [SP, #+0]` *)
  (**r LDR IR12 [R1, #8] *)
  jit_alu32_thumb_load_store_template_jit LDR_I_OP (Int.repr 12) Int.one (Int.repr 8) st.

(** * Spilling Stage: str ri [sp, #(i*4)] *)
Definition jit_alu32_thumb_upd_save (r: reg) (ldr_l str_l: list reg) (st: jit_state): option jit_state :=
  if (list_in_bool reg_eqb r ldr_l) || (list_in_bool reg_eqb r str_l) then
    let ir := (Int.repr (Z.of_nat (reg2nat r))) in
      jit_alu32_thumb_load_store_template_jit STR_I_OP ir
        (Int.repr (Z.of_nat (ireg2nat SP))) (Int.mul ir (Int.repr 4)) st
  else
    Some st.

Definition jit_alu32_thumb_save (ldr_l str_l: list reg) (st: jit_state): option jit_state :=
  match jit_alu32_thumb_upd_save R4 ldr_l str_l st with
  | Some R4_st =>
    match jit_alu32_thumb_upd_save R5 ldr_l str_l R4_st with
    | Some R5_st =>
      match jit_alu32_thumb_upd_save R6 ldr_l str_l R5_st with
      | Some R6_st =>
        match jit_alu32_thumb_upd_save R7 ldr_l str_l R6_st with
        | Some R7_st =>
          match jit_alu32_thumb_upd_save R8 ldr_l str_l R7_st with
          | Some R8_st =>
            match jit_alu32_thumb_upd_save R9 ldr_l str_l R8_st with
            | Some R9_st =>
              match jit_alu32_thumb_upd_save R10 ldr_l str_l R9_st with
              | Some R10_st =>
                if (use_IR11 st) then
                  jit_alu32_thumb_load_store_template_jit STR_I_OP (Int.repr 11)
                    (Int.repr (Z.of_nat (ireg2nat SP))) (Int.repr 44) R10_st
                else
                  Some R10_st
              | None => None
              end
            | None => None
            end
          | None => None
          end
        | None => None
        end
      | None => None
      end
    | None => None
    end
  | None => None
  end.

(** * Load Stage: Load selected BPF registers into corresponding arm32 registers *)
(*
Definition jit_alu32_thumb_upd_load (r: reg) (ldr_l: list reg) (st: jit_state): option jit_state :=
  if list_in_bool reg_eqb r ldr_l then
    let int_r     := Int.repr (Z.of_nat (reg2nat r)) in
      jit_alu32_thumb_load_store_template_jit LDR_I_OP int_r (Int.repr 12) (Int.mul int_r (Int.repr 8)) st
  else
    Some st.

Definition jit_alu32_thumb_load (ldr_l: list reg) (st: jit_state): option jit_state :=
  match jit_alu32_thumb_upd_load R10 ldr_l st with
  | Some R10_st =>
    match jit_alu32_thumb_upd_load R9 ldr_l R10_st with
    | Some R9_st =>
      match jit_alu32_thumb_upd_load R8 ldr_l R9_st with
      | Some R8_st =>
        match jit_alu32_thumb_upd_load R7 ldr_l R8_st with
        | Some R7_st =>
          match jit_alu32_thumb_upd_load R6 ldr_l R7_st with
          | Some R6_st =>
            match jit_alu32_thumb_upd_load R5 ldr_l R6_st with
            | Some R5_st =>
              match jit_alu32_thumb_upd_load R4 ldr_l R5_st with
              | Some R4_st =>
                match jit_alu32_thumb_upd_load R3 ldr_l R4_st with
                | Some R3_st =>
                  match jit_alu32_thumb_upd_load R2 ldr_l R3_st with
                  | Some R2_st =>
                    match jit_alu32_thumb_upd_load R1 ldr_l R2_st with
                    | Some R1_st =>
                      jit_alu32_thumb_upd_load R0 ldr_l R1_st
                    | None => None
                    end
                  | None => None
                  end
                  | None => None
                end
              | None => None
              end
            | None => None
            end
          | None => None
          end
        | None => None
        end
      | None => None
      end
    | None => None
    end
  | None => None
  end. *)

Definition jit_alu32_thumb_upd_load (r: reg) (st: jit_state): option jit_state :=
  let int_r     := Int.repr (Z.of_nat (reg2nat r)) in
    jit_alu32_thumb_load_store_template_jit LDR_I_OP int_r (Int.repr 12) (Int.mul int_r (Int.repr 8)) st.

Fixpoint jit_alu32_thumb_load (ldr_l: list reg) (st: jit_state): option jit_state :=
  match ldr_l with
  | [] => Some st
  | hd :: tl =>
    match jit_alu32_thumb_upd_load hd st with
    | Some st1 => jit_alu32_thumb_load tl st1
    | None => None
    end
  end.

(** * Jitted Code: from BPF alu32 to thumb alu *)


(**r move imm32 low16-bit to ireg *)

Definition mov_int_to_movw (i: int) (r: ireg) (st: jit_state): option jit_state :=
  let lo_imm8   := decode_arm32 i 0  8 in
  let lo_imm3   := decode_arm32 i 8  3 in
  let lo_i      := decode_arm32 i 11 1 in
  let lo_imm4   := decode_arm32 i 12 4 in
  let movw_lo_0 := encode_arm32 lo_imm4 MOVW_OP   0  4 in
  let movw_lo   := encode_arm32 lo_i    movw_lo_0 10 1 in

  let movw_hi_0 := encode_arm32 (int_of_ireg r) lo_imm8 8 4 in
  let movw_hi   := encode_arm32 lo_imm3 movw_hi_0 12 3 in
    match upd_jitted_list movw_lo st with
    | Some movw_st0 => upd_jitted_list movw_hi movw_st0
    | None => None
    end.

(**r move imm32 high16-bit to ireg *)

Definition mov_int_to_movt (i: int) (r: ireg) (st: jit_state): option jit_state :=
  let hi_imm8   := decode_arm32 i 16 8 in
  let hi_imm3   := decode_arm32 i 24 3 in
  let hi_i      := decode_arm32 i 27 1 in
  let hi_imm4   := decode_arm32 i 28 4 in
  let movt_lo_0 := encode_arm32 hi_imm4 MOVT_OP   0  4 in
  let movt_lo   := encode_arm32 hi_i    movt_lo_0 10 1 in

  let movt_hi_0 := encode_arm32 (int_of_ireg r) hi_imm8 8 4 in
  let movt_hi   := encode_arm32 hi_imm3 movt_hi_0 12 3 in
    match upd_jitted_list movt_lo st with
    | Some movt_st0 => upd_jitted_list movt_hi movt_st0
    | None => None
    end.

(** for alu32 reg *)
(**r src could be IR11 *)
Definition bpf_alu32_to_thumb_reg (bop: binOp) (dst: reg) (src: ireg) (st: jit_state): option jit_state :=
  match bop with
  | BPF_ADD =>
    let d       := if Int.lt (Int.repr (id_of_reg dst)) (Int.repr 8) then Int.zero else Int.one in
    let rdn     := if Int.lt (Int.repr (id_of_reg dst)) (Int.repr 8) then
                      (Int.repr (id_of_reg dst))
                    else
                      Int.sub (Int.repr (id_of_reg dst)) (Int.repr 8) in
    let ins_rdn := encode_arm32 rdn ADD_R_OP 0 3 in
    let ins_rm  := encode_arm32 (int_of_ireg src) ins_rdn 3 4 in
    let ins     := encode_arm32 d ins_rm 7 1 in
      upd_jitted_list ins st
  | BPF_SUB =>
    let ins_lo  := encode_arm32 (Int.repr (id_of_reg dst)) SUB_R_OP 0 4 in
    let ins_hi  := encode_arm32 (Int.repr (id_of_reg dst)) (int_of_ireg src) 8 4 in
      match upd_jitted_list ins_lo st with
      | Some ins_st0 => upd_jitted_list ins_hi ins_st0
      | None => None
      end
  | BPF_MUL =>
    let ins_lo  := encode_arm32 (Int.repr (id_of_reg dst)) MUL_OP 0 4 in
    let ins_hi0 := encode_arm32 (Int.repr (id_of_reg dst)) (int_of_ireg src) 8 4 in
    let ins_hi  := encode_arm32 (Int.repr 0xf) ins_hi0 12 4 in
      match upd_jitted_list ins_lo st with
      | Some ins_st0 => upd_jitted_list ins_hi ins_st0
      | None => None
      end
  | BPF_DIV =>
      match upd_jitted_list UDIV_OP st with
      | Some div_st0 => upd_jitted_list (Int.repr 0xf0f1) div_st0
      | None => None
      end
  | BPF_OR =>
    let ins_lo  := encode_arm32 (Int.repr (id_of_reg dst)) ORR_R_OP 0 4 in
    let ins_hi  := encode_arm32 (Int.repr (id_of_reg dst)) (int_of_ireg src) 8 4 in
      match upd_jitted_list ins_lo st with
      | Some ins_st0 => upd_jitted_list ins_hi ins_st0
      | None => None
      end
  | BPF_AND =>
    let ins_lo  := encode_arm32 (Int.repr (id_of_reg dst)) AND_R_OP 0 4 in
    let ins_hi  := encode_arm32 (Int.repr (id_of_reg dst)) (int_of_ireg src) 8 4 in
      match upd_jitted_list ins_lo st with
      | Some ins_st0 => upd_jitted_list ins_hi ins_st0
      | None => None
      end
  | BPF_LSH =>
    let lsl_lo  := encode_arm32 (Int.repr (id_of_reg dst)) LSL_R_OP 0 4 in
    let lsl_hi  := construct_thumb2_shift_rd_rm (Int.repr (id_of_reg dst)) (int_of_ireg src) in
      match upd_jitted_list lsl_lo st with
      | Some lsl_st0 => upd_jitted_list lsl_hi lsl_st0
      | None => None
      end
  | BPF_RSH =>
    let lsr_lo  := encode_arm32 (Int.repr (id_of_reg dst)) LSR_R_OP 0 4 in
    let lsr_hi  := construct_thumb2_shift_rd_rm (Int.repr (id_of_reg dst)) (int_of_ireg src) in
      match upd_jitted_list lsr_lo st with
      | Some lsr_st0 => upd_jitted_list lsr_hi lsr_st0
      | None => None
      end
  | BPF_MOD => None
  | BPF_XOR =>
    let ins_lo  := encode_arm32 (Int.repr (id_of_reg dst)) EOR_R_OP 0 4 in
    let ins_hi  := encode_arm32 (Int.repr (id_of_reg dst)) (int_of_ireg src) 8 4 in
      match upd_jitted_list ins_lo st with
      | Some ins_st0 => upd_jitted_list ins_hi ins_st0
      | None => None
      end
  | BPF_MOV =>
    let d       := if Int.lt (Int.repr (id_of_reg dst)) (Int.repr 8) then Int.zero else Int.one in
    let rdn     := if Int.lt (Int.repr (id_of_reg dst)) (Int.repr 8) then
                      (Int.repr (id_of_reg dst))
                    else
                      Int.sub (Int.repr (id_of_reg dst)) (Int.repr 8) in
    let ins_rdn := encode_arm32 rdn MOV_R_OP 0 3 in
    let ins_rm  := encode_arm32 (int_of_ireg src)  ins_rdn 3 4 in
    let ins     := encode_arm32 d ins_rm 7 1 in
      upd_jitted_list ins st
  | BPF_ARSH =>
    let asr_lo  := encode_arm32 (Int.repr (id_of_reg dst)) ASR_R_OP 0 4 in
    let asr_hi  := construct_thumb2_shift_rd_rm (Int.repr (id_of_reg dst)) (int_of_ireg src) in
      match upd_jitted_list asr_lo st with
      | Some asr_st0 => upd_jitted_list asr_hi asr_st0
      | None => None
      end
  end.

(** for alu32 imm *)
Definition bpf_alu32_to_thumb_imm0 (imm32: int) (bop: binOp) (dst: reg) (st: jit_state): option jit_state :=
  match bop with
  | BPF_ADD =>
    let ins_lo    := encode_arm32 (int_of_reg dst) ADD_I_OP 0 4 in
    let ins_hi    := encode_arm32 (int_of_reg dst) imm32 8 4 in
      match upd_jitted_list ins_lo st with
      | Some ins_st0 => upd_jitted_list ins_hi ins_st0
      | None => None
      end
  | BPF_SUB =>
    let ins_lo    := encode_arm32 (int_of_reg dst) SUB_I_OP 0 4 in
    let ins_hi    := encode_arm32 (int_of_reg dst) imm32 8 4 in
      match upd_jitted_list ins_lo st with
      | Some ins_st0 => upd_jitted_list ins_hi ins_st0
      | None => None
      end
  | BPF_MUL =>
    let st0 := mov_int_to_movw imm32 IR11 st in
      bpf_alu32_to_thumb_reg BPF_MUL dst IR11 st
  | BPF_OR  =>
    let ins_lo    := encode_arm32 (int_of_reg dst) ORR_I_OP 0 4 in
    let ins_hi    := encode_arm32 (int_of_reg dst) imm32 8 4 in
      match upd_jitted_list ins_lo st with
      | Some ins_st0 => upd_jitted_list ins_hi ins_st0
      | None => None
      end
  | BPF_AND =>
    let ins_lo    := encode_arm32 (int_of_reg dst) AND_I_OP 0 4 in
    let ins_hi    := encode_arm32 (int_of_reg dst) imm32 8 4 in
      match upd_jitted_list ins_lo st with
      | Some ins_st0 => upd_jitted_list ins_hi ins_st0
      | None => None
      end
  | BPF_XOR =>
    let ins_lo    := encode_arm32 (int_of_reg dst) EOR_I_OP 0 4 in
    let ins_hi    := encode_arm32 (int_of_reg dst) Int.zero 8 4 in
      match upd_jitted_list ins_lo st with
      | Some ins_st0 => upd_jitted_list ins_hi ins_st0
      | None => None
      end
  | BPF_MOV =>
    let ins_hi    := encode_arm32 (int_of_reg dst) imm32 8 4 in
      match upd_jitted_list MOVW_OP st with
      | Some ins_st0 => upd_jitted_list ins_hi ins_st0
      | None => None
      end
  | _ => None
  end.

Definition bpf_alu32_to_thumb_imm (bop: binOp) (dst: reg) (imm32: int) (st: jit_state): option jit_state :=
  let lo_32 := decode_arm32 imm32 0 16 in
  let hi_32 := decode_arm32 imm32 16 16 in
    if (Int.cmp Cle Int.zero imm32) && (Int.cmp Cle imm32 (Int.repr 255)) then
      bpf_alu32_to_thumb_imm0 imm32 bop dst st
    else 
      match mov_int_to_movw imm32 IR11 st with
      | Some st0 => 
        if Int.eq hi_32 Int.zero then
          bpf_alu32_to_thumb_reg bop dst IR11 st0
        else
          match mov_int_to_movt imm32 IR11 st0 with
          | Some st1 => bpf_alu32_to_thumb_reg bop dst IR11 st1
          | None => None
          end
      | None => None
      end.

Definition bpf_alu32_to_thumb (ins: bpf_instruction) (st: jit_state): option jit_state :=
  match ins with
  | BPF_BINARY a bop dst src =>
    match a with
    | A32 =>
      match src with
      | inl r => bpf_alu32_to_thumb_reg bop dst (ireg_of_reg r) st
      | inr i => bpf_alu32_to_thumb_imm bop dst i st
      end
    | A64 => None
    end
  | _ => None
  end.

Fixpoint jit_core (l: list bpf_instruction) (st: jit_state): option jit_state :=
  match l with
  | [] => Some st
  | hd :: tl =>
    match bpf_alu32_to_thumb hd st with
    | Some st0 => jit_core tl st0
    | None => None
    end
  end.

(** * Store Stage: Store selected arm32 registers into corresponding BPF registers *)

Definition jit_alu32_thumb_upd_store (r: reg) (str_l: list reg) (st: jit_state): option jit_state :=
  if list_in_bool reg_eqb r str_l then
    let int_r   := Int.repr (Z.of_nat (reg2nat r)) in
      jit_alu32_thumb_load_store_template_jit STR_I_OP int_r (Int.repr 12) (Int.mul int_r (Int.repr 8)) st
  else
    Some st.

(** @input
  * @jl : a part of the thumb state
  * @ls : record the info that which BPF register should be loaded or stored
  * @ptr: a pointer to the start address of the BPF state, and we know the offset of BPF registers and the flag

  * @output
  * @jl: new value of stack offset, pc and binary code
  *)

Definition jit_alu32_thumb_store (str_l: list reg) (st: jit_state): option jit_state :=
  match jit_alu32_thumb_upd_store R0 str_l st with
  | Some R0_st =>
    match jit_alu32_thumb_upd_store R1 str_l R0_st with
    | Some R1_st =>
      match jit_alu32_thumb_upd_store R2 str_l R1_st with
      | Some R2_st =>
        match jit_alu32_thumb_upd_store R3 str_l R2_st with
        | Some R3_st =>
          match jit_alu32_thumb_upd_store R4 str_l R3_st with
          | Some R4_st =>
            match jit_alu32_thumb_upd_store R5 str_l R4_st with
            | Some R5_st =>
              match jit_alu32_thumb_upd_store R6 str_l R5_st with
              | Some R6_st =>
                match jit_alu32_thumb_upd_store R7 str_l R6_st with
                | Some R7_st =>
                  match jit_alu32_thumb_upd_store R8 str_l R7_st with
                  | Some R8_st =>
                    match jit_alu32_thumb_upd_store R9 str_l R8_st with
                    | Some R9_st =>
                      jit_alu32_thumb_upd_store R10 str_l R9_st
                    | None => None
                    end
                  | None => None
                  end
                | None => None
                end
              | None => None
              end
            | None => None
            end
          | None => None
          end
        | None => None
        end
      | None => None
      end
    | None => None
    end
  | None => None
  end.


(** * Reloading Stage: recover the initial value of selected arm32 registers *)
Definition jit_alu32_thumb_upd_reset (r: reg) (ldr_l str_l: list reg) (st: jit_state): option jit_state :=
  if (list_in_bool reg_eqb r ldr_l) || (list_in_bool reg_eqb r str_l) then
    let ir := (Int.repr (Z.of_nat (reg2nat r))) in
      jit_alu32_thumb_load_store_template_jit LDR_I_OP ir
        (Int.repr (Z.of_nat (ireg2nat SP))) (Int.mul ir (Int.repr 4)) st
  else
    Some st.

Definition jit_alu32_thumb_reset (ldr_l str_l: list reg) (st: jit_state): option jit_state :=
  let option_R11_st :=
    if (use_IR11 st) then
      jit_alu32_thumb_load_store_template_jit LDR_I_OP
        (Int.repr 11) (Int.repr (Z.of_nat (ireg2nat SP))) (Int.repr 44) st
    else
      Some st in
  match option_R11_st with
  | Some R11_st =>
    match jit_alu32_thumb_upd_reset R10 ldr_l str_l R11_st with
    | Some R10_st =>
      match jit_alu32_thumb_upd_reset R9 ldr_l str_l R10_st with
      | Some R9_st =>
        match jit_alu32_thumb_upd_reset R8 ldr_l str_l R9_st with
        | Some R8_st =>
          match jit_alu32_thumb_upd_reset R7 ldr_l str_l R8_st with
          | Some R7_st =>
            match jit_alu32_thumb_upd_reset R6 ldr_l str_l R7_st with
            | Some R6_st =>
              match jit_alu32_thumb_upd_reset R5 ldr_l str_l R6_st with
              | Some R5_st =>
                jit_alu32_thumb_upd_reset R4 ldr_l str_l R5_st
              | None => None
              end
            | None => None
            end
          | None => None
          end
        | None => None
        end
      | None => None
      end
    | None => None
    end
  | None => None
  end.


(** Post: LDR SP [SP, #+0]; BX LR *)
Definition jit_alu32_post (st: jit_state): option jit_state :=
  (**r LDR SP [SP, #+0] *)
  match jit_alu32_thumb_load_store_template_jit LDR_I_OP (Int.repr (Z.of_nat (ireg2nat SP))) (Int.repr (Z.of_nat (ireg2nat SP))) Int.zero st with
  | Some st0 =>
    (**r BX LR *)
    let ins_rm   := encode_arm32 (Int.repr (Z.of_nat (ireg2nat RA))) BX_OP 3 4 in
      upd_jitted_list ins_rm st0
  | None => None
  end.

(** * Jit Procedure *)
Definition jit_alu32_to_thumb (l: list bpf_instruction) (st: jit_state): option jit_state :=
  let st0 := reset_init_jittedthumb st in
  let b   := jit_alu32_use_IR11 l in
  let st1 := upd_IR11_jittedthumb b st0 in
    match jit_alu32_load_list l with
    | Some ldr_l =>
      match jit_alu32_store_list l with
      | Some str_l =>
        match jit_alu32_pre st1 with
        | Some thumb_pre =>
          match jit_alu32_thumb_save ldr_l str_l thumb_pre with
          | Some thumb_save =>
            match jit_alu32_thumb_load ldr_l thumb_save with
            | Some thumb_load =>
              match jit_core l thumb_load with
              | Some thumb_core =>
                match jit_alu32_thumb_store str_l thumb_core with
                | Some thumb_store =>
                  match jit_alu32_thumb_reset ldr_l str_l thumb_store with
                  | Some thumb_reset => jit_alu32_post thumb_reset
                  | None => None
                  end
                | None => None
                end
              | None => None
              end
            | None => None
            end
          | None => None
          end
        | None => None
        end
      | None => None
      end
    | None => None
    end.

Close Scope string_scope.
Close Scope asm.
Close Scope bool_scope.
Close Scope Z_scope.