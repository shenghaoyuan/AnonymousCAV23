From compcert Require Import Integers.
From compcert.arm Require Import AsmSyntax BinSyntax BinDecode.

From bpf.comm Require Import Flag BinrBPF ListAsArray Regs.
From bpf.model Require Import Encode.
From bpf.jit.thumb Require Import KeyValue2 LoadStoreRegs JITState.
From bpf.jit.thumb Require Import ThumbEncode ThumbDecode Arm32Reg ThumbJITOpcode ThumbInsOp.

From Coq Require Import List ZArith Arith String.
Import ListNotations.
Open Scope Z_scope.
Open Scope bool_scope.
Open Scope asm.
Open Scope string_scope.

(** * ARM IR12 is FP for CompCert *)

(** * Functions in ARM *)

(** It consists of:
1. Prologue: (PUSH+ADD+SUB) save the previous state of the program (by storing values of LR and R11 onto the Stack) and set up the Stack for the local variables of the function. 
2. Body
3. Epilogue: (SUB+POP) restore the program’s state to it’s initial one (before the function call) so that it can continue from where it left of. For that we need to readjust the Stack Pointer.

However, in our jitted thumb code, we adopt a non-standard calling conversion, or, in other word, our `self-defined calling conversion`.
*)

(** * ARM32 Stack Frame Layout *)

(** Since 2022-10-18, we decide to adopt a static ARMReg-stack mapping relation that is used for the SAVE & RESET stage:
  IR_i <---> Stack [i*4, i*4+4) where i \in [4,11]
  BTW,
  - Stack[ 0, 4) = old SP (** done by compcertbin / user-defined magic function *)
  - Stack[ 4, 8) = current r1 value (** if r1 is used before, we need to save it firstly, then use it as flag_addr to modify bpf_flag, and finally recover r1 *)
  - Stack[ 8,12) = flag_addr
  - Stack[12,16) = unused
 *)

(**

In current version, we consider stack as a special memory, so we just do load and store but never modify fp & sp, it is ok because we only has BPF alu32. We should modify this strategy if we consider BPF call instruction.

CompCertBin will allocate a new block (where save the IR, i.e. IR12, i.e. the old SP into the location 0) for jitted thumb, and it will start from 0!!!

 high addr
+---------+ * stack_size = 12 * 4
/  R11   /
/        /
/  R4    /
/ unused /
/ unused /
/   R1   /
/ old SP /
+---------+  (<--- SP) * current SP points to here
 low addr


+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
| R0 | R1 | -  | -  | -  | -  | -  | -  | -  | -  | -  | FP | IP | SP | RA | PC |
+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+

==> // move R1 to IR12 (now IR12 stores the starting address of bpf state)

+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
| R0 | R1 | -  | -  | -  | -  | -  | -  | -  | -  | -  | FP | IP | SP | RA | PC |
+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+

==> // calling conversion (save all related registers from R0-R10 into the stack, may save FP)

+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
| R0 | R1 | R2 | R3 | R4 | R5 | R6 | R7 | R8 | R9 | R10| FP | IP | SP | RA | PC |
+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+

Now R0-R10 are ready for loading rBPF related registers.
*)


(** * Mapping from rBPF Registers to ARM32 Registers

rBPF ---> ARM32
R0         R0
   ...
R10        R10


We DO accept if dst or src is R10.
 *)


(** * Jitted ARM Instructions
For each jitted thumb instruction segment, it has the following structure:

ldr r12, [r1, #8];                         (**r Pre  Stage *)
str ri,  [sp, #(i*4)];                     (**r Save Stage *) i \in [4-11]
ldr ri,  [r12, #(i*8)];                    (**r Load Stage *) i \in[0, 10]
jitted thumb;                              (**r Jitted Stage *)
str ri,  [r12, #(i*8)];                    (**r Store Stage *) i \in[0, 10]
ldr ri,  [sp, #(i*4)];                     (**r Reset Stage *) i \in [4-11]
ldr sp,  [sp, #0]; bx lr                   (**r Post Stage *)

where
1) Pre  Stage: use arm32 IR12 as the start address of the BPF register map;
2) Save Stage: store selected arm32 registers into the stack; (i.e. calling conversion)
3) Load Stage: load related BPF registers (only low 32-bits) into arm32 registers;
4) Jitted Stage: generate core BPF-alu32-jitted thumb code;
5) Store Stage: store related arm32 registers into BPF registers (high 32-bits all 0);
6) Reset Stage: recover related arm32 registers from the stack;  (i.e. calling conversion)
7) Post Stage: recover the arm32 IR12 register and jump.

so, before call jitted thumb code, the initial thumb state has the information that:
- a special arm register (let's say IR12) points to the start address of the rBPF register map.
- Ri points to the corresponding BPF Ri

 *)

(**r let's say IR12 storing the start address of the rBPF state *)
(**r we will use this one as an additional register for the src of BPF_ALU32_IMM because CompCert ARM32 uses IR12 as frame pointer, so we have no choice but only use IR11 as IP. *)

(**r MUST div by 2 before call `construct_thumb_b` because of `P label` where label = imm8:'0' *)
Definition construct_thumb_b (cd imm8: int): int :=
  let ins_imm8 := encode_arm32 imm8 B_OP 0 8 in
    encode_arm32 cd ins_imm8 8 4.

Definition construct_thumb2_shift_rd_rm (rd rm: int): int :=
  let ins_rd := encode_arm32 rd rm 8 4 in
    encode_arm32 (Int.repr 0xf) ins_rd 12 4.

Definition jit_alu32_thumb_store_template_ins (rt rn imm12: int) (st: jit_state): jit_state :=
  let str_low   := encode_arm32 rn STR_I_OP 0 4 in
  let str_high  := encode_arm32 rt imm12 12 4 in
  let str_st    := add_ins_jittedthumb str_low st in
    add_ins_jittedthumb str_high str_st.
(**r TODO: we could merge them *)
Definition jit_alu32_thumb_load_template_ins (rt rn imm12: int) (st: jit_state): jit_state :=
  let str_low   := encode_arm32 rn LDR_I_OP 0 4 in
  let str_high  := encode_arm32 rt imm12 12 4 in
  let str_st    := add_ins_jittedthumb str_low st in
    add_ins_jittedthumb str_high str_st.

Definition jit_alu32_thumb_store_template_jit (rt rn imm12: int) (st: jit_state): option jit_state :=
  let str_low   := encode_arm32 rn STR_I_OP 0 4 in
  let str_high  := encode_arm32 rt imm12 12 4 in
    match upd_jitted_list str_low st with
    | Some str_st => upd_jitted_list str_high str_st
    | None => None
    end.

Definition jit_alu32_thumb_load_template_jit (rt rn imm12: int) (st: jit_state): option jit_state :=
  let str_low   := encode_arm32 rn LDR_I_OP 0 4 in
  let str_high  := encode_arm32 rt imm12 12 4 in
    match upd_jitted_list str_low st with
    | Some str_st => upd_jitted_list str_high str_st
    | None => None
    end.

(** @input
  * @r   : an integer representing the flag

  * @output
  * @ins :  binary format of `str f [IR12, #+ofs]` where
  * - IR12 stores the start address of BPF state
  * - ofs = BPF_R0_OFS + 4

  * @brief
  * store an expected flag into the BPF flag

mov r11, #f
str r1, [sp, #4] *
ldr r1, [r12, #4]
str r11, [r1, #0]
ldr r1, [sp, #4] *

where * is optional

  *)

Definition jit_alu32_store_flag (f: int) (st: jit_state): jit_state :=
  
  (**r because f is very small, i.e. \in [0,16], so we only consider imm8 *)
  (**r mov IR11 f *)
  let movw_hi   := encode_arm32 (Int.repr 11) f 8 4 in
  let mov_st0   := add_ins_jittedthumb MOVW_OP st in
  let st0       := add_ins_jittedthumb movw_hi mov_st0 in

  (**r if r1 is used, save the current value of r1 to Stack[4, 8)  *)
  let st1       :=
    if (is_non_reg R1 (load_store_regs st0)) then
      jit_alu32_thumb_store_template_ins Int.one (Int.repr 13) (Int.repr 4) st0
    else
      st0
    in

  (**r ldr r1, [r12, #4] *)
  let st2       := jit_alu32_thumb_load_template_ins Int.one (Int.repr 12) (Int.repr 4) st1 in

  (**r str r11, [r1, #0] *)
  let st3       := jit_alu32_thumb_store_template_ins (Int.repr 11) Int.one Int.zero st2 in

  (**r if r1 is used, recover the current value of r1 from Stack[4, 8)  *)
    if (is_non_reg R1 (load_store_regs st3)) then
      jit_alu32_thumb_load_template_ins Int.one (Int.repr 13) (Int.repr 4) st3
    else
      st3.


(** * Pre Stage: mov *)

Definition jit_alu32_pre (st: jit_state): option jit_state :=
  (* the allocation will do `STR IR12 [SP, #+0]` *)
  (**r LDR IR12 [R1, #8] *)
  jit_alu32_thumb_load_template_jit (Int.repr 12) Int.one (Int.repr 8) st.

(** * Save Stage: Save previous arm32 registers *)

(** we consider stack as a special memory to store everything we want and because we don't do call, we never modify the value of arm32's SP. *)

(** @input
  * @r  : push register r into the stack[r*4, r*4+4)
  * @st : initial state
  * @ls : load and store related-registers

  * @output
  * @st :  new state with binary format of `str r [sp, #+ofs]` where we use `str` to implement `push`
  *)

Definition jit_alu32_thumb_upd_save (r: reg) (st: jit_state): option jit_state :=
  if is_non_reg r (load_store_regs st) then
    let ir := (Int.repr (Z.of_nat (reg2nat r))) in
      jit_alu32_thumb_store_template_jit ir (Int.repr (Z.of_nat (ireg2nat SP))) (Int.mul ir (Int.repr 4)) st
  else
    Some st.

(** @input
  * @st: current location of the pointer of jarm * current jitted binary thumb code

  * @output
  * @st: new value of stack offset, pc and binary code

  * @brief
  * NB: because of ARM calling conversion, we only consider r \in [4, 11]
  *)
Definition jit_alu32_thumb_save (st: jit_state): option jit_state :=
  match jit_alu32_thumb_upd_save R4  st with
  | Some R4_st =>
    match jit_alu32_thumb_upd_save R5  R4_st with
    | Some R5_st =>
      match jit_alu32_thumb_upd_save R6  R5_st with
      | Some R6_st =>
        match jit_alu32_thumb_upd_save R7  R6_st with
        | Some R7_st =>
          match jit_alu32_thumb_upd_save R8  R7_st with
          | Some R8_st =>
            match jit_alu32_thumb_upd_save R9  R8_st with
            | Some R9_st =>
              match jit_alu32_thumb_upd_save R10 R9_st with
              | Some R10_st =>
                if (use_IR11 st) then
                  jit_alu32_thumb_store_template_jit (Int.repr 11)
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

(** @input
  * @r  : load BPF register r (low 32-bits) into arm32 register r
  * @st : initial state
  * @ls : load and store related-registers

  * @output
  * @st : new state with binary format of `ldr r [IR12, #+ofs]` where
  * - IR12 stores the start address of BPF state
  * - ofs = r * 8
  *)
Definition jit_alu32_thumb_upd_load (r: reg) (st: jit_state): option jit_state :=
  if is_load_reg r (load_store_regs st) then
    let int_r     := Int.repr (Z.of_nat (reg2nat r)) in
      jit_alu32_thumb_load_template_jit int_r (Int.repr 12) (Int.mul int_r (Int.repr 8)) st
  else
    Some st.

Definition no_reg_load (st: jit_state): bool :=
  if is_load_reg R0 (load_store_regs st) then false
  else if is_load_reg R1 (load_store_regs st) then false
  else if is_load_reg R2 (load_store_regs st) then false
  else if is_load_reg R3 (load_store_regs st) then false
  else if is_load_reg R4 (load_store_regs st) then false
  else if is_load_reg R5 (load_store_regs st) then false
  else if is_load_reg R6 (load_store_regs st) then false
  else if is_load_reg R7 (load_store_regs st) then false
  else if is_load_reg R8 (load_store_regs st) then false
  else if is_load_reg R9 (load_store_regs st) then false
  else if is_load_reg R10 (load_store_regs st) then false
  else
    true.

(** @input
  * @jl : a part of the thumb state
  * @ls : record the info that which BPF register should be loaded or stored
  * @ptr: a pointer to the start address of the BPF state, and we know the offset of BPF registers and the flag

  * @output
  * @jl: new value of stack offset, pc and binary code

  * @brief
  * NB: ldr r0, [r12 #8]; ldr ri, [r0, #(i*8)]; here i should be from high to low [10, 0]
  *)
Definition jit_alu32_thumb_load (st: jit_state): option jit_state :=
  if no_reg_load st then
    (**r this case: we don't need any infomation from bpf register maps *)
    Some st
  else
    match jit_alu32_thumb_upd_load R10 st with
    | Some R10_st =>
      match jit_alu32_thumb_upd_load R9  R10_st with
      | Some R9_st =>
        match jit_alu32_thumb_upd_load R8  R9_st with
        | Some R8_st =>
          match jit_alu32_thumb_upd_load R7  R8_st with
          | Some R7_st =>
            match jit_alu32_thumb_upd_load R6  R7_st with
            | Some R6_st =>
              match jit_alu32_thumb_upd_load R5  R6_st with
              | Some R5_st =>
                match jit_alu32_thumb_upd_load R4  R5_st with
                | Some R4_st =>
                  match jit_alu32_thumb_upd_load R3  R4_st with
                  | Some R3_st =>
                    match jit_alu32_thumb_upd_load R2  R3_st with
                    | Some R2_st =>
                      match jit_alu32_thumb_upd_load R1  R2_st with
                      | Some R1_st =>
                        jit_alu32_thumb_upd_load R0 R1_st
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

(** * Jitted Code: from BPF alu32 to thumb alu *)

(** for alu32 reg *)

(**r src could be IR11 *)
Definition bpf_alu32_to_thumb_reg (op: opcode_alu32_reg) (dst: reg) (src: ireg) (st: jit_state): option jit_state :=
  match op with
  | BPF_ADD32_REG =>
    let d       := if Int.lt (Int.repr (id_of_reg dst)) (Int.repr 8) then Int.zero else Int.one in
    let rdn     := if Int.lt (Int.repr (id_of_reg dst)) (Int.repr 8) then
                      (Int.repr (id_of_reg dst))
                    else
                      Int.sub (Int.repr (id_of_reg dst)) (Int.repr 8) in
    let ins_rdn := encode_arm32 rdn ADD_R_OP 0 3 in
    let ins_rm  := encode_arm32 (int_of_ireg src) ins_rdn 3 4 in
    let ins     := encode_arm32 d ins_rm 7 1 in
    let ins_st  := add_ins_jittedthumb ins st in
      match upd_load_store_regs_jittedthumb dst LoadAndStore ins_st with
      | None => None (**r TODO: proving this is impossible *)
      | Some ldr_st =>
        if ireg_eqb src IR11 then
          Some ldr_st
        else
          match reg_of_ireg src with
          | Some r => upd_load_store_regs_jittedthumb r LoadPerm ldr_st
          | None => None (**r TODO: proving this is impossible *)
          end
      end

  | BPF_SUB32_REG =>
    let ins_lo  := encode_arm32 (Int.repr (id_of_reg dst)) SUB_R_OP 0 4 in
    let ins_hi  := encode_arm32 (Int.repr (id_of_reg dst)) (int_of_ireg src) 8 4 in
    let ins_st0 := add_ins_jittedthumb ins_lo st in
    let ins_st  := add_ins_jittedthumb ins_hi ins_st0 in
      match upd_load_store_regs_jittedthumb dst LoadAndStore ins_st with
      | None => None (**r TODO: proving this is impossible *)
      | Some ldr_st =>
        if ireg_eqb src IR11 then
          Some ldr_st
        else
          match reg_of_ireg src with
          | Some r =>
            upd_load_store_regs_jittedthumb r LoadPerm ldr_st
          | None => None (**r TODO: proving this is impossible *)
          end
      end

  | BPF_MUL32_REG =>
    let ins_lo  := encode_arm32 (Int.repr (id_of_reg dst)) MUL_OP 0 4 in
    let ins_hi0 := encode_arm32 (Int.repr (id_of_reg dst)) (int_of_ireg src) 8 4 in
    let ins_hi  := encode_arm32 (Int.repr 0xf) ins_hi0 12 4 in
    let ins_st0 := add_ins_jittedthumb ins_lo st in
    let ins_st  := add_ins_jittedthumb ins_hi ins_st0 in
      match upd_load_store_regs_jittedthumb dst LoadAndStore ins_st with
      | None => None (**r TODO: proving this is impossible *)
      | Some ldr_st =>
        if ireg_eqb src IR11 then
          Some ldr_st
        else
          match reg_of_ireg src with
          | Some r => upd_load_store_regs_jittedthumb r LoadPerm ldr_st
          | None => None (**r TODO: proving this is impossible *)
          end
      end

  | BPF_DIV32_REG =>
    if (reg_eqb dst R0) && (ireg_eqb src IR1) then
      (**r construct: udiv Rd Rn Rm *)
      let div_st0 := add_ins_jittedthumb UDIV_OP st in
      let div_st  := add_ins_jittedthumb (Int.repr 0xf0f1) div_st0 in

        match upd_load_store_regs_jittedthumb dst LoadAndStore div_st with
        | None => None (**r TODO: proving this is impossible *)
        | Some ldr_st =>
        if ireg_eqb src IR11 then
          Some ldr_st
        else
          match reg_of_ireg src with
          | Some r => upd_load_store_regs_jittedthumb r LoadPerm ldr_st
          | None => None (**r TODO: proving this is impossible *)
          end
        end
    else
      None
  | BPF_OR32_REG =>
    let ins_lo  := encode_arm32 (Int.repr (id_of_reg dst)) ORR_R_OP 0 4 in
    let ins_hi  := encode_arm32 (Int.repr (id_of_reg dst)) (int_of_ireg src) 8 4 in
    let ins_st0 := add_ins_jittedthumb ins_lo st in
    let ins_st  := add_ins_jittedthumb ins_hi ins_st0 in
      match upd_load_store_regs_jittedthumb dst LoadAndStore ins_st with
      | None => None (**r TODO: proving this is impossible *)
      | Some ldr_st =>
        if ireg_eqb src IR11 then
          Some ldr_st
        else
          match reg_of_ireg src with
          | Some r => upd_load_store_regs_jittedthumb r LoadPerm ldr_st
          | None => None (**r TODO: proving this is impossible *)
          end
      end
  | BPF_AND32_REG =>
    let ins_lo  := encode_arm32 (Int.repr (id_of_reg dst)) AND_R_OP 0 4 in
    let ins_hi  := encode_arm32 (Int.repr (id_of_reg dst)) (int_of_ireg src) 8 4 in
    let ins_st0 := add_ins_jittedthumb ins_lo st in
    let ins_st  := add_ins_jittedthumb ins_hi ins_st0 in
      match upd_load_store_regs_jittedthumb dst LoadAndStore ins_st with
      | None => None (**r TODO: proving this is impossible *)
      | Some ldr_st =>
        if ireg_eqb src IR11 then
          Some ldr_st
        else
          match reg_of_ireg src with
          | Some r => upd_load_store_regs_jittedthumb r LoadPerm ldr_st
          | None => None (**r TODO: proving this is impossible *)
          end
      end

  | BPF_LSH32_REG =>

    (**r construct: lsl Rd Rn Rm *)
    let lsl_lo  := encode_arm32 (Int.repr (id_of_reg dst)) LSL_R_OP 0 4 in
    let lsl_hi  := construct_thumb2_shift_rd_rm (Int.repr (id_of_reg dst)) (int_of_ireg src) in
    let lsl_st0 := add_ins_jittedthumb lsl_lo st in
    let lsl_st  := add_ins_jittedthumb lsl_hi lsl_st0 in

      match upd_load_store_regs_jittedthumb dst LoadAndStore lsl_st with
      | None => None (**r TODO: proving this is impossible *)
      | Some ldr_st =>
        if ireg_eqb src IR11 then
          Some ldr_st
        else
          match reg_of_ireg src with
          | Some r => upd_load_store_regs_jittedthumb r LoadPerm ldr_st
          | None => None (**r TODO: proving this is impossible *)
          end
      end
  | BPF_RSH32_REG =>

    (**r construct: lsr Rd Rn Rm *)
    let lsr_lo  := encode_arm32 (Int.repr (id_of_reg dst)) LSR_R_OP 0 4 in
    let lsr_hi  := construct_thumb2_shift_rd_rm (Int.repr (id_of_reg dst)) (int_of_ireg src) in
    let lsr_st0 := add_ins_jittedthumb lsr_lo st in
    let lsr_st  := add_ins_jittedthumb lsr_hi lsr_st0 in

      match upd_load_store_regs_jittedthumb dst LoadAndStore lsr_st with
      | None => None (**r TODO: proving this is impossible *)
      | Some ldr_st =>
        if ireg_eqb src IR11 then
          Some ldr_st
        else
          match reg_of_ireg src with
          | Some r => upd_load_store_regs_jittedthumb r LoadPerm ldr_st
          | None => None (**r TODO: proving this is impossible *)
          end
      end

  | BPF_XOR32_REG =>
    let ins_lo  := encode_arm32 (Int.repr (id_of_reg dst)) EOR_R_OP 0 4 in
    let ins_hi  := encode_arm32 (Int.repr (id_of_reg dst)) (int_of_ireg src) 8 4 in
    let ins_st0 := add_ins_jittedthumb ins_lo st in
    let ins_st  := add_ins_jittedthumb ins_hi ins_st0 in
      match upd_load_store_regs_jittedthumb dst LoadAndStore ins_st with
      | None => None (**r TODO: proving this is impossible *)
      | Some ldr_st =>
        if ireg_eqb src IR11 then
          Some ldr_st
        else
          match reg_of_ireg src with
          | Some r => upd_load_store_regs_jittedthumb r LoadPerm ldr_st
          | None => None (**r TODO: proving this is impossible *)
          end
      end
  | BPF_MOV32_REG =>
    (**r optimization: for `mov ri ri`, we generate nothing *)
    if reg_ireg_eqb dst src then
      Some st
    else
      let d       := if Int.lt (Int.repr (id_of_reg dst)) (Int.repr 8) then Int.zero else Int.one in
      let rdn     := if Int.lt (Int.repr (id_of_reg dst)) (Int.repr 8) then
                        (Int.repr (id_of_reg dst))
                      else
                        Int.sub (Int.repr (id_of_reg dst)) (Int.repr 8) in
      let ins_rdn := encode_arm32 rdn MOV_R_OP 0 3 in
      let ins_rm  := encode_arm32 (int_of_ireg src)  ins_rdn 3 4 in
      let ins     := encode_arm32 d ins_rm 7 1 in
      let ins_st  := add_ins_jittedthumb ins st in
        match upd_load_store_regs_jittedthumb dst StorePerm ins_st with
        | None => None (**r TODO: proving this is impossible *)
        | Some ldr_st =>
          if ireg_eqb src IR11 then
            Some ldr_st
          else
            match reg_of_ireg src with
            | Some r => upd_load_store_regs_jittedthumb r LoadPerm ldr_st
          | None => None (**r TODO: proving this is impossible *)
          end
        end
  | BPF_ARSH32_REG =>

    (**r construct: asr Rd Rn Rm *)
    let asr_lo  := encode_arm32 (Int.repr (id_of_reg dst)) ASR_R_OP 0 4 in
    let asr_hi  := construct_thumb2_shift_rd_rm (Int.repr (id_of_reg dst)) (int_of_ireg src) in
    let asr_st0 := add_ins_jittedthumb asr_lo st in
    let asr_st  := add_ins_jittedthumb asr_hi asr_st0 in

      match upd_load_store_regs_jittedthumb dst LoadAndStore asr_st with
      | None => None (**r TODO: proving this is impossible *)
      | Some ldr_st =>
        if ireg_eqb src IR11 then
          Some ldr_st
        else
          match reg_of_ireg src with
          | Some r => upd_load_store_regs_jittedthumb r LoadPerm ldr_st
          | None => None (**r TODO: proving this is impossible *)
          end
      end
  | BPF_ALU32_REG_ILLEGAL_INS => None (**r TODO: we will prove this branch is unreachable *)
  end.

(** for alu32 imm *)
Definition bpf_alu32_to_thumb_imm (op: opcode_alu32_imm) (dst: reg) (imm8: int) (st: jit_state): option jit_state :=
  match op with
  | BPF_ADD32_IMM =>
    let ins_lo    := encode_arm32 (Int.repr (id_of_reg dst)) ADD_I_OP 0 4 in
    let ins_hi    := encode_arm32 (Int.repr (id_of_reg dst)) imm8 8 4 in
    let ins_st0   := add_ins_jittedthumb ins_lo st in
    let ins_st    := add_ins_jittedthumb ins_hi ins_st0 in
      upd_load_store_regs_jittedthumb dst LoadAndStore ins_st
  | BPF_SUB32_IMM =>
    let ins_lo    := encode_arm32 (Int.repr (id_of_reg dst)) SUB_I_OP 0 4 in
    let ins_hi    := encode_arm32 (Int.repr (id_of_reg dst)) imm8 8 4 in
    let ins_st0   := add_ins_jittedthumb ins_lo st in
    let ins_st    := add_ins_jittedthumb ins_hi ins_st0 in
      upd_load_store_regs_jittedthumb dst LoadAndStore ins_st

  | BPF_OR32_IMM =>
    let ins_lo    := encode_arm32 (Int.repr (id_of_reg dst)) ORR_I_OP 0 4 in
    let ins_hi    := encode_arm32 (Int.repr (id_of_reg dst)) imm8 8 4 in
    let ins_st0   := add_ins_jittedthumb ins_lo st in
    let ins_st    := add_ins_jittedthumb ins_hi ins_st0 in
      upd_load_store_regs_jittedthumb dst LoadAndStore ins_st

  | BPF_AND32_IMM =>
    let ins_lo    := encode_arm32 (Int.repr (id_of_reg dst)) AND_I_OP 0 4 in
    let ins_hi    := encode_arm32 (Int.repr (id_of_reg dst)) imm8 8 4 in
    let ins_st0   := add_ins_jittedthumb ins_lo st in
    let ins_st    := add_ins_jittedthumb ins_hi ins_st0 in
      upd_load_store_regs_jittedthumb dst LoadAndStore ins_st

  | BPF_NEG32_IMM =>
    let ins_lo    := encode_arm32 (Int.repr (id_of_reg dst)) RSB_I_OP 0 4 in
    let ins_hi    := encode_arm32 (Int.repr (id_of_reg dst)) imm8 8 4 in
    let ins_st0   := add_ins_jittedthumb ins_lo st in
    let ins_st    := add_ins_jittedthumb ins_hi ins_st0 in
      upd_load_store_regs_jittedthumb dst LoadAndStore ins_st

  | BPF_XOR32_IMM =>
    let ins_lo    := encode_arm32 (Int.repr (id_of_reg dst)) EOR_I_OP 0 4 in
    let ins_hi    := encode_arm32 (Int.repr (id_of_reg dst)) Int.zero 8 4 in
    let ins_st0   := add_ins_jittedthumb ins_lo st in
    let ins_st    := add_ins_jittedthumb ins_hi ins_st0 in
      upd_load_store_regs_jittedthumb dst LoadAndStore ins_st
  | BPF_MOV32_IMM =>
    let ins_hi    := encode_arm32 (Int.repr (id_of_reg dst)) imm8 8 4 in
    let ins_st0   := add_ins_jittedthumb MOVW_OP st in
    let ins_st    := add_ins_jittedthumb ins_hi ins_st0 in
      upd_load_store_regs_jittedthumb dst StorePerm ins_st
  | _ => None (**r TODO: we will prove this branch is unreachable *)
  end.


(**r move imm32 low16-bit to ireg *)

Definition mov_int_to_movw (i: int) (r: ireg) (st: jit_state): jit_state :=
  let lo_imm8   := decode_arm32 i 0  8 in
  let lo_imm3   := decode_arm32 i 8  3 in
  let lo_i      := decode_arm32 i 11 1 in
  let lo_imm4   := decode_arm32 i 12 4 in
(**r - encoding T3
MOVW Rd, #imm16 (= imm4:i:imm3:imm8)

 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0     1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0
 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0     5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 --------------------------------    --------------------------------
|1 1 1 1 0|i|1 0|0|1|0 0| imm4  |   |0| imm3|  Rd   |  imm8         |
 --------------------------------    -------------------------------- *)
  let movw_lo_0 := encode_arm32 lo_imm4 MOVW_OP   0  4 in
  let movw_lo   := encode_arm32 lo_i    movw_lo_0 10 1 in

  let movw_hi_0 := encode_arm32 (int_of_ireg r) lo_imm8 8 4 in
  let movw_hi   := encode_arm32 lo_imm3 movw_hi_0 12 3 in

  let movw_st0  := add_ins_jittedthumb movw_lo st in
    add_ins_jittedthumb movw_hi movw_st0.

(**r move imm32 high16-bit to ireg *)

Definition mov_int_to_movt (i: int) (r: ireg) (st: jit_state): jit_state :=
  let hi_imm8   := decode_arm32 i 16 8 in
  let hi_imm3   := decode_arm32 i 24 3 in
  let hi_i      := decode_arm32 i 27 1 in
  let hi_imm4   := decode_arm32 i 28 4 in

(**r - encoding T1
MOVT Rd, #imm16 (= imm4:i:imm3:imm8)

 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0     1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0
 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0     5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 --------------------------------    --------------------------------
|1 1 1 1 0|i|1 0|1|1|0|0| imm4  |   |0| imm3|  Rd   |  imm8         |
 --------------------------------    -------------------------------- *)
  let movt_lo_0 := encode_arm32 hi_imm4 MOVT_OP   0  4 in
  let movt_lo   := encode_arm32 hi_i    movt_lo_0 10 1 in
  let movt_st0  := add_ins_jittedthumb movt_lo st in

  let movt_hi_0 := encode_arm32 (int_of_ireg r) hi_imm8 8 4 in
  let movt_hi   := encode_arm32 hi_imm3 movt_hi_0 12 3 in
    add_ins_jittedthumb movt_hi movt_st0.

Definition bpf_alu32_to_thumb (ins: int64) (st: jit_state): option jit_state :=
  let op    := get_opcode ins in
  let opc   := nat_to_opcode_alu32 op in
  let dst   := get_dst ins in
  let src   := get_src ins in
  let imm32 := get_immediate ins in
    match z_to_reg dst with
    | Some d =>
      match opc with
      | ALU32_REG =>
        let opr := nat_to_opcode_alu32_reg op in
          match z_to_reg src with
          | Some s => bpf_alu32_to_thumb_reg opr d (ireg_of_reg s) st
          | None => None (**r TODO: proving this is impossible *)
          end
      | ALU32_IMM =>
        (**r because ARM32 doesn't have MUL_IMM and UDIV_IMM, so we must do special cases *)
        let opi := nat_to_opcode_alu32_imm op in
          (**r
              - for an imm12 (4-rotate + imm8), we only support 0000 + imm8, i.e. [0, 255],
              - for imm > 255, we do `mov` firstly and then do `X32_REG`
            *)
          if (Bool.eqb (opcode_alu32_imm_eqb opi BPF_MUL32_IMM) false) && (**r CompCert doesn't have mul_imm *)
              (Int.cmp Cle Int.zero imm32) && (Int.cmp Cle imm32 (Int.repr 255)) then
            bpf_alu32_to_thumb_imm opi d imm32 st
          else
            let hi_32 := decode_arm32 imm32 16 16 in
              if Int.eq hi_32 Int.zero then
                (**r optimization: if high_16 = 0 then only `add movw` else `add movw + movt` *)
                if (opcode_alu32_imm_eqb opi BPF_MOV32_IMM) then
                  (**r optimization: movw dst imm16 *)
                  Some (mov_int_to_movw imm32 (ireg_of_reg d) st)
                else
                  let st1 := upd_IR11_jittedthumb true st in
                  (**r adding movw *)
                  let st2 := mov_int_to_movw imm32 IR11 st1 in
                    bpf_alu32_to_thumb_reg (opcode_reg_of_imm opi) d IR11 st2

              else
                let st1 := upd_IR11_jittedthumb true st in
                (**r adding movw movt *)
                let st2 := mov_int_to_movw imm32 IR11 st1 in
                let st3 := mov_int_to_movt imm32 IR11 st2 in
                  bpf_alu32_to_thumb_reg (opcode_reg_of_imm opi) d IR11 st3
      | ALU32_ILLEGAL_INS => None
      end
    | None => None (**r TODO: proving this is impossible *)
    end.

(** we always use a fuel (= List.length l) to make sure termination *)


(** TODO: We try to make the proof easier: split the `jit_alu32_aux_thumb` into two passes
  - pass_1: we calculate the global information of the given BPF alu32 list: 
    - ofs: the size of given BPF alu32 list
    - len: the size of expected thumb list
    - ls: loadStoreRegs info of the given BPF alu32 list
    - l: the expected thumb list
  - pass_2:
    - l: where bal will be modify.
  *)

(** @input
  * @ls: the loadStoreRegs

  * @output
  * @n: the number of store instructions

  * @brief
  * compute the number of the generated instructions in the store stage
  *)

Definition get_store_ins_num (st: jit_state): nat :=
  let ls := load_store_regs st in
  let n0 := if is_store_reg R0 ls then 1%nat else 0%nat in
  let n1 := if is_store_reg R1 ls then S n0 else n0 in
  let n2 := if is_store_reg R2 ls then S n1 else n1 in
  let n3 := if is_store_reg R3 ls then S n2 else n2 in
  let n4 := if is_store_reg R4 ls then S n3 else n3 in
  let n5 := if is_store_reg R5 ls then S n4 else n4 in
  let n6 := if is_store_reg R6 ls then S n5 else n5 in
  let n7 := if is_store_reg R7 ls then S n6 else n6 in
  let n8 := if is_store_reg R8 ls then S n7 else n7 in
  let n9 := if is_store_reg R9 ls then S n8 else n8 in
    if is_store_reg R10 ls then S n9 else n9.


(** @input
  * @fuel (initially = List.length l)
  * @entry_point
  * @l: rBPF binary instructions
  * @j: jitted thumb binary instructions (pre)

  * @output
  * the offset and jitted thumb binary instructions

  * @brief
  * finds a sequential of alu32 instructions starting from entry_point and translates it into jitted thumb instructions
  *)
Fixpoint jit_alu32_to_thumb_pass (fuel entry_point: nat) (st: jit_state): option jit_state :=
  match fuel with
  | O => Some st
  | S n =>
    match eval_jit_ins (Int.repr (Z.of_nat entry_point)) st with
    | Some ins =>
      if ins_is_bpf_alu32 ins then
        match bpf_alu32_to_thumb ins st with
        | Some thumb_st =>
          let new_thumb_st := upd_bpf_offset_jittedthumb thumb_st in
            jit_alu32_to_thumb_pass n (S entry_point) new_thumb_st
        | None => None
        end
      else
        Some st
    | None => None
    end
  end.

(** * Store Stage: Store selected arm32 registers into corresponding BPF registers *)

(** @input
  * @r   : store arm32 register r into BPF register r

  * @output
  * @ins :  binary format of `str r [IR12, #+ofs]` where
  * - IR12 stores the start address of BPF state
  * - ofs = r * 8
  *)

Definition jit_alu32_thumb_upd_store (r: reg) (st: jit_state): option jit_state :=
  if is_store_reg r (load_store_regs st) then
    let int_r   := Int.repr (Z.of_nat (reg2nat r)) in
      jit_alu32_thumb_store_template_jit int_r (Int.repr 12) (Int.mul int_r (Int.repr 8)) st
  else
    Some st.

(** @input
  * @jl : a part of the thumb state
  * @ls : record the info that which BPF register should be loaded or stored
  * @ptr: a pointer to the start address of the BPF state, and we know the offset of BPF registers and the flag

  * @output
  * @jl: new value of stack offset, pc and binary code
  *)

Definition jit_alu32_thumb_store (st: jit_state): option jit_state :=
  match jit_alu32_thumb_upd_store R0 st with
  | Some R0_st =>
    match jit_alu32_thumb_upd_store R1 R0_st with
    | Some R1_st =>
      match jit_alu32_thumb_upd_store R2 R1_st with
      | Some R2_st =>
        match jit_alu32_thumb_upd_store R3 R2_st with
        | Some R3_st =>
          match jit_alu32_thumb_upd_store R4 R3_st with
          | Some R4_st =>
            match jit_alu32_thumb_upd_store R5 R4_st with
            | Some R5_st =>
              match jit_alu32_thumb_upd_store R6 R5_st with
              | Some R6_st =>
                match jit_alu32_thumb_upd_store R7 R6_st with
                | Some R7_st =>
                  match jit_alu32_thumb_upd_store R8 R7_st with
                  | Some R8_st =>
                    match jit_alu32_thumb_upd_store R9 R8_st with
                    | Some R9_st =>
                      jit_alu32_thumb_upd_store R10 R9_st
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


(** * Reset Stage: recover the initial value of selected arm32 registers *)

(** @input
  * @r   : pop register r from the stack

  * @output
  * @ins :  binary format of `ldr r [sp, #+ofs]` where we use `ldr` to implement `pop`
  *)
Definition jit_alu32_thumb_upd_reset (r: reg) (st: jit_state): option jit_state :=
  if is_non_reg r (load_store_regs st) then
    let ir := (Int.repr (Z.of_nat (reg2nat r))) in
      jit_alu32_thumb_load_template_jit ir (Int.repr (Z.of_nat (ireg2nat SP))) (Int.mul ir (Int.repr 4)) st
  else
    Some st.

(** @input
  * @jl       : current location of the pointer of jarm * current jitted binary thumb code
  * @ls       : load and store related-registers

  * @output
  * @jl: new value of stack offset, pc and binary code

  *)
Definition jit_alu32_thumb_reset (st: jit_state): option jit_state :=
  let option_R11_st :=
    if (use_IR11 st) then
      jit_alu32_thumb_load_template_jit (Int.repr 11) (Int.repr (Z.of_nat (ireg2nat SP))) (Int.repr 44) st
    else
      Some st in
  match option_R11_st with
  | Some R11_st =>
    match jit_alu32_thumb_upd_reset R10 R11_st with
    | Some R10_st =>
      match jit_alu32_thumb_upd_reset R9  R10_st with
      | Some R9_st =>
        match jit_alu32_thumb_upd_reset R8  R9_st with
        | Some R8_st =>
          match jit_alu32_thumb_upd_reset R7  R8_st with
          | Some R7_st =>
            match jit_alu32_thumb_upd_reset R6  R7_st with
            | Some R6_st =>
              match jit_alu32_thumb_upd_reset R5  R6_st with
              | Some R5_st =>
                jit_alu32_thumb_upd_reset R4  R5_st
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
  match jit_alu32_thumb_load_template_jit (Int.repr (Z.of_nat (ireg2nat SP))) (Int.repr (Z.of_nat (ireg2nat SP))) Int.zero st with
  | Some st0 =>
    (**r BX LR *)
    let ins_rm   := encode_arm32 (Int.repr (Z.of_nat (ireg2nat RA))) BX_OP 3 4 in
      upd_jitted_list ins_rm st0
  | None => None
  end.

(** * Jit Procedure *)

(** @input
  * @fuel: the initial value is the size of from
  * @pc: the index of current pointer to from
  * @from: a sequence of jitted thumb core instructions
  * @to: the initial ready jitted thumb binary instructions
  * @ls: the loadStoreRegs to calculate the offset of all possible `bal` instructions

  * @output
  * a updated jitted thumb binary instructions: adding `from` to the end of `to`
  *)
Fixpoint copy_thumb_list_from_to_aux (fuel pc: nat) (st: jit_state): option jit_state :=
  match fuel with
  | O => Some st
  | S n =>
    match eval_thumb_ins (Int.repr (Z.of_nat pc)) st with
    | Some ins0 =>
      match upd_jitted_list ins0 st with
      | Some st0 =>
        copy_thumb_list_from_to_aux n (S pc) st0
      | None => None
      end
    | None => None
    end
  end.

Definition copy_thumb_list_from_to (st: jit_state): option jit_state :=
  copy_thumb_list_from_to_aux (thumb_len st) 0 st.

Definition jit_alu32_to_thumb (pc: nat) (st: jit_state): option jit_state :=
  let st0 := reset_init_jittedthumb st in
    match jit_alu32_to_thumb_pass (jit_ins_len st0) pc st0 with
    | Some st1 =>
      let st2 := add_key_value2 pc (jitted_len st1) (Nat.sub (offset st1) 1) st1 in
        match jit_alu32_pre st2 with
        | Some thumb_pre =>
          match jit_alu32_thumb_save thumb_pre with
          | Some thumb_save =>
            match jit_alu32_thumb_load thumb_save with
            | Some thumb_load =>
              match copy_thumb_list_from_to thumb_load with
              | Some thumb_core =>
                match jit_alu32_thumb_store thumb_core with
                | Some thumb_store =>
                  match jit_alu32_thumb_reset thumb_store with
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
    end.


Fixpoint jit_alu32_aux (fuel pc: nat) (pre_is_alu32: bool) (st: jit_state): option jit_state :=
  match fuel with
  | O => Some st
  | S n =>
    match eval_jit_ins (Int.repr (Z.of_nat pc)) st with
    | Some ins =>
      if ins_is_bpf_alu32 ins then
        if Bool.eqb pre_is_alu32 false then
          match jit_alu32_to_thumb pc st with
          | Some st0 => jit_alu32_aux n (S pc) true st0
          | None => None
          end
        else
          jit_alu32_aux n (S pc) true st
      else if ins_is_bpf_jump ins then (**r check if ins is jump *)
        let ofs     := get_offset ins in
        let next_pc := Int.add (Int.add (Int.repr (Z.of_nat pc)) ofs) Int.one in
          match eval_jit_ins next_pc st with
          | Some next_ins =>
            if ins_is_bpf_alu32 next_ins then
              match jit_alu32_to_thumb (Z.to_nat (Int.unsigned next_pc)) st with
              | Some st0 => jit_alu32_aux n (S pc) false st0
              | None => None
              end
            else
              jit_alu32_aux n (S pc) false st
          | None => None
          end
      else (**r when ins is not jump *)
        jit_alu32_aux n (S pc) false st
    | None => None
    end
  end.

Definition jit_alu32 (st: jit_state): option jit_state :=
  jit_alu32_aux (jit_ins_len st) 0 false st.

Close Scope string_scope.
Close Scope asm.
Close Scope bool_scope.
Close Scope Z_scope.
