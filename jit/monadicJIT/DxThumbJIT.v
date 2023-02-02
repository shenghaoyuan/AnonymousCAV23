From compcert Require Import Integers.
From compcert.arm Require Import AsmSyntax BinSyntax.

From bpf.comm Require Import Flag BinrBPF ListAsArray Regs rBPFValues.
From bpf.model Require Import Encode.
From bpf.dxcomm Require Import DxIntegers DxNat.
From bpf.jit.thumb Require Import LoadStoreRegs KeyValue2.
From bpf.jit.thumb Require Import ThumbEncode ThumbDecode Arm32Reg ThumbJITOpcode ThumbInsOp JITState.

From bpf.jit.monadicJIT Require Import JITNat DxJITMonad DxMonadCommon.

From Coq Require Import List ZArith Arith String.
Import ListNotations.
Open Scope Z_scope.
Open Scope bool_scope.
Open Scope asm.
Open Scope string_scope.
Open Scope monad_scope.

Definition decode_thumb (ins: int16) (from size: nat): M int :=
  returnM (decode_arm32 ins from size).

Definition encode_thumb (v ins: int16) (from size: nat): M int :=
  returnM (encode_arm32 v ins from size).

Definition is_non_reg (r: reg): M bool :=
  do ls <-- eval_load_store_regs;
    returnM (is_non_reg r ls).

Definition is_load_reg (r: reg): M bool :=
  do ls <-- eval_load_store_regs;
    returnM (is_load_reg r ls).

Definition is_store_reg (r: reg): M bool :=
  do ls <-- eval_load_store_regs;
    returnM (is_store_reg r ls).

Definition opcode_reg_of_imm (op: opcode_alu32_imm): M opcode_alu32_reg :=
  returnM (opcode_reg_of_imm op).

Definition ins_is_bpf_alu32 (ins: int64) : M bool := returnM (ins_is_bpf_alu32 ins).

Definition ins_is_bpf_jump (ins: int64) : M bool := returnM (ins_is_bpf_jump ins).

(**r MUST div by 2 before call `construct_thumb_b` because of `P label` where label = imm8:'0' *)
Definition construct_thumb_b (cd imm8: int16): M int16 :=
  do ins_imm8 <-- encode_thumb imm8 B_OP 0 nat_8;
    encode_thumb cd ins_imm8 nat_8 nat_4.

Definition construct_thumb2_shift_rd_rm (rd rm: int16): M int16 :=
  do ins_rd <-- encode_thumb rd rm nat_8 nat_4;
    encode_thumb int16_15 ins_rd nat_12 nat_4.

Definition jit_alu32_thumb_store_template_ins (rt rn imm12: int16): M unit :=
  do str_low   <-- encode_thumb rn STR_I_OP 0 nat_4;
  do str_high  <-- encode_thumb rt imm12 nat_12 nat_4;
  do _         <-- add_ins_jittedthumb str_low;
    add_ins_jittedthumb str_high.

Definition jit_alu32_thumb_load_template_ins (rt rn imm12: int16): M unit :=
  do str_low   <-- encode_thumb rn LDR_I_OP 0 nat_4;
  do str_high  <-- encode_thumb rt imm12 nat_12 nat_4;
  do _         <-- add_ins_jittedthumb str_low;
    add_ins_jittedthumb str_high.

Definition jit_alu32_thumb_store_template_jit (rt rn imm12: int16): M unit :=
  do str_low   <-- encode_thumb rn STR_I_OP 0 nat_4;
  do str_high  <-- encode_thumb rt imm12 nat_12 nat_4;
  do _         <-- upd_jitted_list str_low;
    upd_jitted_list str_high.

Definition jit_alu32_thumb_load_template_jit (rt rn imm12: int16): M unit :=
  do str_low   <-- encode_thumb rn LDR_I_OP 0 nat_4;
  do str_high  <-- encode_thumb rt imm12 nat_12 nat_4;
  do _         <-- upd_jitted_list str_low;
    upd_jitted_list str_high.

Definition jit_alu32_store_flag (f: int): M unit :=
  do movw_hi   <-- encode_thumb int16_11 f nat_8 nat_4;
  do _         <-- add_ins_jittedthumb MOVW_OP;
  do _         <-- add_ins_jittedthumb movw_hi;
  do b         <-- is_non_reg R1;
  do _         <--
    if b then
      returnM tt
    else
      jit_alu32_thumb_store_template_ins int16_1 int16_13 int16_4;
  do _         <-- jit_alu32_thumb_load_template_ins int16_1 int16_12 int16_4;
  do _         <-- jit_alu32_thumb_store_template_ins int16_11 int16_1 int16_0;
    if b then
      returnM tt
    else
      jit_alu32_thumb_load_template_ins int16_1 int16_13 int16_4.


(** * Pre Stage *)
Definition jit_alu32_pre: M unit :=
  do ins_rdn <-- encode_thumb int16_4 MOV_R_OP 0 nat_3;
  do ins_rm  <-- encode_thumb int16_1 ins_rdn nat_3 nat_4;
  do ins_mov <-- encode_thumb int16_1 ins_rm nat_7 nat_1;
    upd_jitted_list ins_mov.

(** * Save Stage *)
Definition jit_alu32_thumb_upd_save (r: reg): M unit :=
  do b <-- is_non_reg r;
    if b then
      returnM tt
    else
    do ir <-- returnM (int16_of_nat (reg2nat r));
      jit_alu32_thumb_store_template_jit ir (int16_of_nat (ireg2nat SP)) (int16_mul ir int16_4).

Definition jit_alu32_thumb_save: M unit :=
  do _ <-- jit_alu32_thumb_upd_save R4;
  do _ <-- jit_alu32_thumb_upd_save R5;
  do _ <-- jit_alu32_thumb_upd_save R6;
  do _ <-- jit_alu32_thumb_upd_save R7;
  do _ <-- jit_alu32_thumb_upd_save R8;
  do _ <-- jit_alu32_thumb_upd_save R9;
  do _ <-- jit_alu32_thumb_upd_save R10;
  do b <-- eval_use_IR11;
    if b then
      jit_alu32_thumb_store_template_jit int16_11 (int16_of_nat (ireg2nat SP)) int16_44
    else
      returnM tt.

Definition jit_alu32_thumb_upd_load (r: reg): M unit :=
  do b <-- is_load_reg r;
  if b then
    do int_r     <-- returnM (int16_of_nat (reg2nat r));
      jit_alu32_thumb_load_template_jit int_r int16_0 (int16_mul int_r int16_8)
  else
    returnM tt.

Definition no_reg_load : M bool :=
  do b0 <-- is_load_reg R0;
    if b0 then returnM false else
  do b1 <-- is_load_reg R1;
    if b1 then returnM false else
  do b2 <-- is_load_reg R2;
    if b2 then returnM false else
  do b3 <-- is_load_reg R3;
    if b3 then returnM false else
  do b4 <-- is_load_reg R4;
    if b4 then returnM false else
  do b5 <-- is_load_reg R5;
    if b5 then returnM false else
  do b6 <-- is_load_reg R6;
    if b6 then returnM false else
  do b7 <-- is_load_reg R7;
    if b7 then returnM false else
  do b8 <-- is_load_reg R8;
    if b8 then returnM false else
  do b9 <-- is_load_reg R9;
    if b9 then returnM false else
  do b10 <-- is_load_reg R10;
    if b10 then returnM false else
      returnM true.

Definition jit_alu32_thumb_load: M unit :=
  do b <-- no_reg_load;
    if b then returnM tt else

  do _ <-- jit_alu32_thumb_load_template_jit int16_0 int16_12 int16_8;
  do _ <-- jit_alu32_thumb_upd_load R10;
  do _ <-- jit_alu32_thumb_upd_load R9;
  do _ <-- jit_alu32_thumb_upd_load R8;
  do _ <-- jit_alu32_thumb_upd_load R7;
  do _ <-- jit_alu32_thumb_upd_load R6;
  do _ <-- jit_alu32_thumb_upd_load R5;
  do _ <-- jit_alu32_thumb_upd_load R4;
  do _ <-- jit_alu32_thumb_upd_load R3;
  do _ <-- jit_alu32_thumb_upd_load R2;
  do _ <-- jit_alu32_thumb_upd_load R1;
    jit_alu32_thumb_upd_load R0.

Definition bpf_alu32_to_thumb_reg (op: opcode_alu32_reg) (dst: reg) (src: ireg): M unit :=
  match op with
  | BPF_ADD32_REG =>
    do d       <-- if int16_lt (int16_of_nat (reg2nat dst)) int16_8 then returnM int16_0 else returnM int16_1;
    do rdn     <-- if int16_lt (int16_of_nat (reg2nat dst)) int16_8 then
                      returnM (int16_of_nat (reg2nat dst))
                    else
                      returnM (int16_sub (int16_of_nat (reg2nat dst)) int16_8);
    do ins_rdn <-- encode_thumb rdn ADD_R_OP 0 nat_3;
    do ins_rm  <-- encode_thumb (int_of_ireg src) ins_rdn nat_3 nat_4;
    do ins     <-- encode_thumb d ins_rm nat_7 nat_1;
    do _       <-- add_ins_jittedthumb ins;

    do _       <-- upd_load_store_regs_jittedthumb dst LoadAndStore;
      if ireg_eqb src IR11 then
        returnM tt
      else
        do r <-- reg_of_ireg src;
          upd_load_store_regs_jittedthumb r LoadPerm

  | BPF_SUB32_REG =>
    do ins_lo  <-- encode_thumb (int16_of_nat (reg2nat dst)) SUB_R_OP 0 nat_4;
    do ins_hi  <-- encode_thumb (int16_of_nat (reg2nat dst)) (int16_of_ireg src) nat_8 nat_4;
    do _       <-- add_ins_jittedthumb ins_lo;
    do _       <-- add_ins_jittedthumb ins_hi;
    do _       <-- upd_load_store_regs_jittedthumb dst LoadAndStore;
      if ireg_eqb src IR11 then
        returnM tt
      else
        do r <-- reg_of_ireg src;
          upd_load_store_regs_jittedthumb r LoadPerm

  | BPF_MUL32_REG =>
    do ins_lo  <-- encode_thumb (int16_of_nat (reg2nat dst)) MUL_OP 0 nat_4;
    do ins_hi0 <-- encode_thumb (int16_of_nat (reg2nat dst)) (int16_of_ireg src) nat_8 nat_4;
    do ins_hi  <-- encode_thumb int16_15 ins_hi0 nat_12 nat_4;
    do _       <-- add_ins_jittedthumb ins_lo;
    do _       <-- add_ins_jittedthumb ins_hi;
    do _       <-- upd_load_store_regs_jittedthumb dst LoadAndStore;
      if ireg_eqb src IR11 then
        returnM tt
      else
        do r <-- reg_of_ireg src;
          upd_load_store_regs_jittedthumb r LoadPerm
  | BPF_DIV32_REG =>
    if (reg_eqb dst R0) && (ireg_eqb src IR1) then
      do st1     <-- upd_IR11_jittedthumb true;

      do cmp_lo  <-- encode_thumb (int16_of_ireg src) CMP_I_OP 0 nat_4;
      do _       <-- add_ins_jittedthumb cmp_lo;
      do _       <-- add_ins_jittedthumb int16_0x0f00;

      do b_r1    <-- is_non_reg R1;
      do b_ne    <--
        if b_r1 then
          construct_thumb_b COND_NE int16_6
        else
          construct_thumb_b COND_NE int16_10;

      do _       <-- add_ins_jittedthumb b_ne;

      do _       <-- jit_alu32_store_flag int32_10;

      do _       <-- add_ins_jittedthumb BNE_0;

      do _       <-- add_ins_jittedthumb UDIV_OP;
      do _       <-- add_ins_jittedthumb int16_0xf0f1;

      do _       <-- upd_load_store_regs_jittedthumb dst LoadAndStore;
        if ireg_eqb src IR11 then
          returnM tt
        else
          do r <-- reg_of_ireg src;
            upd_load_store_regs_jittedthumb r LoadPerm
    else
      upd_flag BPF_ILLEGAL_DIV
  | BPF_OR32_REG =>
    do ins_lo  <-- encode_thumb (int16_of_nat (reg2nat dst)) ORR_R_OP 0 nat_4;
    do ins_hi  <-- encode_thumb (int16_of_nat (reg2nat dst)) (int16_of_ireg src) nat_8 nat_4;
    do _       <-- add_ins_jittedthumb ins_lo;
    do _       <-- add_ins_jittedthumb ins_hi;
    do _       <-- upd_load_store_regs_jittedthumb dst LoadAndStore;
      if ireg_eqb src IR11 then
        returnM tt
      else
        do r <-- reg_of_ireg src;
          upd_load_store_regs_jittedthumb r LoadPerm
  | BPF_AND32_REG =>
    do ins_lo  <-- encode_thumb (int16_of_nat (reg2nat dst)) AND_R_OP 0 nat_4;
    do ins_hi  <-- encode_thumb (int16_of_nat (reg2nat dst)) (int16_of_ireg src) nat_8 nat_4;
    do _       <-- add_ins_jittedthumb ins_lo;
    do _       <-- add_ins_jittedthumb ins_hi;
    do _       <-- upd_load_store_regs_jittedthumb dst LoadAndStore;
      if ireg_eqb src IR11 then
        returnM tt
      else
        do r <-- reg_of_ireg src;
          upd_load_store_regs_jittedthumb r LoadPerm

  | BPF_LSH32_REG =>
    do _       <-- upd_IR11_jittedthumb true;

    do cmp_lo  <-- encode_thumb (int16_of_ireg src) CMP_I_OP 0 nat_4;
    do _       <-- add_ins_jittedthumb cmp_lo;
    do _       <-- add_ins_jittedthumb int16_0x0f20;

    do b_r1    <-- is_non_reg R1;
    do b_lt    <--
      if b_r1 then
        construct_thumb_b COND_LT int16_6
      else
        construct_thumb_b COND_LT int16_10;

    do _       <-- add_ins_jittedthumb b_lt;

    do _       <-- jit_alu32_store_flag int32_11;

    do _       <-- add_ins_jittedthumb BLT_0;

    do lsl_lo  <-- encode_thumb (int16_of_nat (reg2nat dst)) LSL_R_OP 0 nat_4;
    do lsl_hi  <-- construct_thumb2_shift_rd_rm (int16_of_nat (reg2nat dst)) (int16_of_ireg src);
    do _       <-- add_ins_jittedthumb lsl_lo;
    do _       <-- add_ins_jittedthumb lsl_hi;
    do _       <-- upd_load_store_regs_jittedthumb dst LoadAndStore;
      if ireg_eqb src IR11 then
        returnM tt
      else
        do r <-- reg_of_ireg src;
          upd_load_store_regs_jittedthumb r LoadPerm
  | BPF_RSH32_REG =>
    do st1   <-- upd_IR11_jittedthumb true;

    do cmp_lo  <-- encode_thumb (int16_of_ireg src) CMP_I_OP 0 nat_4;
    do _       <-- add_ins_jittedthumb cmp_lo;
    do _       <-- add_ins_jittedthumb int16_0x0f20;

    do b_r1    <-- is_non_reg R1;
    do b_lt    <--
      if b_r1 then
        construct_thumb_b COND_LT int16_6
      else
        construct_thumb_b COND_LT int16_10;

    do _       <-- add_ins_jittedthumb b_lt;

    do _       <-- jit_alu32_store_flag int32_11;

    do _       <-- add_ins_jittedthumb BLT_0;

    do lsr_lo  <-- encode_thumb (int16_of_nat (reg2nat dst)) LSR_R_OP 0 nat_4;
    do lsr_hi  <-- construct_thumb2_shift_rd_rm (int16_of_nat (reg2nat dst)) (int16_of_ireg src);
    do _       <-- add_ins_jittedthumb lsr_lo;
    do _       <-- add_ins_jittedthumb lsr_hi;
    do _       <-- upd_load_store_regs_jittedthumb dst LoadAndStore;
      if ireg_eqb src IR11 then
        returnM tt
      else
        do r <-- reg_of_ireg src;
          upd_load_store_regs_jittedthumb r LoadPerm

  | BPF_XOR32_REG =>
    do ins_lo  <-- encode_thumb (int16_of_nat (reg2nat dst)) EOR_R_OP 0 nat_4;
    do ins_hi  <-- encode_thumb (int16_of_nat (reg2nat dst)) (int16_of_ireg src) nat_8 nat_4;
    do _       <-- add_ins_jittedthumb ins_lo;
    do _       <-- add_ins_jittedthumb ins_hi;
    do _       <-- upd_load_store_regs_jittedthumb dst LoadAndStore;
      if ireg_eqb src IR11 then
        returnM tt
      else
        do r <-- reg_of_ireg src;
          upd_load_store_regs_jittedthumb r LoadPerm
  | BPF_MOV32_REG =>
    if reg_ireg_eqb dst src then
      returnM tt
    else
      do d       <-- if Int.lt (int16_of_nat (reg2nat dst)) int16_8 then returnM int16_0 else returnM int16_1;
      do rdn     <-- if Int.lt (int16_of_nat (reg2nat dst)) int16_8 then
                        returnM (int16_of_nat (reg2nat dst))
                      else
                        returnM (int16_sub (int16_of_nat (reg2nat dst)) int16_8);
      do ins_rdn <-- encode_thumb rdn MOV_R_OP 0 nat_3;
      do ins_rm  <-- encode_thumb (int_of_ireg src)  ins_rdn nat_3 nat_4;
      do ins     <-- encode_thumb d ins_rm nat_7 nat_1;

      do _       <-- add_ins_jittedthumb ins;
      do _       <-- upd_load_store_regs_jittedthumb dst StorePerm;
        if ireg_eqb src IR11 then
          returnM tt
        else
          do r <-- reg_of_ireg src;
            upd_load_store_regs_jittedthumb r LoadPerm
  | BPF_ARSH32_REG =>
    do st1   <-- upd_IR11_jittedthumb true;

    do cmp_lo  <-- encode_thumb (int16_of_ireg src) CMP_I_OP 0 nat_4;
    do _       <-- add_ins_jittedthumb cmp_lo;
    do _       <-- add_ins_jittedthumb int16_0x0f20;

    do b_r1    <-- is_non_reg R1;
    do b_lt    <--
      if b_r1 then
        construct_thumb_b COND_LT int16_6
      else
        construct_thumb_b COND_LT int16_10;

    do _       <-- add_ins_jittedthumb b_lt;

    do _       <-- jit_alu32_store_flag int32_11;

    do _       <-- add_ins_jittedthumb BLT_0;

    do asr_lo  <-- encode_thumb (int16_of_nat (reg2nat dst)) ASR_R_OP 0 nat_4;
    do asr_hi  <-- construct_thumb2_shift_rd_rm (int16_of_nat (reg2nat dst)) (int16_of_ireg src);
    do _       <-- add_ins_jittedthumb asr_lo;
    do _       <-- add_ins_jittedthumb asr_hi;

    do _       <-- upd_load_store_regs_jittedthumb dst LoadAndStore;
      if ireg_eqb src IR11 then
        returnM tt
      else
        do r <-- reg_of_ireg src;
          upd_load_store_regs_jittedthumb r LoadPerm

  | BPF_ALU32_REG_ILLEGAL_INS => upd_flag BPF_ILLEGAL_ALU
  end.


Definition bpf_alu32_to_thumb_imm (op: opcode_alu32_imm) (dst: reg) (imm8: int): M unit :=
  match op with
  | BPF_ADD32_IMM =>
    do ins_lo    <-- encode_thumb (int_of_nat (reg2nat dst)) ADD_I_OP 0 nat_4;
    do ins_hi    <-- encode_thumb (int_of_nat (reg2nat dst)) imm8 nat_8 nat_4;
    do _         <-- add_ins_jittedthumb ins_lo;
    do _         <-- add_ins_jittedthumb ins_hi;
      upd_load_store_regs_jittedthumb dst LoadAndStore
  | BPF_SUB32_IMM =>
    do ins_lo    <-- encode_thumb (int_of_nat (reg2nat dst)) SUB_I_OP 0 nat_4;
    do ins_hi    <-- encode_thumb (int_of_nat (reg2nat dst)) imm8 nat_8 nat_4;
    do _         <-- add_ins_jittedthumb ins_lo;
    do _         <-- add_ins_jittedthumb ins_hi;
      upd_load_store_regs_jittedthumb dst LoadAndStore

  | BPF_OR32_IMM =>
    do ins_lo    <-- encode_thumb (int_of_nat (reg2nat dst)) ORR_I_OP 0 nat_4;
    do ins_hi    <-- encode_thumb (int_of_nat (reg2nat dst)) imm8 nat_8 nat_4;
    do _         <-- add_ins_jittedthumb ins_lo;
    do _         <-- add_ins_jittedthumb ins_hi;
      upd_load_store_regs_jittedthumb dst LoadAndStore

  | BPF_AND32_IMM =>
    do ins_lo    <-- encode_thumb (int_of_nat (reg2nat dst)) AND_I_OP 0 nat_4;
    do ins_hi    <-- encode_thumb (int_of_nat (reg2nat dst)) imm8 nat_8 nat_4;
    do _         <-- add_ins_jittedthumb ins_lo;
    do _         <-- add_ins_jittedthumb ins_hi;
      upd_load_store_regs_jittedthumb dst LoadAndStore

  | BPF_NEG32_IMM =>
    do ins_lo    <-- encode_thumb (int_of_nat (reg2nat dst)) RSB_I_OP 0 nat_4;
    do ins_hi    <-- encode_thumb (int_of_nat (reg2nat dst)) Int.zero nat_8 nat_4;
    do _         <-- add_ins_jittedthumb ins_lo;
    do _         <-- add_ins_jittedthumb ins_hi;
      upd_load_store_regs_jittedthumb dst LoadAndStore

  | BPF_XOR32_IMM =>
    do ins_lo    <-- encode_thumb (int_of_nat (reg2nat dst)) EOR_I_OP 0 nat_4;
    do ins_hi    <-- encode_thumb (int_of_nat (reg2nat dst)) imm8 nat_8 nat_4;
    do _         <-- add_ins_jittedthumb ins_lo;
    do _         <-- add_ins_jittedthumb ins_hi;
      upd_load_store_regs_jittedthumb dst LoadAndStore
  | BPF_MOV32_IMM =>
    do ins_hi    <-- encode_thumb (int_of_nat (reg2nat dst)) imm8 nat_8 nat_4;
    do _         <-- add_ins_jittedthumb MOVW_OP;
    do _         <-- add_ins_jittedthumb ins_hi;
      upd_load_store_regs_jittedthumb dst StorePerm
  | _ => upd_flag BPF_ILLEGAL_ALU
  end.


Definition mov_int_to_reg_binary (i: int) (r: ireg): M unit :=
  do lo_imm8   <-- decode_thumb i 0       nat_8;
  do lo_imm3   <-- decode_thumb i nat_8   nat_3;
  do lo_i      <-- decode_thumb i nat_11  nat_1;
  do lo_imm4   <-- decode_thumb i nat_12  nat_4;
(**r - encoding T3
MOVW Rd, #imm16 (= imm4:i:imm3:imm8)

 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0     1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0
 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0     5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 --------------------------------    --------------------------------
|1 1 1 1 0|i|1 0|0|1|0 0| imm4  |   |0| imm3|  Rd   |  imm8         |
 --------------------------------    -------------------------------- *)
  do movw_lo_0 <-- encode_thumb lo_imm4 MOVW_OP   0       nat_4;
  do movw_lo   <-- encode_thumb lo_i    movw_lo_0 nat_10  nat_1;

  do movw_hi_0 <-- encode_thumb (int_of_ireg r) lo_imm8   nat_8   nat_4;
  do movw_hi   <-- encode_thumb lo_imm3         movw_hi_0 nat_12  nat_3;

  do _         <-- add_ins_jittedthumb movw_lo;
  do _         <-- add_ins_jittedthumb movw_hi;

  do hi_32     <-- decode_thumb i nat_16 nat_16;

  if Int.eq hi_32 Int.zero then
    returnM tt
  else
    do hi_imm8   <-- decode_thumb i nat_16 nat_8;
    do hi_imm3   <-- decode_thumb i nat_24 nat_3;
    do hi_i      <-- decode_thumb i nat_27 nat_1;
    do hi_imm4   <-- decode_thumb i nat_28 nat_4;

(**r - encoding T1
MOVT Rd, #imm16 (= imm4:i:imm3:imm8)

 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0     1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0
 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0     5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 --------------------------------    --------------------------------
|1 1 1 1 0|i|1 0|1|1|0|0| imm4  |   |0| imm3|  Rd   |  imm8         |
 --------------------------------    -------------------------------- *)
    do movt_lo_0 <-- encode_thumb hi_imm4 MOVT_OP   0       nat_4;
    do movt_lo   <-- encode_thumb hi_i    movt_lo_0 nat_10  nat_1;
    do _         <-- add_ins_jittedthumb movt_lo;

    do movt_hi_0 <-- encode_thumb (int_of_ireg r) hi_imm8   nat_8   nat_4;
    do movt_hi   <-- encode_thumb hi_imm3         movt_hi_0 nat_12  nat_3;
      add_ins_jittedthumb movt_hi.

Definition nat_to_opcode_alu32 (op: nat8): M opcode_alu32 :=
  if Int.eq (Int.and (nat2int op) int32_7) int32_4 then
    if Int.eq Int.zero (Int.and (nat2int op) int32_8) then
      returnM ALU32_IMM
    else
      returnM ALU32_REG
  else
    returnM ALU32_ILLEGAL_INS.

Definition nat_to_opcode_alu32_reg (op: nat8): M opcode_alu32_reg := returnM (nat_to_opcode_alu32_reg op).

Definition nat_to_opcode_alu32_imm (op: nat8): M opcode_alu32_imm := returnM (nat_to_opcode_alu32_imm op).

Definition bpf_alu32_to_thumb (ins: int64): M unit :=
  do op    <-- get_opcode_ins ins;
  do opc   <-- nat_to_opcode_alu32 op;
  do dst   <-- get_dst ins;
  do imm32 <-- get_immediate ins;
    match opc with
    | ALU32_REG =>
      do opr <-- nat_to_opcode_alu32_reg op;
      do src   <-- get_src ins;
        bpf_alu32_to_thumb_reg opr dst (ireg_of_reg src)
    | ALU32_IMM =>
      do opi <-- nat_to_opcode_alu32_imm op;
        if (Bool.eqb (opcode_alu32_imm_eqb opi BPF_MUL32_IMM) false) && (Int_leu Int.zero imm32) && (Int_leu imm32 int32_0xff) then
          bpf_alu32_to_thumb_imm opi dst imm32
        else
          do _ <-- upd_IR11_jittedthumb true;
          do _ <-- mov_int_to_reg_binary (sint32_to_uint32 imm32) IR11;
          do opk <-- opcode_reg_of_imm opi;
            bpf_alu32_to_thumb_reg opk dst IR11
    | ALU32_ILLEGAL_INS => upd_flag BPF_ILLEGAL_ALU
    end.

Definition get_store_ins_num: M nat :=
  do b  <-- is_store_reg R0;
  do n0 <-- if b then returnM nat_1 else returnM 0%nat;
  do b  <-- is_store_reg R1;
  do n1 <-- if b then returnM (Nat.add n0 nat_1) else returnM n0;
  do b  <-- is_store_reg R2;
  do n2 <-- if b then returnM (Nat.add n1 nat_1) else returnM n1;
  do b  <-- is_store_reg R3;
  do n3 <-- if b then returnM (Nat.add n2 nat_1) else returnM n2;
  do b  <-- is_store_reg R4;
  do n4 <-- if b then returnM (Nat.add n3 nat_1) else returnM n3;
  do b  <-- is_store_reg R5;
  do n5 <-- if b then returnM (Nat.add n4 nat_1) else returnM n4;
  do b  <-- is_store_reg R6;
  do n6 <-- if b then returnM (Nat.add n5 nat_1) else returnM n5;
  do b  <-- is_store_reg R7;
  do n7 <-- if b then returnM (Nat.add n6 nat_1) else returnM n6;
  do b  <-- is_store_reg R8;
  do n8 <-- if b then returnM (Nat.add n7 nat_1) else returnM n7;
  do b  <-- is_store_reg R9;
  do n9 <-- if b then returnM (Nat.add n8 nat_1) else returnM n8;
  do b  <-- is_store_reg R10;
    if b then returnM (Nat.add n9 nat_1) else returnM n9.


Fixpoint jit_alu32_to_thumb_pass2_aux (fuel pc: nat): M unit :=
  match fuel with
  | O => returnM tt
  | S n =>
    do ins0 <-- eval_thumb_ins (int_of_nat pc);
      if orb (Int.eq ins0 BNE_0) (Int.eq ins0 BLT_0) then
        do store_len <-- get_store_ins_num;
        do ofs       <-- returnM (int_of_nat (Nat.div (Nat.add (Nat.mul fuel nat_2) (Nat.mul store_len nat_4)) nat_2));
        do ins       <-- encode_thumb ofs ins0 0 nat_8;
        do _         <-- upd_thumb_jittedthumb ins pc;
          jit_alu32_to_thumb_pass2_aux n (Nat.add pc nat_1)
      else
        jit_alu32_to_thumb_pass2_aux n (Nat.add pc nat_1)
  end.

Definition jit_alu32_to_thumb_pass2: M unit :=
  do len <-- eval_thumb_len;
    jit_alu32_to_thumb_pass2_aux len 0.

Fixpoint jit_alu32_to_thumb_pass1 (fuel entry_point: nat): M unit :=
  match fuel with
  | O => jit_alu32_to_thumb_pass2
  | S n =>
    do ins <-- eval_ins (int_of_nat entry_point);
    do b   <-- ins_is_bpf_alu32 ins;
      if b then
        do _ <-- bpf_alu32_to_thumb ins;
        do _ <-- upd_bpf_offset_jittedthumb;
          jit_alu32_to_thumb_pass1 n (Nat.add entry_point nat_1)
      else
        jit_alu32_to_thumb_pass2
  end.

(** * Store Stage: *)

Definition jit_alu32_thumb_upd_store (r: reg): M unit :=
  do b <-- is_store_reg r;
    if b then
    do int_r   <-- returnM (int16_of_nat (reg2nat r));
      jit_alu32_thumb_store_template_jit int_r int16_12 (int16_mul int_r int16_8)
    else
      returnM tt.

Definition jit_alu32_thumb_store: M unit :=
  do _ <-- jit_alu32_thumb_load_template_jit int16_12 int16_12 int16_8;
  do _ <-- jit_alu32_thumb_upd_store R0;
  do _ <-- jit_alu32_thumb_upd_store R1;
  do _ <-- jit_alu32_thumb_upd_store R2;
  do _ <-- jit_alu32_thumb_upd_store R3;
  do _ <-- jit_alu32_thumb_upd_store R4;
  do _ <-- jit_alu32_thumb_upd_store R5;
  do _ <-- jit_alu32_thumb_upd_store R6;
  do _ <-- jit_alu32_thumb_upd_store R7;
  do _ <-- jit_alu32_thumb_upd_store R8;
  do _ <-- jit_alu32_thumb_upd_store R9;
    jit_alu32_thumb_upd_store R10.

Definition jit_alu32_store_flag_jit (f: int): M unit :=
  do movw_hi   <-- encode_thumb int16_11 f nat_8 nat_4;
  do _         <-- upd_jitted_list MOVW_OP;
  do _         <-- upd_jitted_list movw_hi;

  do b         <-- is_non_reg R1;
  do st1       <--
    if b then
      returnM tt
    else
      jit_alu32_thumb_store_template_jit int16_1 int16_13 int16_4;

  do st2       <-- jit_alu32_thumb_load_template_jit int16_1 int16_12 int16_4;
  do st3       <-- jit_alu32_thumb_store_template_jit int16_11 int16_1 int16_0;
    if b then
      returnM tt
    else
      jit_alu32_thumb_load_template_jit int16_1 int16_13 int16_4.


Definition jit_alu32_thumb_store_succ_R0: M unit :=
  do _       <-- jit_alu32_store_flag_jit (int_of_flag BPF_SUCC_RETURN);
  do _       <-- jit_alu32_thumb_load_template_jit int16_12 int16_12 int16_8;
    jit_alu32_thumb_store_template_jit int16_0 int16_12 int16_0.

Definition jit_alu32_thumb_upd_reset (r: reg): M unit :=
  do b <-- is_non_reg r;
    if b then
      returnM tt
    else
      do ir <-- returnM (int16_of_nat (reg2nat r));
        jit_alu32_thumb_load_template_jit ir (int16_of_nat (ireg2nat SP)) (int16_mul ir int16_4).

Definition jit_alu32_thumb_reset: M unit :=
  do f <-- eval_use_IR11;
  do _ <-- if f then
    jit_alu32_thumb_load_template_jit int16_11 (int16_of_nat (ireg2nat SP)) int16_44
  else
    returnM tt;
  do _ <-- jit_alu32_thumb_upd_reset R10;
  do _ <-- jit_alu32_thumb_upd_reset R9;
  do _ <-- jit_alu32_thumb_upd_reset R8;
  do _ <-- jit_alu32_thumb_upd_reset R7;
  do _ <-- jit_alu32_thumb_upd_reset R6;
  do _ <-- jit_alu32_thumb_upd_reset R5;
    jit_alu32_thumb_upd_reset R4.

(** Post: *)

Definition jit_alu32_post: M unit :=
  do _       <-- jit_alu32_thumb_load_template_jit (int16_of_nat (ireg2nat SP)) (int16_of_nat (ireg2nat SP)) int16_0;
  do ins_rm  <-- encode_thumb (int16_of_nat (ireg2nat RA)) BX_OP nat_3 nat_4;
    upd_jitted_list ins_rm.

(** * Jit Procedure *)

Fixpoint copy_thumb_list_from_to_aux (fuel pc: nat): M unit :=
  match fuel with
  | O => returnM tt
  | S n =>
    do ins0 <-- eval_thumb_ins (int_of_nat pc);
    do _    <-- upd_jitted_list ins0;
      copy_thumb_list_from_to_aux n (Nat.add pc nat_1)
  end.

Definition copy_thumb_list_from_to: M unit :=
  do len <-- eval_thumb_len;
  copy_thumb_list_from_to_aux len 0.

Definition jit_alu32_to_thumb (pc: nat) : M unit :=
  do _    <-- reset_init_jittedthumb;
  do len  <-- eval_ins_len;
  do _    <-- jit_alu32_to_thumb_pass1 (nat_of_int len) pc;

  do ofs0 <-- eval_jitted_len;
  do ofs1 <-- eval_offset;
  do st2  <-- add_key_value2 pc ofs0 ofs1;

  do _    <-- jit_alu32_pre;
  do _    <-- jit_alu32_thumb_save;
  do _    <-- jit_alu32_thumb_load;
  do _    <-- copy_thumb_list_from_to;
  do _    <-- jit_alu32_thumb_store;
  do _    <-- jit_alu32_thumb_reset;
    jit_alu32_post.

Fixpoint jit_alu32_aux (fuel pc: nat) (pre_is_alu32: bool) : M unit :=
  match fuel with
  | O => returnM tt
  | S n =>
    do ins  <-- eval_ins (int_of_nat pc);
    do b    <-- ins_is_bpf_alu32 ins;
      if b then
        if Bool.eqb pre_is_alu32 false then
          do _ <-- jit_alu32_to_thumb pc;
            jit_alu32_aux n (Nat.add pc nat_1) true
        else
          jit_alu32_aux n (Nat.add pc nat_1) true
      else
        do b <-- ins_is_bpf_jump ins;
        if b then
          do ofs      <-- get_offset ins;
          do next_pc  <-- returnM (Int.add (Int.add (int_of_nat pc) ofs) Int.one);
          do next_ins <-- eval_ins next_pc;
          do b        <-- ins_is_bpf_alu32 next_ins;
            if b then
              do _    <-- jit_alu32_to_thumb (nat_of_int next_pc);
                jit_alu32_aux n (Nat.add pc nat_1) false
            else
              jit_alu32_aux n (Nat.add pc nat_1) false
      else (**r when ins is not jump *)
        jit_alu32_aux n (Nat.add pc nat_1) false
  end.

Definition jit_alu32 : M unit :=
  do len  <-- eval_ins_len;
    jit_alu32_aux (nat_of_int len) 0 false.

Close Scope monad_scope.
Close Scope string_scope.
Close Scope asm.
Close Scope bool_scope.
Close Scope Z_scope.
