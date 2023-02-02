From compcert Require Import Ctypes AST Integers Values Memory.
From compcert.arm Require Import AsmSyntax BinSyntax BinDecode.
From Coq Require Import ZArith List.
Import ListNotations.

From bpf.comm Require Import Regs rBPFAST BinrBPF ListAsArray.
From bpf.jit.thumb Require Import Arm32Reg ThumbEncode.

Open Scope bool_scope.

(** * THUMB/THUMB2 Decode *)

(** There are many encoding ways for ARM32, here we adopt `encoding T1/T2/T3` for Thumb ISA.
*)


(** We only consider the following instructions

0) THUMB 16-bit (0x15_10: 010001)
- ADD_REG
- MOV_REG
- CMP_REG
- BX
and 
- B 

1) THUMB2 32-bit
  1.1) ALU_REG (op15_11 = 11101)
  - AND_REG
  - EOR_REG
  - ORR_REG
  - RSB_REG
  - SUB_REG

  1.2) ALU_IMM (op15 = 11110)
  - ADD_IMM
  - AND_IMM
  - EOR_IMM
  - ORR_IMM
  - RSB_IMM
  - SUB_IMM
  - MOVW
  - MOVT
  - CMP_IMM

  1.3) MEM_IMM & MEM_REG & ALU (op15_11= 11111)
  - LDR_IMM
  - STR_IMM
  - LDR_REG
  - STR_REG

  - UDIV
  - MUL
  - ASR_REG
  - LSL_REG
  - LSR_REG *)

(*
Definition decode_arm32 (ins: int) (from size: nat): int :=
  Int.unsigned_bitfield_extract (Z.of_nat from) (Z.of_nat size) ins.

Definition int2ireg (r: int): option ireg :=
  if Int.eq r (Int.repr 0) then
    Some IR0
  else if Int.eq r (Int.repr 1) then
    Some IR1
  else if Int.eq r (Int.repr 2) then
    Some IR2
  else if Int.eq r (Int.repr 3) then
    Some IR3
  else if Int.eq r (Int.repr 4) then
    Some IR4
  else if Int.eq r (Int.repr 5) then
    Some IR5
  else if Int.eq r (Int.repr 6) then
    Some IR6
  else if Int.eq r (Int.repr 7) then
    Some IR7
  else if Int.eq r (Int.repr 8) then
    Some IR8
  else if Int.eq r (Int.repr 9) then
    Some IR9
  else if Int.eq r (Int.repr 10) then
    Some IR10
  else if Int.eq r (Int.repr 11) then
    Some IR11
  else if Int.eq r (Int.repr 12) then
    Some IR12
  else if Int.eq r (Int.repr 13) then
    Some IR13
  else if Int.eq r (Int.repr 14) then
    Some IR14
  else
    None.

(**r From ARMv7-M Architecture Reference Manual

If the value of bits[15:11] of the halfword being decoded is one of the following, the halfword is the first halfword
of a 32-bit instruction:
- 0b11101.
- 0b11110.
- 0b11111.
Otherwise, the halfword is a 16-bit instruction.

*)
Definition is_thumb2 (ins: int): bool :=
  (**r bits [15:11] *)
  let op := decode_arm32 ins 11 5 in
    if Int.eq op (Int.repr 0x1d) then (**r 0b11101 *)
      true
    else if Int.eq op (Int.repr 0x1e) then (**r 0b11110 *)
      true
    else if Int.eq op (Int.repr 0x1f) then (**r 0b11111 *)
      true
    else
      false.

(** For THUMB ISA, we only consider the following instructions:
1. 16-bit (0x15_10: 010001)
- ADD_REG
- MOV_REG
- CMP_REG
- BX
- B  *)
Definition decode_thumb (ins: int): option instruction :=
  let op15_10 := decode_arm32 ins 10 6 in
    if Int.eq op15_10 (Int.repr 0x11) then (**r 0b010001 *)
      (**r let's say op_9_8 is the opcode *)
      let op := decode_arm32 ins 8 2 in
      let rm := int2ireg (decode_arm32 ins 3 4) in
      let rn := decode_arm32 ins 0 3 in
      let n  := decode_arm32 ins 7 1 in
      let rd := int2ireg (encode_arm32 n rn 3 1) in
        match rd, rm with
        | Some Rd, Some Rm =>
          if Int.eq op Int.zero then
(**r - encoding T2
ADD Rdn, Rm (Rdn = D:Rdn)
 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0
 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 --------------------------------
|0 1 0 0 0 1|0 0|D|  Rm   |Rdn  |
 -------------------------------- *)
            Some (Padd Rd Rd (SOreg Rm))
          else if Int.eq op Int.one then
(**r - encoding T2
CMP Rn, Rm (Rn = N:Rn)
 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0
 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 --------------------------------
|0 1 0 0 0 1|0 1|N|   Rm  |  Rn |
 -------------------------------- *)
            Some (Pcmp Rd (SOreg Rm)) (**r here Rd i.e. Rn *)
          else if Int.eq op (Int.repr 2) then
(**r - encoding T1
MOV Rd, Rm (Rd = D:Rd)
 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0
 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 --------------------------------
|0 1 0 0 0 1|1 0|D|  Rm   | Rd  |
 -------------------------------- *)
            Some (Pmov Rd (SOreg Rm))
          else if andb (Int.eq op (Int.repr 3)) (ireg_eqb Rd IR0) then (**r here op must be = 3 &&  Rd = IR0 *)
(**r - encoding T1
BX Rm
 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0
 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 --------------------------------
|0 1 0 0 0 1|1 1|0|   Rm  |0 0 0|
 -------------------------------- *)
            Some (Pbreg Rm)
          else
            None
        | _, _ => None
        end
    else
      let op15_12 := decode_arm32 ins 12 4 in
        if Int.eq op15_12 (Int.repr 0xd) then (**r 0b1101 *)
          let imm8 := decode_arm32 ins 0 8 in
          (**r NB: permitted offsets of T2 is `Even numbers` in the range –256 to 254, for imm8:'0'
                  so, imm8 \in [-128, 127] *)
(**r - encoding T1
B label ( = imm8:'0' )
 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0
 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 --------------------------------
|1 1 0 1|  cond |     imm8      |
 -------------------------------- *)
            if andb (Int.cmpu Cle (Int.repr (-128)%Z) imm8) (Int.cmpu Cle imm8 (Int.repr 127)) then
              Some (Pb (Ptrofs.of_ints imm8))
            else (**r B offset error! *)
              None
        else
          None.

(** imm12 = i:imm3:imm8
Now, we say i:imm3=0000 i.e. we don't conside shift
so imm8 \in [0, 255]
 *)
Definition thumb_constant_range_imm12 (i imm3 imm8: int): bool :=
  if andb 
      (andb (Int.eq i Int.zero) (Int.eq imm3 Int.zero))
      (andb (Int.cmpu Cle Int.zero imm8) (Int.cmpu Cle imm8 (Int.repr 255))) then
    true
  else
    false.

(** For THUMB2 ISA, we only consider the following instructions:
  1.1. ALU_REG (op15_11 = 11101)
  - AND_REG
  - EOR_REG
  - ORR_REG
  - RSB_REG
  - SUB_REG

  1.2. ALU_IMM (op15 = 11110)
  - ADD_IMM
  - AND_IMM
  - EOR_IMM
  - ORR_IMM
  - RSB_IMM
  - SUB_IMM
  - MOVW
  - MOVT
  - CMP_IMM

  1.3. MEM_IMM & MEM_REG & ALU (op15_11= 11111)
  - LDR_IMM
  - STR_IMM
  - LDR_REG
  - STR_REG

  - UDIV
  - MUL
  - ASR_REG
  - LSL_REG
  - LSR_REG  *)

Definition decode_thumb2 (ins_lo ins_hi: int): option instruction :=
  let lo_op15_11 := decode_arm32 ins_lo 11 5 in
    if Int.eq lo_op15_11 (Int.repr 0x1d) then (**r 0b11101 *)
      let lo_op10_9  := decode_arm32 ins_lo 9 2 in
      (**r let's say lo_8_5 is opcode *)
      let op         := decode_arm32 ins_lo 5 4 in
      let lo_opS     := decode_arm32 ins_lo 4 1 in
      let rn         := int2ireg (decode_arm32 ins_lo 0 4) in

      let hi_op15_12 := decode_arm32 ins_hi 12 4 in
      let rd         := int2ireg (decode_arm32 ins_hi 8 4) in
      let hi_op7_4   := decode_arm32 ins_hi 4 4 in
      let rm         := int2ireg (decode_arm32 ins_hi 0 4) in
        if andb
            (andb (Int.eq lo_op10_9 Int.one)    (**r lo_10_9 = 0b01 *)
                  (Int.eq lo_opS Int.zero))     (**r S = 0 *)
            (andb (Int.eq hi_op15_12 Int.zero)  (**r hi_15_12 = 0b0000 *)
                  (Int.eq hi_op7_4 Int.zero))   (**r hi_7_4 = 0b0000 *) then
          match rn, rd, rm with
          | Some Rn, Some Rd, Some Rm =>
            if Int.eq op Int.zero then
(**r - encoding T2
AND Rd, Rn, Rm

 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0     1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0
 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0     5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 --------------------------------    --------------------------------
|1 1 1 0 1|0 1|0 0 0 0|S|  Rn   |   |0|0 0 0|  Rd   |0 0|typ|  Rm   |
 --------------------------------    -------------------------------- *)
              Some (Pand Rd Rn (SOreg Rm))
            else if Int.eq op (Int.repr 0x2) then
(**r - encoding T2
ORR Rd, Rn, Rm

 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0     1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0
 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0     5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 --------------------------------    --------------------------------
|1 1 1 0 1|0 1|0 0 1 0|S|  Rn   |   |0|0 0 0|  Rd   |0 0|typ|  Rm   |
 --------------------------------    -------------------------------- *)
              Some (Porr Rd Rn (SOreg Rm))
            else if Int.eq op (Int.repr 0x4) then
(**r - encoding T2
EOR Rd, Rn, Rm

 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0     1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0
 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0     5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 --------------------------------    --------------------------------
|1 1 1 0 1|0 1|0 1 0 0|S|  Rn   |   |0|0 0 0|  Rd   |0 0|typ|  Rm   |
 --------------------------------    -------------------------------- *)
              Some (Peor Rd Rn (SOreg Rm))
            else if Int.eq op (Int.repr 0xd) then
(**r - encoding T2
SUB Rd, Rn, Rm

 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0     1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0
 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0     5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 --------------------------------    --------------------------------
|1 1 1 0 1|0 1|1 1 0 1|S|  Rn   |   |0|0 0 0|  Rd   |0 0|typ|  Rm   |
 --------------------------------    -------------------------------- *)
              Some (Psub Rd Rn (SOreg Rm))
            else if Int.eq op (Int.repr 0xe) then
(**r - encoding T2
RSB Rd, Rn, Rm

 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0     1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0
 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0     5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 --------------------------------    --------------------------------
|1 1 1 0 1|0 1|1 1 1 0|S|  Rn   |   |0|0 0 0|  Rd   |0 0|typ|  Rm   |
 --------------------------------    -------------------------------- *)
              Some (Prsb Rd Rn (SOreg Rm))
            else
              None
          | _, _, _ => None
          end
        else
          None

    else if Int.eq lo_op15_11 (Int.repr 0x1e) then (**r 0b11110 *)
      let i          := decode_arm32 ins_lo 10 1 in
      let lo_op9     := decode_arm32 ins_lo 9 1 in
      (**r let's say lo_8_5 is opcode *)
      let op         := decode_arm32 ins_lo 5 4 in
      let lo_opS     := decode_arm32 ins_lo 4 1 in
      let imm4       := decode_arm32 ins_lo 0 4 in
      let rn         := int2ireg imm4 in

      let hi_op15    := decode_arm32 ins_hi 15 1 in
      let imm3       := decode_arm32 ins_hi 12 3 in
      let rd         := int2ireg (decode_arm32 ins_hi 8 4) in
      let imm8       := decode_arm32 ins_hi 0 8 in

      (**r imm12 = i:imm3:imm8 *)
      let imm12      := encode_arm32 i (encode_arm32 imm3 imm8 8 3) 11 1 in
      (**r imm16 = imm4:imm12 *)
      let imm16      := encode_arm32 imm4 imm12 12 4 in

        if Int.eq hi_op15 Int.zero then (**r hi_15 = 0b0 *)
          (**r we firstly consider CMP *)
          if andb (Int.eq op (Int.repr 0xd))
              (andb (Int.eq lo_op9 Int.zero) (Int.eq lo_opS Int.one)) then
              match rn, rd with (**r we hope rd = 0b1111 i,e, None *)
              | Some Rn, None =>
(**r - encoding T2
CMP Rn, #imm12 (= i:imm3:imm8)

 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0     1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0
 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0     5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 --------------------------------    --------------------------------
|1 1 1 1 0|i|0|1 1 0 1|1|  Rn   |   |0| imm3|1 1 1 1|  imm8         |
 --------------------------------    -------------------------------- *)
                if thumb_constant_range_imm12 i imm3 imm8 then
                  Some (Pcmp Rn (SOimm imm12))
                else (**r imm12 error *)
                  None
              | _, _ => None
              end
          else
            match rd with
            | Some Rd =>
              (**r Then we consider MOVW and MOVT *)
              if andb (Int.eq lo_op9 Int.one) (Int.eq lo_opS Int.zero) then
                if Int.eq op (Int.repr 0x2) then
(**r - encoding T3
MOVW Rd, #imm16 (= imm4:i:imm3:imm8)

 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0     1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0
 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0     5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 --------------------------------    --------------------------------
|1 1 1 1 0|i|1 0|0|1|0 0| imm4  |   |0| imm3|  Rd   |  imm8         |
 --------------------------------    -------------------------------- *)
                  if andb (Int.cmpu Cle Int.zero imm16) (Int.cmpu Cle imm16 (Int.repr 65535)) then
                    Some (Pmovw Rd imm16)
                  else (**r imm16 error: 0-65535 for encoding T3 *)
                    None
                else if Int.eq op (Int.repr 0x6) then
(**r - encoding T1
MOVT Rd, #imm16 (= imm4:i:imm3:imm8)

 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0     1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0
 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0     5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 --------------------------------    --------------------------------
|1 1 1 1 0|i|1 0|1|1|0|0| imm4  |   |0| imm3|  Rd   |  imm8         |
 --------------------------------    -------------------------------- *)
                  if andb (Int.cmpu Cle Int.zero imm16) (Int.cmpu Cle imm16 (Int.repr 65535)) then
                    Some (Pmovt Rd imm16)
                  else (**r imm16 error: 0-65535 for encoding T3 *)
                    None
                else
                  None
              else if andb (Int.eq lo_op9 Int.zero) (Int.eq lo_opS Int.zero) then
              (**r Last, we consider other alu_imm: add, and, eor, orr, rsb and sub *)
                if thumb_constant_range_imm12 i imm3 imm8 then
                  match rn with
                  | Some Rn =>
                    if Int.eq op Int.zero then
(**r - encoding T1
AND Rd, Rn, #imm12 (= i:imm3:imm8)

 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0     1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0
 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0     5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 --------------------------------    --------------------------------
|1 1 1 1 0|i|0|0 0 0 0|S|  Rn   |   |0| imm3|  Rd   |  imm8         |
 --------------------------------    -------------------------------- *)
                        Some (Pand Rd Rn (SOimm imm12))
                    else if Int.eq op (Int.repr 0x2) then
(**r - encoding T1
ORR Rd, Rn, #imm12 (= i:imm3:imm8)

 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0     1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0
 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0     5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 --------------------------------    --------------------------------
|1 1 1 1 0|i|0|0 0 1 0|S|  Rn   |   |0| imm3|  Rd   |  imm8         |
 --------------------------------    -------------------------------- *)
                      Some (Porr Rd Rn (SOimm imm12))
                    else if Int.eq op (Int.repr 0x4) then
(**r - encoding T1
EOR Rd, Rn, #imm12 (= i:imm3:imm8)

 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0     1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0
 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0     5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 --------------------------------    --------------------------------
|1 1 1 1 0|i|0|0 1 0 0|S|  Rn   |   |0| imm3|  Rd   |  imm8         |
 --------------------------------    -------------------------------- *)
                      Some (Peor Rd Rn (SOimm imm12))
                    else if Int.eq op (Int.repr 0x8) then
(** - encoding T3
ADD Rd, Rn, #imm12 (= i:imm3:imm8)

 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0     1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0
 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0     5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 --------------------------------    --------------------------------
|1 1 1 1 0|i|0|1 0 0 0|S|  Rn   |   |0| imm3|  Rd   |  imm8         |
 --------------------------------    -------------------------------- *)
                      Some (Padd Rd Rn (SOimm imm12))
                    else if Int.eq op (Int.repr 0xd) then
(**r - encoding T3
SUB Rd, Rn, #imm12 (= i:imm3:imm8)

 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0     1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0
 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0     5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 --------------------------------    --------------------------------
|1 1 1 1 0|i|0|1 1 0 1|S|  Rn   |   |0| imm3|  Rd   |  imm8         |
 --------------------------------    -------------------------------- *)
                      Some (Psub Rd Rn (SOimm imm12))
                    else if Int.eq op (Int.repr 0xe) then
(**r - encoding T1
RSB Rd, Rn, #imm12 (= i:imm3:imm8)

 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0     1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0
 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0     5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 --------------------------------    --------------------------------
|1 1 1 1 0|i|0|1 1 1 0|S|  Rn   |   |0| imm3|  Rd   |  imm8         |
 --------------------------------    -------------------------------- *)
                      Some (Prsb Rd Rn (SOimm imm12))
                    else
                      None
                  | None => None
                  end
                else (**r imm12 error *)
                  None
              else
                None
            | None => None
            end
        else (**r this branch: hi_15 = 0b1 *)
          None

    else if Int.eq lo_op15_11 (Int.repr 0x1f) then (**r 0b11111 *)
      let lo_op10_9  := decode_arm32 ins_lo 9 2 in
      let op         := decode_arm32 ins_lo 5 4 in (**r let's say lo_8_5 is opcode *)
      let lo_opS     := decode_arm32 ins_lo 4 1 in
      let rn         := int2ireg (decode_arm32 ins_lo 0 4) in

      let hi_op15_12 := decode_arm32 ins_hi 12 4 in
      let rt         := int2ireg hi_op15_12 in
      let imm12      := decode_arm32 ins_hi 0 12 in

      let rd         := int2ireg (decode_arm32 ins_hi 8 4) in
      let hi_op7_4   := decode_arm32 ins_hi 4 4 in

      let rm         := int2ireg (decode_arm32 ins_hi 0 4) in
        if Int.eq lo_op10_9 Int.zero then
          (**r it maybe LDR_IMM/STR_IMM/LDR_REG/STR *)
          if Int.eq op (Int.repr 2) then
            match rn, rt, rm, rd with
            | Some Rn, Some Rt, Some Rm, Some Rd =>
              if andb (ireg_eqb Rd IR0) (Int.eq hi_op7_4 Int.zero) then
                if Int.eq lo_opS Int.zero then
(**r - encoding T2
STR Rt, Rn, Rm

 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0     1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0
 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0     5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 --------------------------------    --------------------------------
|1 1 1 1 1|0 0|0|0|1 0|0|  Rn   |   |   Rt  |0|0 0 0 0 0|0 0|  Rm   |
 --------------------------------    -------------------------------- *)
                  Some (Pstr Rt Rn (SOreg Rm))
                else if Int.eq lo_opS Int.one then
(**r - encoding T2
LDR Rt, Rn, Rm

 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0     1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0
 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0     5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 --------------------------------    --------------------------------
|1 1 1 1 1|0 0|0|0|1 0|1|  Rn   |   |   Rt  |0|0 0 0 0 0|0 0|  Rm   |
 --------------------------------    -------------------------------- *)
                  Some (Pldr Rt Rn (SOreg Rm))
                else
                  None
              else
                None
            | _, _, _, _ => None
            end
          else if Int.eq op (Int.repr 0x6) then
            if andb (Int.cmpu Cle Int.zero imm12) (Int.cmpu Cle imm12 (Int.repr 4095)) then
              match rn, rt with
              | Some Rn, Some Rt =>
                  if Int.eq lo_opS Int.zero then
(**r - encoding T3
STR Rt, Rn, #imm12

 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0     1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0
 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0     5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 --------------------------------    --------------------------------
|1 1 1 1 1|0 0|0|1|1 0|0|  Rn   |   |   Rt  |         imm12         |
 --------------------------------    -------------------------------- *)
                    Some (Pstr Rt Rn (SOimm imm12))
                  else if Int.eq lo_opS Int.one then
(**r - encoding T3
LDR Rt, Rn, #imm12

 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0     1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0
 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0     5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 --------------------------------    --------------------------------
|1 1 1 1 1|0 0|0|1|1 0|1|  Rn   |   |   Rt  |         imm12         |
 --------------------------------    -------------------------------- *)
                    Some (Pldr Rt Rn (SOimm imm12))
                  else
                    None
              | _, _ => None
              end
            else (**r imm12 error: 0-4095 for encoding T3 *)
              None
          else
            None

        else if Int.eq lo_op10_9 Int.one then
          (**r it maybe alu ... *)
          match rn, rm, rd with
          | Some Rn, Some Rm, Some Rd =>
            if Int.eq hi_op15_12 (Int.repr 0xf) then
              if Int.eq hi_op7_4 Int.zero then
                if Int.eq lo_opS Int.zero then
                  if Int.eq op Int.zero then
(**r - encoding T2
LSL Rd, Rn, Rm

 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0     1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0
 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0     5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 --------------------------------    --------------------------------
|1 1 1 1 1|0 1 0|0|0 0|S|  Rn   |   |1 1 1 1|  Rd   |0|0 0 0|  Rm   |
 --------------------------------    -------------------------------- *)
                    Some (Plsl Rd Rn Rm)
                  else if Int.eq op Int.one then
(**r - encoding T2
LSR Rd, Rn, Rm

 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0     1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0
 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0     5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 --------------------------------    --------------------------------
|1 1 1 1 1|0 1 0|0|0 1|S|  Rn   |   |1 1 1 1|  Rd   |0|0 0 0|  Rm   |
 --------------------------------    -------------------------------- *)
                    Some (Plsr Rd Rn Rm)
                  else if Int.eq op (Int.repr 0x2) then
(**r - encoding T2
ASR Rd, Rn, Rm

 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0     1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0
 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0     5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 --------------------------------    --------------------------------
|1 1 1 1 1|0 1 0|0|1 0|S|  Rn   |   |1 1 1 1|  Rd   |0|0 0 0|  Rm   |
 --------------------------------    -------------------------------- *)
                    Some (Pasr Rd Rn Rm)
                  else if Int.eq op (Int.repr 0x8) then
(**r - encoding T2
MUL Rd, Rn, Rm

 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0     1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0
 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0     5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 --------------------------------    --------------------------------
|1 1 1 1 1|0 1 1 0|0 0 0|  Rn   |   |1 1 1 1|  Rd   |0 0 0 0|  Rm   |
 --------------------------------    -------------------------------- *)
                    Some (Pmul Rd Rn Rm)
                  else
                    None

                else
                  None
              else if Int.eq hi_op7_4 (Int.repr 0xf) then
                if andb
                    (andb (Int.eq op (Int.repr 0xd)) (Int.eq lo_opS Int.one))
                    (andb (ireg_eqb Rd IR0)
                      (andb (ireg_eqb Rm IR0) (ireg_eqb Rn IR1))) then
(**r - encoding T1
UDIV Rd, Rn, Rm

 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0     1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0
 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0     5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 --------------------------------    --------------------------------
|1 1 1 1 1|0 1 1 1 0 1|1|  Rn   |   |1 1 1 1|   Rd  |1 1 1 1|  Rm   |
 --------------------------------    -------------------------------- *)
                  Some Pudiv
                else
                  None
              else
                None
            else
              None
          | _, _, _ => None
          end
        else
          None
    else (**r this case should be impossible *)
      None.

Definition find_instr (v:val) (m : mem) : option (instruction * bool) :=
  match Memory.Mem.loadv AST.Mint16unsigned m v with
  | Some (Vint op) =>
      if is_thumb2 op then
        match Mem.loadv Mint16unsigned m (Val.add v (Vint (Int.repr 2))) with
        | Some (Vint i) => option_map (fun x => (x,true)) (decode_thumb2 op i)
        | _              => None
        end
      else
        option_map (fun x => (x, false)) (decode_thumb op)
    | _            => None
  end. *)

Fixpoint arm32_decode_prog_aux (fuel pc: nat) (addr: val) (m: mem): list instruction :=
  match fuel with
  | O => []
  | S n =>
    let ptr := Val.add addr (Vint (Int.repr (Z.of_nat (2 * pc)%nat))) in
    match find_instr ptr m with
    | Some (ins, b) =>
      if b then
        [ins] ++ (arm32_decode_prog_aux n (S (S pc)) addr m)
      else
        [ins] ++ (arm32_decode_prog_aux n (S pc) addr m)
    | None => []
    end
  end.

Definition arm32_decode_prog (addr: val) (len: nat) (m: mem): list instruction :=
  arm32_decode_prog_aux len 0 addr m.
