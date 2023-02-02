From compcert.lib Require Import Integers.
From compcert.arm Require Import Asm AsmSyntax BinSyntax BinSem BinDecode.
From compcert.common Require Import Values Memory.

From bpf.comm Require Import Regs.
From bpf.jit.thumb Require Import Arm32Reg ThumbInsOp JITState.
From bpf.jit.simulation Require Import BitfieldLemma.

From Coq Require Import ZArith Arith Lia.
Open Scope Z_scope.

Global Transparent Archi.ptr64.

Ltac int_true_false :=
  match goal with
  | |- context [Int.lt ?X ?Y]  =>
    try change (Int.lt X Y) with true;
    try change (Int.lt X Y) with false; simpl
  | |- context [Int.eq ?X ?Y]  =>
    try change (Int.eq X Y) with false; simpl
  | |- context [Int.unsigned_bitfield_extract ?X ?Y ?Z = ?W]  =>
    try (change (Int.unsigned_bitfield_extract X Y Z) with W; simpl; reflexivity)
  | |- context [Int.bitfield_insert ?X ?Y ?Z ?K = ?W]  =>
    try (change (Int.bitfield_insert X Y Z K) with W; simpl; reflexivity)
  end.

Lemma int2ireg_id_of_reg_same:
  forall r,
    int2ireg (Int.repr (id_of_reg r)) = Some (ireg_of_reg r).
Proof.
  unfold int2ireg.
  intros; destruct r; simpl; auto with ints.
Qed.

Lemma lemma_thumb_add_reg:
  forall rd r m b ofs,
    match
    Val.load_result AST.Mint16unsigned
      (Vint
         (encode_arm32 (if Int.lt (Int.repr (id_of_reg rd)) (Int.repr 8) then Int.zero else Int.one)
            (encode_arm32 (int_of_ireg (ireg_of_reg r))
               (encode_arm32
                  (if Int.lt (Int.repr (id_of_reg rd)) (Int.repr 8)
                   then Int.repr (id_of_reg rd)
                   else Int.sub (Int.repr (id_of_reg rd)) (Int.repr 8)) ADD_R_OP 0 3) 3 4) 7 1))
    with
    | Vint op =>
        if is_thumb2 op
        then
         match
           Mem.load AST.Mint16unsigned m b ofs
         with
         | Some (Vint i) => Coqlib.option_map (fun x : instruction => (x, true)) (decode_thumb2 op i)
         | _ => None
         end
        else Coqlib.option_map (fun x : instruction => (x, false)) (decode_thumb op)
    | _ => None
    end = Some ((Padd (ireg_of_reg rd) (ireg_of_reg rd) (SOreg (ireg_of_reg r))), false).
Proof.
  intros.
  simpl; unfold is_thumb2.
  assert (Heq:
   (decode_arm32
      (Int.zero_ext 16
         (encode_arm32 (if Int.lt (Int.repr (id_of_reg rd)) (Int.repr 8) then Int.zero else Int.one)
            (encode_arm32 (int_of_ireg (ireg_of_reg r))
               (encode_arm32
                  (if Int.lt (Int.repr (id_of_reg rd)) (Int.repr 8)
                   then Int.repr (id_of_reg rd)
                   else Int.sub (Int.repr (id_of_reg rd)) (Int.repr 8)) ADD_R_OP 0 3) 3 4) 7 1)) 11 5) =
    (Int.repr 8)). {
    clear.
    unfold decode_arm32, encode_arm32.
    rewrite Int_unsigned_bitfield_extract_zero_ext_narrow; try lia.
    erewrite bitfield_insert_unsigned_bitfield_extract_same_outside with
      (pos0 := 7) (width0 := 1) (pos1 := 11) (width1 := 5); change Int.zwordsize with 32; try lia;
    [| reflexivity | reflexivity ].
    erewrite bitfield_insert_unsigned_bitfield_extract_same_outside with
      (pos0 := 3) (width0 := 4) (pos1 := 11) (width1 := 5); change Int.zwordsize with 32; try lia;
    [| reflexivity | reflexivity ].
    erewrite bitfield_insert_unsigned_bitfield_extract_same_outside with
      (pos0 := 0) (width0 := 3) (pos1 := 11) (width1 := 5); change Int.zwordsize with 32; try lia;
    [| reflexivity | reflexivity ].
    unfold ADD_R_OP; simpl.
    int_true_false.
  }
  rewrite Heq; clear Heq.
  (* why the following two don't work??? TODO
  repeat int_true_false.
  auto with ints. *)
  change (Int.eq (Int.repr 8) (Int.repr 29)) with false; simpl.
  change (Int.eq (Int.repr 8) (Int.repr 30)) with false; simpl.
  change (Int.eq (Int.repr 8) (Int.repr 31)) with false; simpl.
  unfold Coqlib.option_map.
  unfold decode_thumb.

  assert (Heq:
   (decode_arm32
      (Int.zero_ext 16
         (encode_arm32 (if Int.lt (Int.repr (id_of_reg rd)) (Int.repr 8) then Int.zero else Int.one)
            (encode_arm32 (int_of_ireg (ireg_of_reg r))
               (encode_arm32
                  (if Int.lt (Int.repr (id_of_reg rd)) (Int.repr 8)
                   then Int.repr (id_of_reg rd)
                   else Int.sub (Int.repr (id_of_reg rd)) (Int.repr 8)) ADD_R_OP 0 3) 3 4) 7 1)) 10 6) =
    (Int.repr 17)). {
    unfold decode_arm32, encode_arm32.
    rewrite Int_unsigned_bitfield_extract_zero_ext_narrow; try lia.
    erewrite bitfield_insert_unsigned_bitfield_extract_same_outside with
      (pos0 := 7) (width0 := 1) (pos1 := 10) (width1 := 6); change Int.zwordsize with 32; try lia;
    [| reflexivity | reflexivity ].
    erewrite bitfield_insert_unsigned_bitfield_extract_same_outside with
      (pos0 := 3) (width0 := 4) (pos1 := 10) (width1 := 6); change Int.zwordsize with 32; try lia;
    [| reflexivity | reflexivity ].
    erewrite bitfield_insert_unsigned_bitfield_extract_same_outside with
      (pos0 := 0) (width0 := 3) (pos1 := 10) (width1 := 6); change Int.zwordsize with 32; try lia;
    [| reflexivity | reflexivity ].
    simpl.
    int_true_false.
  }
  rewrite Heq; clear Heq.
  rewrite Int.eq_true.

  assert (Heq:
    (encode_arm32
     (decode_arm32
        (Int.zero_ext 16
           (encode_arm32 (if Int.lt (Int.repr (id_of_reg rd)) (Int.repr 8) then Int.zero else Int.one)
              (encode_arm32 (int_of_ireg (ireg_of_reg r))
                 (encode_arm32
                    (if Int.lt (Int.repr (id_of_reg rd)) (Int.repr 8)
                     then Int.repr (id_of_reg rd)
                     else Int.sub (Int.repr (id_of_reg rd)) (Int.repr 8)) ADD_R_OP 0 3) 3 4) 7 1)) 7 1)
     (decode_arm32
        (Int.zero_ext 16
           (encode_arm32 (if Int.lt (Int.repr (id_of_reg rd)) (Int.repr 8) then Int.zero else Int.one)
              (encode_arm32 (int_of_ireg (ireg_of_reg r))
                 (encode_arm32
                    (if Int.lt (Int.repr (id_of_reg rd)) (Int.repr 8)
                     then Int.repr (id_of_reg rd)
                     else Int.sub (Int.repr (id_of_reg rd)) (Int.repr 8)) ADD_R_OP 0 3) 3 4) 7 1)) 0 3) 3 1) =
   (Int.repr (id_of_reg rd))
  ). {
    clear.
    unfold decode_arm32, encode_arm32.
    rewrite ! Int_unsigned_bitfield_extract_zero_ext_narrow; try lia.
    erewrite bitfield_insert_unsigned_bitfield_extract_same_outside with
      (pos0 := 7) (width0 := 1) (pos1 := 0) (width1 := 3); change Int.zwordsize with 32; try lia;
    [| reflexivity | reflexivity ].
    erewrite bitfield_insert_unsigned_bitfield_extract_same_outside with
      (pos0 := 3) (width0 := 4) (pos1 := 0) (width1 := 3); change Int.zwordsize with 32; try lia;
    [| reflexivity | reflexivity ].
    erewrite bitfield_insert_unsigned_bitfield_extract_same with
      (pos := 0) (width := 3); change Int.zwordsize with 32; try lia.
    3:{ reflexivity. }
    2:{ instantiate (1 := (if Int.lt (Int.repr (id_of_reg rd)) (Int.repr 8)
           then Int.repr (id_of_reg rd)
           else Int.sub (Int.repr (id_of_reg rd)) (Int.repr 8))).
        destruct rd; repeat int_true_false.
    }
    erewrite bitfield_insert_unsigned_bitfield_extract_same with
      (pos := 7) (width := 1); change Int.zwordsize with 32; try lia.
    3:{ reflexivity. }
    2:{ instantiate (1 := (Int.bitfield_insert (Z.of_nat 7) (Z.of_nat 1) Int.zero
(if Int.lt (Int.repr (id_of_reg rd)) (Int.repr 8) then Int.zero else Int.one))).
        destruct rd; repeat int_true_false.
    }
    destruct rd; repeat int_true_false.
  }
  rewrite Heq.
  rewrite int2ireg_id_of_reg_same.

  clear Heq.
  assert (Heq:
    decode_arm32
     (Int.zero_ext 16
        (encode_arm32 (if Int.lt (Int.repr (id_of_reg rd)) (Int.repr 8) then Int.zero else Int.one)
           (encode_arm32 (int_of_ireg (ireg_of_reg r))
              (encode_arm32
                 (if Int.lt (Int.repr (id_of_reg rd)) (Int.repr 8)
                  then Int.repr (id_of_reg rd)
                  else Int.sub (Int.repr (id_of_reg rd)) (Int.repr 8)) ADD_R_OP 0 3) 3 4) 7 1)) 3 4 =
   (Int.repr (id_of_reg r))
  ). {
    clear.
    unfold decode_arm32, encode_arm32.
    rewrite ! Int_unsigned_bitfield_extract_zero_ext_narrow; try lia.
    erewrite bitfield_insert_unsigned_bitfield_extract_same_outside with
      (pos0 := 7) (width0 := 1) (pos1 := 3) (width1 := 4); change Int.zwordsize with 32; try lia;
    [| reflexivity | reflexivity ].
    erewrite bitfield_insert_unsigned_bitfield_extract_same with
      (pos := 3) (width := 4); change Int.zwordsize with 32; try lia.
    3:{ reflexivity. }
    2:{ instantiate (1 := Int.bitfield_insert 3 4 Int.zero (Int.repr (id_of_reg r))).
        destruct r; repeat int_true_false.
    }
    unfold int_of_ireg, ireg_of_reg, id_of_reg; simpl.
    destruct r; reflexivity.
  }
  rewrite Heq.
  rewrite int2ireg_id_of_reg_same.

  clear Heq.
  assert (Heq:
    decode_arm32
     (Int.zero_ext 16
        (encode_arm32 (if Int.lt (Int.repr (id_of_reg rd)) (Int.repr 8) then Int.zero else Int.one)
           (encode_arm32 (int_of_ireg (ireg_of_reg r))
              (encode_arm32
                 (if Int.lt (Int.repr (id_of_reg rd)) (Int.repr 8)
                  then Int.repr (id_of_reg rd)
                  else Int.sub (Int.repr (id_of_reg rd)) (Int.repr 8)) ADD_R_OP 0 3) 3 4) 7 1)) 8 2 =
   Int.zero
  ). {
    clear.
    unfold decode_arm32, encode_arm32.
    rewrite ! Int_unsigned_bitfield_extract_zero_ext_narrow; try lia.
    erewrite bitfield_insert_unsigned_bitfield_extract_same_outside with
      (pos0 := 7) (width0 := 1) (pos1 := 8) (width1 := 2); change Int.zwordsize with 32; try lia;
    [| reflexivity | reflexivity ].
    erewrite bitfield_insert_unsigned_bitfield_extract_same_outside with
      (pos0 := 3) (width0 := 4) (pos1 := 8) (width1 := 2); change Int.zwordsize with 32; try lia;
    [| reflexivity | reflexivity ].
    erewrite bitfield_insert_unsigned_bitfield_extract_same_outside with
      (pos0 := 0) (width0 := 3) (pos1 := 8) (width1 := 2); change Int.zwordsize with 32; try lia;
    [| reflexivity | reflexivity ].
    unfold ADD_R_OP; reflexivity.
  }
  rewrite Heq.
  rewrite Int.eq_true.
  reflexivity.
Qed.

Lemma lemma_thumb_ldr :
  forall st0 st1 rt rn i arm_blk ofs0
    (Himm_max: 0 <= i <= 4096)
    (Harm_blk : jitted_list st0 = Vptr arm_blk Ptrofs.zero)
    (Hofs0 : ofs0 = Z.of_nat (jitted_len st0 + (jitted_len st0 + 0)))
    (Hupd_load : match upd_jitted_list (encode_arm32 (int_of_ireg rn) LDR_I_OP 0 4) st0 with
            | Some str_st =>
                upd_jitted_list
                  (encode_arm32 (int_of_ireg rt) (Int.repr i) 12 4) str_st
            | None => None
            end = Some st1),
      find_instr (Vptr arm_blk (Ptrofs.repr ofs0)) (jit_mem st1) = Some (Pldr rt rn (SOimm (Int.repr i)), true).
Proof.
  intros.
  
Admitted.