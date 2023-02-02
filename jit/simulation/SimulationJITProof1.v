From Coq Require Import List ZArith Lia.
From compcert Require Import Integers Values AST Memory Memdata.

From bpf.comm Require Import Flag Regs State Monad rBPFMonadOp rBPFMemType rBPFValues LemmaInt.

From bpf.monadicmodel2 Require Import ConcreteState rBPFInterpreter2.
(*
From bpf.isolation Require Import MemInv. *)

From bpf.jit.thumb Require Import JITState ThumbJIT.
From bpf.jit.iBPF Require Import ISemantics.
From bpf.jit.simulation Require Import BitfieldLemma. (*SimulationJIT. *)

From bpf.jit.thumb Require Import ThumbEncode ThumbDecode ThumbInsOp Arm32Reg.
From compcert.arm Require Import AsmSyntax BinSyntax.

Import ListNotations.

Open Scope Z_scope.

Ltac simpl_if :=
  repeat match goal with
  | |- context[if ?COND then ?BT else ?BF] =>
    try (change (if COND then BT else BF) with BT);
    try (change (if COND then BT else BF) with BF)
  end.

Ltac simpl_if_false :=
  repeat match goal with
  | |- context[if ?COND then ?BT else ?BF] =>
    change (if COND then BT else BF) with BF
  end.

Ltac simpl_if_true :=
  repeat match goal with
  | |- context[if ?COND then ?BT else ?BF] =>
    change (if COND then BT else BF) with BF
  end.

Definition movw_encode (i: int) (r: ireg): int * int :=
  let lo_imm8   := Int.unsigned_bitfield_extract 0  8 i in
  let lo_imm3   := Int.unsigned_bitfield_extract 8  3 i in
  let lo_i      := Int.unsigned_bitfield_extract 11 1 i in
  let lo_imm4   := Int.unsigned_bitfield_extract 12 4 i in
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
    (movw_lo, movw_hi).

Lemma movw_op_eq:
  Int.bitfield_insert 0 10
    (Int.bitfield_insert 10 1
      (Int.bitfield_insert 11 5 Int.zero (Int.repr 0x1e)) Int.zero) (Int.repr 0x240) = MOVW_OP.
Proof.
  reflexivity.
Qed.

Lemma decode_encode_movw:
  forall i r movw_lo movw_hi imm16,
    imm16 = Int.unsigned_bitfield_extract 0 16 i -> 
    movw_encode i r = (movw_lo, movw_hi) ->
    decode_thumb2 movw_lo movw_hi = Some (Pmovw r imm16).
Proof.
  unfold movw_encode, decode_thumb2.
  intros.
  assert (Heq: (decode_arm32 movw_lo 11 5) = (Int.repr 30)).
  {
    unfold encode_arm32, decode_arm32 in *.
    inversion H0.
    clear.
    rewrite <- movw_op_eq.
    do 4 (erewrite bitfield_insert_unsigned_bitfield_extract_same_outside with
      (v := Int.repr 30);
    change Int.zwordsize with 32; try simpl; try lia; try reflexivity; [
    intuition |
    intuition | ]).
    erewrite bitfield_insert_unsigned_bitfield_extract_same with
      (v := Int.repr 30) (p := MOVW_OP);
    change Int.zwordsize with 32; try simpl; try lia; try reflexivity.
  }
  rewrite Heq; clear Heq.
  simpl_if.

  assert (Heq: decode_arm32 movw_hi 15 1 = Int.zero). {
    unfold encode_arm32, decode_arm32 in *.
    inversion H0.
    clear.
    do 2 (erewrite bitfield_insert_unsigned_bitfield_extract_same_outside with
      (v := Int.zero);
    change Int.zwordsize with 32; try simpl; try lia; try reflexivity; [
    intuition |
    intuition | ]).
    erewrite unsigned_bitfield_extract_unsigned_bitfield_extract_zero_outside;
    change Int.zwordsize with 32; try simpl; try lia; try reflexivity.
    intuition.
    intuition.
  }
  rewrite Heq; clear Heq.
  simpl_if.

  assert (Heq: decode_arm32 movw_lo 5 4 = (Int.repr 2)). {
    unfold encode_arm32, decode_arm32 in *.
    inversion H0.
    clear.
    do 2 (erewrite bitfield_insert_unsigned_bitfield_extract_same_outside with
      (v := Int.repr 2);
    change Int.zwordsize with 32; try simpl; try lia; try reflexivity; [
    intuition |
    intuition | ]).
    reflexivity.
  }
  rewrite Heq; clear Heq.
  simpl_if.

  assert (Hreg: int2ireg (decode_arm32 movw_hi 8 4) = Some r). {
    unfold encode_arm32, decode_arm32, int2ireg in *.
    inversion H0.
    clear.
    assert (Heq: (Int.unsigned_bitfield_extract (Z.of_nat 8) (Z.of_nat 4)
       (Int.bitfield_insert 12 3
          (Int.bitfield_insert 8 4 (Int.unsigned_bitfield_extract 0 8 i) (int_of_ireg r))
          (Int.unsigned_bitfield_extract 8 3 i))) = (int_of_ireg r)). {
      unfold int_of_ireg.
      destruct r eqn: Hr; simpl;
      try (erewrite bitfield_insert_unsigned_bitfield_extract_same_outside;
      change Int.zwordsize with 32; try simpl; try lia; try reflexivity; [
      intuition |
      intuition |
      erewrite bitfield_insert_unsigned_bitfield_extract_same with
        (p := Int.shl (Int.repr (Z.of_nat (ireg2nat r))) (Int.repr 8));
      change Int.zwordsize with 32; try simpl; try lia; try (rewrite Hr); try reflexivity ]).
    }
    rewrite Heq.
    destruct r; auto with ints.
  }
  rewrite Hreg; clear Hreg.
  simpl_if.

  assert (Heq: decode_arm32 movw_lo 9 1 = Int.one). {
    unfold encode_arm32, decode_arm32 in *.
    inversion H0.
    clear.
    do 2 (erewrite bitfield_insert_unsigned_bitfield_extract_same_outside with
      (v := Int.one);
    change Int.zwordsize with 32; try simpl; try lia; try reflexivity; [
    intuition |
    intuition | ]).
    unfold MOVW_OP.
    reflexivity.
  }
  rewrite Heq; clear Heq.

  assert (Heq: decode_arm32 movw_lo 4 1 = Int.zero). {
    unfold encode_arm32, decode_arm32 in *.
    inversion H0.
    clear.
    do 2 (erewrite bitfield_insert_unsigned_bitfield_extract_same_outside with
      (v := Int.zero);
    change Int.zwordsize with 32; try simpl; try lia; try reflexivity; [
    intuition |
    intuition | ]).
    unfold MOVW_OP.
    reflexivity.
  }
  rewrite Heq; clear Heq.
  simpl_if.

  assert (Heq: (encode_arm32 (decode_arm32 movw_lo 0 4)
       (encode_arm32 (decode_arm32 movw_lo 10 1)
          (encode_arm32 (decode_arm32 movw_hi 12 3) (decode_arm32 movw_hi 0 8) 8 3) 11 1) 12 4) = imm16). {
    unfold encode_arm32, decode_arm32 in *.
    inversion H0.
    subst.
    clear.
    apply Int.same_bits_eq; intros.
    repeat rewrite Int.bits_bitfield_insert;
      change Int.zwordsize with 32 in *; try lia.
    unfold Coqlib.proj_sumbool.
    destruct Coqlib.zle.
    - (**r 12 <= i0 *)
      destruct Coqlib.zlt.
      + (**r i0 < 16 *)
        simpl.
        repeat rewrite Int.bits_unsigned_bitfield_extract;
          change Int.zwordsize with 32 in *; try lia.
        destruct Coqlib.zlt; [| lia].
        destruct Coqlib.zlt; [| lia].
        repeat rewrite Int.bits_bitfield_insert;
          change Int.zwordsize with 32 in *; try lia.
        unfold Coqlib.proj_sumbool.
        destruct Coqlib.zle.
        * (**r 10 <= i0-12 *)
          destruct Coqlib.zlt; [| lia].
          simpl.
          repeat rewrite Int.bits_unsigned_bitfield_extract;
            change Int.zwordsize with 32 in *; try lia.
        * (**r 10 > i0-12 *)
          simpl.
          destruct Coqlib.zle; [| lia].
          destruct Coqlib.zlt; [| lia].
          simpl.
          repeat rewrite Int.bits_unsigned_bitfield_extract;
            change Int.zwordsize with 32 in *; try lia.
          destruct Coqlib.zlt; [| lia].
          rewrite Z.add_simpl_r, Z.sub_simpl_r.
          rewrite Z.add_0_r.
          reflexivity.
      + (**r i0 >= 16 *)
        simpl.
        destruct Coqlib.zle; [| lia].
        destruct Coqlib.zlt; [lia |].
        simpl.
        destruct Coqlib.zle; [| lia].
        destruct Coqlib.zlt; [lia |].
        simpl.
        repeat rewrite Int.bits_unsigned_bitfield_extract;
          change Int.zwordsize with 32 in *; try lia.
        destruct Coqlib.zlt; [lia |].
        destruct Coqlib.zlt; [lia |].
        reflexivity.
    - (**r 12 > i0 *)
      simpl.
      destruct Coqlib.zle; [| simpl].
      + (**r 11 <= i0 *)
        destruct Coqlib.zlt; [| lia].
        simpl.
        repeat rewrite Int.bits_unsigned_bitfield_extract;
          change Int.zwordsize with 32 in *; try lia.
        destruct Coqlib.zlt; [| lia].
        repeat rewrite Int.bits_bitfield_insert;
          change Int.zwordsize with 32 in *; try lia.
        unfold Coqlib.proj_sumbool.
        destruct Coqlib.zle; try lia.
        destruct Coqlib.zlt; simpl; try lia.
        repeat rewrite Int.bits_unsigned_bitfield_extract;
          change Int.zwordsize with 32 in *; try lia.
          destruct Coqlib.zlt; simpl; try lia.
          destruct Coqlib.zlt; [| lia].
          rewrite Z.add_simpl_r, Z.sub_simpl_r.
          rewrite Z.add_0_r.
          reflexivity.
      + (**r 11 > i0 *)
        destruct Coqlib.zle; simpl; try lia.
        * destruct Coqlib.zlt; simpl; try lia.
          repeat rewrite Int.bits_unsigned_bitfield_extract;
            change Int.zwordsize with 32 in *; try lia.
          destruct Coqlib.zlt; simpl; try lia.
          repeat rewrite Int.bits_bitfield_insert;
            change Int.zwordsize with 32 in *; try lia.
          unfold Coqlib.proj_sumbool.
          destruct Coqlib.zle; try lia.
          destruct Coqlib.zlt; simpl; try lia.
          repeat rewrite Int.bits_unsigned_bitfield_extract;
            change Int.zwordsize with 32 in *; try lia.
          destruct Coqlib.zlt; simpl; try lia.
          destruct Coqlib.zlt; simpl; try lia.
          rewrite Z.add_simpl_r, Z.sub_simpl_r.
          rewrite Z.add_0_r.
          reflexivity.
        * repeat rewrite Int.bits_unsigned_bitfield_extract;
            change Int.zwordsize with 32 in *; try lia.
          destruct Coqlib.zlt; simpl; try lia.
          destruct Coqlib.zlt; simpl; try lia.
          repeat rewrite Int.bits_bitfield_insert;
            change Int.zwordsize with 32 in *; try lia.
          unfold Coqlib.proj_sumbool.
          destruct Coqlib.zle; try lia.
          destruct Coqlib.zlt; simpl; try lia.
          repeat rewrite Int.bits_unsigned_bitfield_extract;
            change Int.zwordsize with 32 in *; try lia.
          destruct Coqlib.zle; simpl; try lia.
          destruct Coqlib.zlt; simpl; try lia.
          repeat rewrite Z.add_0_r.
          reflexivity.
  }
  rewrite Heq; clear Heq.

  subst.
  assert (Hrange:= unsigned_bitfield_extract_range_low).
  specialize (Hrange i (Int.unsigned_bitfield_extract 0 16 i) 0 16).
  change Int.zwordsize with 32 in *.
  assert (Ht: 0 <= 0 /\ 0 < 16 /\ 0 + 16 <= 32) by lia.
  specialize (Hrange Ht); clear Ht.
  assert (Ht: Int.unsigned_bitfield_extract 0 16 i =
              Int.unsigned_bitfield_extract 0 16 i) by reflexivity.
  specialize (Hrange Ht); clear Ht.
  destruct Hrange as (Hrange_low & Hrange_high).
  unfold Int.cmpu.
  destruct negb eqn: Hle; simpl.
  - destruct (negb (Int.ltu (Int.repr 65535) _)) eqn: Hle'; simpl.
    * reflexivity.
    * rewrite Bool.negb_false_iff in Hle'.
      apply Clt_Zlt_unsigned in Hle'.
      change (Int.unsigned (Int.repr 65535)) with (two_p 16 - 1) in Hle'.
      lia.
  - rewrite Bool.negb_false_iff in Hle.
    apply Clt_Zlt_unsigned in Hle.
    change (Int.unsigned Int.zero) with 0 in Hle.
    lia.
Qed.


(** The most imporant property is:
  for a set of alu32 instructions, bpf_interpreter \sim ibpf_interpeter *)


Section SimulationJITProof1.
  Context {flag_blk regs_blk st_blk: block}.

  Theorem bpf_interpreter_sim_ibpf_interpreter:
    forall f st_i0 st_i1 st_j0 st_j res
      (Hbefore: Rel flag_blk regs_blk st_blk st_i0 st_j0)
      (Hjit: jit_alu32 st_j0 = Some st_j)
      (Hst: bpf_interpreter f st_i0 = Some (res, st_i1)),
        exists st_j1,
          ibpf_interpreter f st_j = Some (res, st_j1) /\
          Rel flag_blk regs_blk st_blk st_i1 st_j1.
  Proof.
    unfold jit_alu32, bpf_interpreter, ibpf_interpreter.
    unfold bindM, returnM; intros.

  Admitted.

End SimulationJITProof1.
Close Scope Z_scope.