(**************************************************************************)
(*  This file is part of CertrBPF,                                        *)
(*  a formally verified rBPF verifier + interpreter + JIT in Coq.         *)
(*                                                                        *)
(*  Copyright (C) 2022 Inria                                              *)
(*                                                                        *)
(*  This program is free software; you can redistribute it and/or modify  *)
(*  it under the terms of the GNU General Public License as published by  *)
(*  the Free Software Foundation; either version 2 of the License, or     *)
(*  (at your option) any later version.                                   *)
(*                                                                        *)
(*  This program is distributed in the hope that it will be useful,       *)
(*  but WITHOUT ANY WARRANTY; without even the implied warranty of        *)
(*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *)
(*  GNU General Public License for more details.                          *)
(*                                                                        *)
(**************************************************************************)

From compcert Require Import Integers Values Memory AST.
From bpf.comm Require Import State Monad rBPFMonadOp.
From bpf.comm Require Import MemRegion rBPFMemType rBPFAST rBPFValues.
From bpf.model Require Import Syntax Semantics.
From bpf.isolation Require Import CommonISOLib MemInv CheckMem.
From bpf.monadicmodel2 Require Import ConcreteState rBPFInterpreter2.
From bpf.equivalence Require Import Relation3.

From Coq Require Import ZArith List Lia.
Import ListNotations.

Open Scope Z_scope.

(** * CheckMem2 *)

(**

This module, similiarly to `isolation/CheckMem.v`, is used to say check_mem is read-only.

following the diagram:

rBPFInterpreter.check_mem ----------(\sim)---------- rBPFInterpreter2.check_mem

        +                                                     +
        +                                                     +
        +                                                     +
        +                                                     +
        (\sim)                                                (\sim)
        +                                                     +
        +                                                     +
        +                                                     +
        +                                                     +

CheckMem.check_memP       ----------(\sim)---------- CheckMem2.check_memP


We finally translate the simulation bewtween monadic functions into the simulation between two CheckMem* functions (non-monadic)

*)

(** * Memory Invariant *)

(*
Similarly, we give a memory invariant definition of Concrete State, this invariant should be inferred by the simulation relation and the memory invariant of the abstract state.

*)


Definition memory_inv2 (st: ConcreteState.state): Prop :=
  (1 <= ConcreteState.mrs_num st)%nat /\
  List.length (ConcreteState.bpf_mrs st) = ConcreteState.mrs_num st /\
  (exists start_blk,
    disjoint_blocks start_blk (ConcreteState.bpf_mrs st)) /\
  inv_memory_regions (ConcreteState.bpf_m st) (ConcreteState.bpf_mrs st).

Lemma memory_inv_memory_inv2:
  forall st0 st1 flag_blk regs_blk st_blk
    (Hrel: Rel flag_blk regs_blk st_blk st0 st1)
    (Hmem_inv: memory_inv st0),
      memory_inv2 st1.
Proof.
  unfold memory_inv, memory_inv2.
  intros.
  set (Hrel' := Hrel).
  destruct Hrel'.
  rewrite mmrs_num, mbpf_mrs in Hmem_inv.
  clear - Hrel Hmem_inv munchange minvalid.
  destruct Hmem_inv as (Hmrs_num & Hmrs_num_eq & Hdisjoint & Hmem_inv).
  do 3 (split; [assumption |]).
  clear -Hrel munchange Hmem_inv minvalid.

  induction (bpf_mrs st1).

  - simpl in *.
    constructor.

  - destruct minvalid as (Hflag_blk & Hregs_blk & Hst_blk & Hblk_neq & minvalid).
    simpl in *.
    destruct Hmem_inv as (Ha & Hmem_inv).
    specialize (IHm Hmem_inv).
    split; [| assumption].
    clear Hmem_inv IHm.
    unfold inv_memory_region in *.
    destruct Ha as (b & Hblk & Hvalid_blk & His_byte & (base & len & Hstart & Hsize & Hperm & Hrange_perm)).

    assert (Hb_neq: b <> flag_blk /\ b <> regs_blk /\ b <> st_blk). {
      split.
      - intro Hf; subst b.
        apply Hflag_blk.
        assumption.
      - split.
        + intro Hf; subst b.
          apply Hregs_blk.
          assumption.
        + intro Hf; subst b.
          apply Hst_blk.
          assumption.
    }

    exists b.
    split; [assumption|].
    split.
    + eapply Mem.valid_block_unchanged_on; eauto.
    + split.
      * unfold is_byte_block in *.
        intros o Hp.

        eapply Mem.perm_unchanged_on_2 in Hp; eauto.

        specialize (His_byte o Hp).
        unfold is_byte_memval in *.

        erewrite Mem.unchanged_on_contents; eauto.
      * exists base, len.
        do 3 (split; [assumption|]).

        unfold Mem.range_perm in *.
        intros ofs Hp.
        specialize (Hrange_perm ofs Hp).

        eapply Mem.perm_unchanged_on; eauto.
Qed.




(** * Equivalence between CheckMem2 and rBPFInterpreter2.check_mem *)

Lemma is_well_chunk_boolM_P2:
  forall chunk st,
    rBPFInterpreter2.is_well_chunk_bool chunk st = Some (is_well_chunk_boolP chunk, st).
Proof.
  unfold rBPFInterpreter2.is_well_chunk_bool, is_well_chunk_boolP.
  unfold returnM.
  intros.
  destruct chunk; reflexivity.
Qed.

Lemma check_mem_aux2M_P:
  forall mr perm addr chunk st,
    rBPFInterpreter2.check_mem_aux2 mr perm addr chunk st = Some (check_mem_aux2P mr perm addr chunk, st).
Proof.
  unfold check_mem_aux2, check_mem_aux2P.
  unfold get_start_addr, get_block_size, get_sub, get_add, get_block_perm.
  unfold_monad.
  intros.
  destruct_if; reflexivity.
Qed.

Fixpoint check_mem_auxP2 (st: ConcreteState.state) (num: nat) (perm: permission) (chunk: memory_chunk) (addr: val) (mrs: MyMemRegionsType) {struct num}: val :=
  match num with
  | O => Vnullptr
  | S n =>
    let cur_mr    := MyMemRegionsIndexnat mrs n in
    let check_mem := check_mem_aux2P cur_mr perm addr chunk in
      match cmp_ptr32_null (ConcreteState.bpf_m st) check_mem with
      | Some res =>
        if res then
          check_mem_auxP2 st n perm chunk addr mrs
        else
          check_mem
      | None => check_mem
      end
  end.


Lemma mem_inv_check_mem_aux2P_valid_pointer:
  forall mr p c v st0 st v' flag_blk regs_blk st_blk
    (Hrel : Rel flag_blk regs_blk st_blk st0 st)
    (Hmem : memory_inv st0)
    (Hin_mem_regions: In mr (bpf_mrs st))
    (Hcheck_mem_aux2P: check_mem_aux2P mr p (Vint c) v = v'),
      (exists b ofs, v' = Vptr b ofs /\
        (Mem.valid_pointer (bpf_m st) b (Ptrofs.unsigned ofs)
        || Mem.valid_pointer (bpf_m st) b (Ptrofs.unsigned ofs - 1))%bool = true /\
        Mem.valid_block (bpf_m st) b)
        \/ v' = Vnullptr.
Proof.
  intros.
  eapply memory_inv_memory_inv2 in Hmem; eauto.

  unfold memory_inv in Hmem.
  destruct Hmem as (Hlen_low & Hlen & Hdisjoint & Hinv_mem).

  eapply In_inv_memory_regions in Hinv_mem; eauto.
  unfold inv_memory_region in Hinv_mem.
  destruct Hinv_mem as (b & Hptr & Hvalid & His_byte & (start & size & Hstart & Hsize & Hperm & Hrange_perm)).
  unfold Mem.range_perm in Hrange_perm.

  unfold check_mem_aux2P in Hcheck_mem_aux2P.
  unfold is_well_chunk_boolP, compu_lt_32, memory_chunk_to_valu32, compu_le_32, memory_chunk_to_valu32_upbound, comp_eq_32, Vzero, val32_modu, memory_chunk_to_valu32, perm_ge, Vnullptr in Hcheck_mem_aux2P.
  rewrite Hptr, Hstart, Hsize in Hcheck_mem_aux2P.
  revert Hcheck_mem_aux2P.

  assert (Heq: Ptrofs.unsigned (Ptrofs.repr (Int.unsigned (Int.sub c start))) = Int.unsigned (Int.sub c start)). {
    rewrite Ptrofs.unsigned_repr; [reflexivity|].
    change Ptrofs.max_unsigned with Int.max_unsigned.
    apply Int.unsigned_range_2.
  }
  assert (Hle: 0 <= Int.unsigned (Int.sub c start)). {
    assert (Hle1: 0 <= Int.unsigned (Int.sub c start) <= Int.max_unsigned).
    apply Int.unsigned_range_2.
    lia.
  }
  destruct v; simpl.
  all: try (intro Hcheck_mem_aux2P; inversion Hcheck_mem_aux2P; right; reflexivity).
  all: destruct_ifN Hcond; try (unfold Ptrofs.of_int; rewrite Ptrofs.add_zero_l; intro Hcheck_mem_aux2P; try inversion Hcheck_mem_aux2P).
  all: try (intro H; inversion H; right; reflexivity).
  all: left;
    eexists; eexists; split; [ reflexivity | ];
    split; [|assumption];
    rewrite Bool.orb_true_iff; left;
    rewrite Mem.valid_pointer_nonempty_perm;
    apply Mem.perm_implies with (p1 := MemRegion.block_perm mr); [ | constructor];
    apply Hrange_perm;
    repeat rewrite Bool.andb_true_iff in Hcond.
    all: rewrite Heq; clear Heq;
    split; [ assumption|];
    destruct Hcond as ((Hcond & Hcond0 & _) & _);
    unfold Int.add in Hcond;
    apply Clt_Zlt_iff in Hcond;
    apply Cle_Zle_iff in Hcond0.
Ltac change_const :=
  let I := fresh "I" in
    repeat match goal with
    | H0: Int.unsigned (Int.sub _ _) <= Int.unsigned (Int.repr ?X) |- _ =>
      change (Int.unsigned (Int.repr X)) with X in H0
    | H1: Int.unsigned
            (Int.repr
               (Int.unsigned (Int.sub ?X ?Z) + Int.unsigned (Int.repr ?Y))) <
          Int.unsigned ?W |- _ =>
      change (Int.unsigned (Int.repr Y)) with Y in H1;
      assert (I: Int.unsigned (Int.repr (Int.unsigned (Int.sub X Z) + Y)) = Int.unsigned (Int.sub X Z) + Y); [
      rewrite Int.unsigned_repr; [reflexivity | change Int.max_unsigned with 4294967295; lia] |
      rewrite I in H1; lia
    ]
    end.
    all: change_const.
Qed.

Lemma cmp_ptr32_null_check_mem_aux2P_Some:
  forall n perm addr chunk st0 st flag_blk regs_blk st_blk
    (Hrel : Rel flag_blk regs_blk st_blk st0 st)
    (Hmem_inv : memory_inv st0)
    (Hperm: perm_order perm Readable),
      exists res, cmp_ptr32_null (bpf_m st)
        (check_mem_aux2P (MyMemRegionsIndexnat (bpf_mrs st) n) perm 
           (Vint addr) chunk) = Some res.
Proof.
  intros.
  remember (MyMemRegionsIndexnat _ _) as mr.
  unfold MyMemRegionsIndexnat, Memory_regions.index_nat in Heqmr.
  destruct (nth_error _ _) eqn: Hnth_error.
  - subst m.
    apply List.nth_error_In in Hnth_error.
    eapply mem_inv_check_mem_aux2P_valid_pointer with (p:= perm) (c:= addr) (v:= chunk) in Hnth_error; eauto.
    destruct Hnth_error as [ Hnth_0 | Hnth_1].
    + destruct Hnth_0 as (b & ofs & Hcheck_mem_aux2P & Hvalid & _).
      rewrite Hcheck_mem_aux2P.
      unfold cmp_ptr32_null; simpl.
      rewrite Hvalid.
      exists false.
      rewrite Int.eq_true.
      rewrite Bool.andb_true_l.
      reflexivity.
    + unfold cmp_ptr32_null; simpl.
      rewrite Hnth_1.
      unfold Vnullptr; simpl.
      exists true.
      rewrite Int.eq_true.
      reflexivity.
  - subst.
    unfold check_mem_aux2P, default_memory_region.
    unfold start_addr, block_size, block_perm, block_ptr.
    assert (Hnullptr: Vint Int.zero = Vnullptr). {
      unfold Vnullptr; reflexivity.
    }
    rewrite <- Hnullptr; clear Hnullptr.
    assert (Hperm_ge: perm_ge Nonempty perm = false). {
      unfold perm_ge.
      unfold Mem.perm_order_dec.
      destruct perm; try reflexivity.
      inversion Hperm.
    }
    rewrite Hperm_ge; clear Hperm_ge.
    rewrite Bool.andb_false_r.
    destruct_if; try reflexivity.
    all: unfold cmp_ptr32_null; simpl;
    exists true;
    rewrite Int.eq_true;
    reflexivity.
Qed.


Lemma check_mem_auxM_P:
  forall n perm chunk addr st0 st flag_blk regs_blk st_blk
    (Hrel : Rel flag_blk regs_blk st_blk st0 st)
    (Hmem_inv : memory_inv st0)
    (Hlt: (n <= mrs_num st)%nat)
    (Hperm: perm_order perm Readable),
    rBPFInterpreter2.check_mem_aux n perm chunk (Vint addr) (bpf_mrs st) st = Some (check_mem_auxP2 st n perm chunk (Vint addr) (bpf_mrs st), st).
Proof.
  unfold check_mem_aux, rBPFMonadOp2.get_mem_region, rBPFMonadOp2.eval_mrs_regions, check_mem_auxP2.
  unfold_monad.
  intros.
  unfold rBPFMonadOp2.cmp_ptr32_nullM, eval_mem.
  induction n.
  reflexivity.
  assert (Hlt': (n < mrs_num st)%nat) by lia.
  assert (Hlt'': (n <= mrs_num st)%nat) by lia.
  specialize (IHn Hlt''); clear Hlt''.
  rewrite <- Nat.ltb_lt in Hlt'.
  rewrite Hlt'.
  rewrite Nat.ltb_lt in Hlt'.

  eapply memory_inv_memory_inv2 in Hmem_inv as Hmem_inv2; eauto.

  set (Hmem_inv2' := Hmem_inv2).
  unfold memory_inv2 in Hmem_inv2'.
  destruct Hmem_inv2' as (_ & Hlen & _ & _).
  rewrite <- Hlen in Hlt'.
  apply nth_error_nth' with (d:= default_memory_region) in Hlt'.
  rewrite Hlt'.
  rewrite check_mem_aux2M_P.

  assert (Hcmp := cmp_ptr32_null_check_mem_aux2P_Some).
  specialize (Hcmp n perm addr chunk st0 st _ _ _ Hrel Hmem_inv Hperm).

  destruct Hcmp as (res & Hcmp).
  assert (Heq: MyMemRegionsIndexnat (bpf_mrs st) n = nth n (bpf_mrs st) default_memory_region). {
    unfold MyMemRegionsIndexnat, Memory_regions.index_nat.
    rewrite Hlt'.
    reflexivity.
  }
  rewrite <- Heq; clear Heq.
  rewrite Hcmp.
  destruct res; [ | reflexivity].
  unfold cmp_ptr32_nullM, State.eval_mem in IHn.
  rewrite IHn.
  reflexivity.
Qed.

Definition check_memP2 (perm: permission) (chunk: memory_chunk) (addr: val) (st: ConcreteState.state): val :=
  let well_chunk := is_well_chunk_boolP chunk in
    if well_chunk then
      let mem_reg_num := eval_mem_num st in
      let mrs         := ConcreteState.eval_mem_regions st in
      let check_mem  := check_mem_auxP2 st mem_reg_num perm chunk addr mrs in
        match cmp_ptr32_null (ConcreteState.bpf_m st) check_mem with
        | Some res =>
          if res then
            Vnullptr
          else
            check_mem
        | None => Vnullptr
        end
      else
        Vnullptr.

Lemma mem_inv_check_mem_auxP_valid_pointer:
  forall st0 st perm chunk addr v flag_blk regs_blk st_blk
    (Hrel : Rel flag_blk regs_blk st_blk st0 st)
    (Hmem : memory_inv st0)
    (Hperm: perm_order perm Readable)
    (Hcheck_mem_auxP: check_mem_auxP2 st (mrs_num st) perm chunk (Vint addr) (bpf_mrs st) = v),
      (exists b ofs,
        v = Vptr b ofs /\
        (Mem.valid_pointer (bpf_m st) b (Ptrofs.unsigned ofs)
          || Mem.valid_pointer (bpf_m st) b (Ptrofs.unsigned ofs - 1) = true)%bool /\
        Mem.valid_block (bpf_m st) b)
        \/ v = Vnullptr.
Proof.
  intros.

  eapply memory_inv_memory_inv2 in Hmem as Hmem2; eauto.

  induction (mrs_num st).
  simpl in Hcheck_mem_auxP.
  subst. right; reflexivity.

  simpl in Hcheck_mem_auxP.

  destruct (cmp_ptr32_null _ _) eqn: Hcmp.
  - destruct b eqn: Hb.
    + apply IHn.
      assumption.
    + unfold cmp_ptr32_null in Hcmp.
      unfold Val.cmpu_bool, Vnullptr in Hcmp; simpl in Hcmp.
      rewrite Hcheck_mem_auxP in Hcmp.
      destruct v eqn: Hv_eq; try inversion Hcmp.
      * eapply mem_inv_check_mem_aux2P_valid_pointer in Hcheck_mem_auxP; eauto.
        unfold MyMemRegionsIndexnat, Memory_regions.index_nat in *.
        assert (Hmem' := Hmem).
        destruct Hmem' as (Hlen & Hdisjoint & Hmem').
        destruct nth_error eqn: Hnth; unfold check_mem_aux2P in Hcheck_mem_auxP.
        ** apply nth_error_In in Hnth.
           assumption.
        ** exfalso; unfold default_memory_region, start_addr, block_size, block_perm, block_ptr in Hcheck_mem_auxP.
           assert (Hperm_ge: perm_ge Nonempty perm = false). {
             unfold perm_ge; destruct perm; try constructor.
             inversion Hperm.
           }
           rewrite Hperm_ge in Hcheck_mem_auxP; clear Hperm_ge.
           rewrite Bool.andb_false_r in Hcheck_mem_auxP.
           destruct is_well_chunk_boolP; change Vnullptr with (Vint Int.zero) in *;inversion Hcheck_mem_auxP; subst; rewrite Int.eq_true in H0; inversion H0.
      * left.
        exists b0, i.
        split; [reflexivity | ].
        split.
        rewrite Int.eq_true in H0.
        rewrite Bool.andb_true_l in H0.
        destruct (Mem.valid_pointer _ _ _ || Mem.valid_pointer _ _ _)%bool eqn: Hvalid; [reflexivity| inversion H0].

        clear - Hcmp.
        change (Int.eq Int.zero Int.zero) with true in Hcmp.
        unfold andb in Hcmp.
        match goal with
        | H: (if ?X then _ else _) = _ |- _ =>
          destruct X eqn: HX; [| inversion H]
        end.
        rewrite Bool.orb_true_iff in HX.
        destruct HX as [HX | HX];
          rewrite Mem.valid_pointer_valid_access in HX;
          apply Mem.valid_access_valid_block in HX;
          assumption.
    - unfold cmp_ptr32_null, Val.cmpu_bool, Vnullptr in Hcmp; simpl in Hcmp.
      rewrite Hcheck_mem_auxP in Hcmp.
      assert (Hcheck_mem_auxP' := Hcheck_mem_auxP).
      assert (Hmem2' := Hmem2).
      destruct Hmem2' as (_ & Hlen & Hdisjoint & Hmem2').
      unfold MyMemRegionsIndexnat, Memory_regions.index_nat in Hcheck_mem_auxP, Hcheck_mem_auxP'.
      unfold check_mem_aux2P in Hcheck_mem_auxP.
      destruct v; try inversion Hcmp;
      change Vnullptr with (Vint Int.zero) in *.

      all: match goal with
           | H: (if ?X then _ else _) = _ |- _ =>
              destruct X; [| inversion H]
           end.
      5:{ inversion H0. }
      5:{
        destruct nth_error eqn: Hnth; [
        apply nth_error_In in Hnth;
        eapply In_inv_memory_regions in Hmem2'; eauto; unfold inv_memory_region in Hmem2';
        destruct Hmem2' as (b' & Hptr & Hvalid & Hbyte & (start & len & Hstart & Hsize & Hperm_order & Hrange));
        rewrite Hptr, Hstart in Hcheck_mem_auxP |
        unfold default_memory_region, start_addr, block_size, block_perm, block_ptr in Hcheck_mem_auxP;
        change Vnullptr with (Vint Int.zero) in Hcheck_mem_auxP]. 2:{
          assert (Hperm_ge: perm_ge Nonempty perm = false). {
            unfold perm_ge; destruct perm; try constructor.
            inversion Hperm.
          }
          rewrite Hperm_ge in Hcheck_mem_auxP; clear Hperm_ge.
          rewrite Bool.andb_false_r in Hcheck_mem_auxP.
          inversion Hcheck_mem_auxP.
        }
        eapply mem_inv_check_mem_aux2P_valid_pointer in Hcheck_mem_auxP'; eauto.
      }
      all: destruct nth_error eqn: Hnth; [apply nth_error_In in Hnth;
      eapply In_inv_memory_regions in Hmem2'; eauto; unfold inv_memory_region in Hmem2';
      destruct Hmem2' as (b' & Hptr & Hvalid & Hbyte & (start & len & Hstart & Hsize & Hperm_order & Hrange));
      rewrite Hptr, Hstart in Hcheck_mem_auxP; inversion Hcheck_mem_auxP |
      unfold default_memory_region, start_addr, block_size, block_perm, block_ptr in Hcheck_mem_auxP;
      change Vnullptr with (Vint Int.zero) in Hcheck_mem_auxP;
      inversion Hcheck_mem_auxP
      ].
Qed.

Lemma check_memM_P:
  forall perm chunk addr st0 st flag_blk regs_blk st_blk
    (Hrel : Rel flag_blk regs_blk st_blk st0 st)
    (Hmem_inv : memory_inv st0)
    (Hperm: perm_order perm Readable),
    check_mem perm chunk (Vint addr) st = Some (check_memP2 perm chunk (Vint addr) st, st).
Proof.
  unfold check_mem, rBPFMonadOp2.eval_mrs_num, rBPFMonadOp2.eval_mrs_regions, check_memP2, rBPFMonadOp2.cmp_ptr32_nullM, eval_mem, eval_mem_regions, eval_mem_num.
  unfold_monad.
  intros.
  rewrite is_well_chunk_boolM_P2.
  destruct is_well_chunk_boolP; try reflexivity.
  rewrite check_mem_auxM_P with (st0 := st0) (flag_blk := flag_blk) (regs_blk := regs_blk) (st_blk := st_blk); auto.
  remember (check_mem_auxP2 st (mrs_num st) perm chunk (Vint addr) (bpf_mrs st)) as res.
  symmetry in Heqres.
  eapply mem_inv_check_mem_auxP_valid_pointer in Heqres; eauto.
  destruct Heqres as [(b & ofs & Hptr & Hvalid) | Hnull]; subst; unfold cmp_ptr32_null, Val.cmpu_bool; change Vnullptr with (Vint Int.zero) in *; simpl; rewrite Int.eq_true.
  - destruct Hvalid as (Hvalid & _).
    rewrite Hvalid; simpl; reflexivity.
  - reflexivity.
Qed.

(** * Equivalence between CheckMem.check_memP and check_memP2 *)

Lemma cmp_ptr32_nullM_ref:
  forall st0 st1 v b flag_blk regs_blk st_blk
  (Hptr: exists b ofs, v = Vptr b ofs /\
            b <> flag_blk /\ b <> regs_blk /\ b <> st_blk /\
            Mem.valid_block (State.eval_mem st0) b)
  (Hbefore: Rel flag_blk regs_blk st_blk st0 st1),
    rBPFMonadOp.cmp_ptr32_nullM v st0 = Some (b, st0) <->
    rBPFMonadOp2.cmp_ptr32_nullM v st1 = Some (b, st1).
Proof.
  intros.
  unfold rBPFMonadOp2.cmp_ptr32_nullM, cmp_ptr32_nullM.
  destruct Hptr as (b0 & ofs & Hptr & Hflag_neq & Hregs_neq & Hst_neq & Hvalid).
  subst v.

  assert (Heval_mem_equiv3:
    forall st0 st1 flag_blk regs_blk st_blk
    (Hbefore: Rel flag_blk regs_blk st_blk st0 st1),
      Mem.unchanged_on (fun (b : block) (_ : Z) => b <> flag_blk /\ b <> regs_blk /\ b <> st_blk)
      (State.eval_mem st0) (ConcreteState.eval_mem st1)). {
    intros.
    unfold State.eval_mem, ConcreteState.eval_mem.
    destruct Hbefore0.
    assumption.
  }

  apply Heval_mem_equiv3 in Hbefore as Hrel.
  unfold rBPFValues.cmp_ptr32_null.
  unfold Val.cmpu_bool; simpl.
  change (Int.eq Int.zero Int.zero) with true.
  unfold andb.

  assert (Hvalid_ptr: forall ofs,
    Mem.valid_pointer (State.eval_mem st0) b0 ofs =
    Mem.valid_pointer (ConcreteState.eval_mem st1) b0 ofs). {
    intros.
    destruct Mem.valid_pointer eqn: Hvalid_ptr.
    - apply Mem.valid_pointer_nonempty_perm in Hvalid_ptr.
      symmetry.
      apply Mem.valid_pointer_nonempty_perm.
      eapply Mem.perm_unchanged_on; eauto.
      simpl. intuition.
    - unfold Mem.valid_pointer in *.
      apply proj_sumbool_false in Hvalid_ptr.
      symmetry.
      unfold Coqlib.proj_sumbool.
      destruct Mem.perm_dec eqn: Hf; [| reflexivity].
      exfalso; apply Hvalid_ptr.
      eapply Mem.perm_unchanged_on_2; eauto.
      simpl. intuition.
  }

  specialize(Hvalid_ptr (Ptrofs.unsigned ofs)) as Hvalid_ptr0.
  specialize(Hvalid_ptr (Ptrofs.unsigned ofs - 1)) as Hvalid_ptr1.
  rewrite Hvalid_ptr0, Hvalid_ptr1.
  match goal with
  | |- context[if (?X)%bool then _ else _] =>
    destruct X eqn: HX
  end.
  - destruct b.
    + split; intro Hf;
      inversion Hf.
    + split; intro Ht; reflexivity.
  - destruct b; split; intro Hf;
      inversion Hf.
Qed.

Lemma cmp_ptr32_null_check_mem_aux2P_Some2:
  forall n perm addr chunk st0 st1 flag_blk regs_blk st_blk
    (Hrel : Rel flag_blk regs_blk st_blk st0 st1)
    (Hmem_inv : memory_inv st0)
    (Hperm: perm_order perm Readable),
      exists res,
        cmp_ptr32_null (State.bpf_m st0)
          (check_mem_aux2P (MyMemRegionsIndexnat (State.bpf_mrs st0) n) perm 
           (Vint addr) chunk) = Some res /\
        cmp_ptr32_null (bpf_m st1)
          (check_mem_aux2P (MyMemRegionsIndexnat (bpf_mrs st1) n) perm 
           (Vint addr) chunk) = Some res.
Proof.
  intros.
  unfold MyMemRegionsIndexnat, Memory_regions.index_nat.

  assert (Heq: State.bpf_mrs st0 = bpf_mrs st1). {
    destruct Hrel.
    assumption.
  }
  rewrite Heq.

  destruct (nth_error _ _) eqn: Hnth_error.
  - apply List.nth_error_In in Hnth_error.
    assert (Hin:= Hnth_error).
    eapply mem_inv_check_mem_aux2P_valid_pointer with (p:= perm) (c:= addr) (v:= chunk) in Hnth_error; eauto.
    destruct Hnth_error as [ Hnth_0 | Hnth_1].
    + destruct Hnth_0 as (b & ofs & Hcheck_mem_aux2P & Hvalid & Hvalid_block).
      rewrite Hcheck_mem_aux2P.
      unfold cmp_ptr32_null; simpl.
      rewrite Hvalid.

      (**r for st0, same valid_pointer *)
      assert (Hvalid0: (Mem.valid_pointer (State.bpf_m st0) b (Ptrofs.unsigned ofs)
          || Mem.valid_pointer (State.bpf_m st0) b (Ptrofs.unsigned ofs - 1))%bool =
         true). {
        apply Bool.orb_prop in Hvalid.

        assert (Hin': In m (State.bpf_mrs st0)). {
          destruct Hrel.
          rewrite mbpf_mrs.
          assumption.
        }
        eapply CheckMem.mem_inv_check_mem_aux2P_valid_pointer in Hcheck_mem_aux2P; eauto.

        destruct Hcheck_mem_aux2P as [Hcheck_mem_aux2P | Hcheck_mem_aux2P];
          [| inversion Hcheck_mem_aux2P].
        destruct Hcheck_mem_aux2P as (b0 & ofs0 & Hptr & Hvalid_ptr & _).
        inversion Hptr.
        subst b0 ofs0.
        assumption.
      }



      exists false.
      rewrite Int.eq_true.
      rewrite Bool.andb_true_l.
      intuition.
      rewrite Hvalid0.
      reflexivity.
    + unfold cmp_ptr32_null; simpl.
      rewrite Hnth_1.
      unfold Vnullptr; simpl.
      exists true.
      rewrite Int.eq_true.
      intuition.
  - subst.
    unfold check_mem_aux2P, default_memory_region.
    unfold start_addr, block_size, block_perm, block_ptr.
    assert (Hnullptr: Vint Int.zero = Vnullptr). {
      unfold Vnullptr; reflexivity.
    }
    rewrite <- Hnullptr; clear Hnullptr.
    assert (Hperm_ge: perm_ge Nonempty perm = false). {
      unfold perm_ge.
      unfold Mem.perm_order_dec.
      destruct perm; try reflexivity.
      inversion Hperm.
    }
    rewrite Hperm_ge; clear Hperm_ge.
    rewrite Bool.andb_false_r.
    destruct_if; try reflexivity.
    all: unfold cmp_ptr32_null; simpl;
    exists true;
    rewrite Int.eq_true;
    intuition.
Qed.


Lemma check_mem_auxP_check_mem_auxP2:
  forall st0 st1 flag_blk regs_blk st_blk n perm chunk addr
    (Hrel : Rel flag_blk regs_blk st_blk st0 st1)
    (Hmem_inv : memory_inv st0)
    (Hperm: perm_order perm Readable),
    CheckMem.check_mem_auxP st0 n perm chunk (Vint addr) (State.bpf_mrs st0) =
    check_mem_auxP2 st1 n perm chunk (Vint addr) (bpf_mrs st1).
Proof.
  intros.
  induction n.

  (**r n = 0*)
  simpl.
  reflexivity.

  (**r n = k -> n = k+1 *)
  simpl.
  rewrite IHn.

  assert (Hcmp := cmp_ptr32_null_check_mem_aux2P_Some2).
  specialize (Hcmp n perm addr chunk st0 st1 _ _ _ Hrel Hmem_inv Hperm).
  destruct Hcmp as (res & Hcmp0 & Hcmp1).
  rewrite Hcmp0, Hcmp1.
  destruct Hrel.
  rewrite mbpf_mrs.
  reflexivity.
Qed.

Lemma cmp_ptr32_null_check_mem_auxP_Some:
  forall st0 st1 perm chunk addr flag_blk regs_blk st_blk
    (Hrel : Rel flag_blk regs_blk st_blk st0 st1)
    (Hmem_inv : memory_inv st0)
    (Hperm: perm_order perm Readable),
    exists res,
    cmp_ptr32_null (State.bpf_m st0)
      (check_mem_auxP st0 (State.mrs_num st0) perm chunk 
         (Vint addr) (State.bpf_mrs st0)) = Some res /\
    cmp_ptr32_null (bpf_m st1)
      (check_mem_auxP st0 (State.mrs_num st0) perm chunk 
         (Vint addr) (State.bpf_mrs st0)) = Some res.
Proof.
  intros.
  unfold cmp_ptr32_null.

  unfold Val.cmpu_bool, Vnullptr; simpl.
  change (Int.eq Int.zero Int.zero) with true; unfold andb.

  eapply CheckMem.mem_inv_check_mem_auxP_valid_pointer with (chunk := chunk) (addr := addr)in Hperm as Hck; eauto.
  destruct Hck as [Hptr | Hnull].
  - destruct Hptr as (b & ofs & Hptr & Hvalid_ptr & Hvalid_blk).
    rewrite Hptr.

    assert (Hvalid_ptr1: (Mem.valid_pointer (bpf_m st1) b
                (Ptrofs.unsigned ofs)
              || Mem.valid_pointer (bpf_m st1) b
                   (Ptrofs.unsigned ofs - 1))%bool = true). {
      rewrite Bool.orb_true_iff in *.
      destruct Hvalid_ptr as [Hvalid_ptr | Hvalid_ptr]; [left | right].
      all:
        rewrite Mem.valid_pointer_valid_access in *;
        unfold Mem.valid_access in *;
        intuition;
        clear H0;
        unfold Mem.range_perm in *;
        intros;
        specialize (H ofs0 H0);
        destruct Hrel;
        eapply Mem.perm_unchanged_on; eauto;
        simpl.

      all:
        destruct minvalid as (Hflag_blk & Hregs_blk & Hst_blk & _);
        split; [intro Hf; subst b; apply Hflag_blk; assumption|];
        split; intro Hf; subst b; [apply Hregs_blk | apply Hst_blk]; assumption.
    }
    rewrite Hvalid_ptr, Hvalid_ptr1.

    eexists; intuition.
  - rewrite Hnull.
    unfold Vnullptr; simpl.
    eexists; intuition.
Qed.

Lemma check_memP_check_memP2:
  forall perm chunk addr st0 st1 flag_blk regs_blk st_blk
    (Hrel : Rel flag_blk regs_blk st_blk st0 st1)
    (Hmem_inv : memory_inv st0)
    (Hperm: perm_order perm Readable),
    check_memP perm chunk (Vint addr) st0 = check_memP2 perm chunk (Vint addr) st1.
Proof.
  intros.
  unfold check_memP, check_memP2.
  unfold is_well_chunk_boolP.

  assert (Heq0: State.eval_mem_num st0 = eval_mem_num st1). {
    destruct Hrel.
    unfold State.eval_mem_num, eval_mem_num.
    assumption.
  }

  assert (Heq1: State.eval_mem_regions st0 = eval_mem_regions st1). {
    destruct Hrel.
    unfold State.eval_mem_regions, eval_mem_regions.
    assumption.
  }

  unfold State.eval_mem_num, eval_mem_num,
    State.eval_mem_regions, eval_mem_regions in *.
  rewrite <- Heq0, Heq1.

  erewrite <- check_mem_auxP_check_mem_auxP2; eauto.

  eapply cmp_ptr32_null_check_mem_auxP_Some in Hperm; eauto.
  destruct Hperm as (res & Hcmp0 & Hcmp1).
  rewrite <- Heq1.
  rewrite Hcmp0, Hcmp1.
  reflexivity.
Qed.


Lemma cmp_ptr32_null_check_memP_Some:
  forall st0 st1 perm chunk addr flag_blk regs_blk st_blk
    (Hrel : Rel flag_blk regs_blk st_blk st0 st1)
    (Hmem_inv : memory_inv st0)
    (Hperm: perm_order perm Readable),
    exists res,
    cmp_ptr32_null (State.bpf_m st0)
      (check_memP perm chunk (Vint addr) st0) = Some res /\
    cmp_ptr32_null (bpf_m st1)
      (check_memP perm chunk (Vint addr) st0) = Some res.
Proof.
  intros.
  unfold cmp_ptr32_null.

  unfold Val.cmpu_bool, Vnullptr; simpl.
  change (Int.eq Int.zero Int.zero) with true; unfold andb.

  eapply CheckMem.mem_inv_check_mem_valid_pointer with (chunk := chunk) (addr := addr)in Hperm as Hck; eauto.
  destruct Hck as [Hptr | Hnull].
  - destruct Hptr as (b & ofs & Hptr & Hvalid_ptr & Hvalid_blk).
    rewrite Hptr.

    assert (Hvalid_ptr1: (Mem.valid_pointer (bpf_m st1) b
                (Ptrofs.unsigned ofs)
              || Mem.valid_pointer (bpf_m st1) b
                   (Ptrofs.unsigned ofs - 1))%bool = true). {
      rewrite Bool.orb_true_iff in *.
      destruct Hvalid_ptr as [Hvalid_ptr | Hvalid_ptr]; [left | right].
      all:
        rewrite Mem.valid_pointer_valid_access in *;
        unfold Mem.valid_access in *;
        intuition;
        clear H0;
        unfold Mem.range_perm in *;
        intros;
        specialize (H ofs0 H0);
        destruct Hrel;
        eapply Mem.perm_unchanged_on; eauto;
        simpl.

      all:
        destruct minvalid as (Hflag_blk & Hregs_blk & Hst_blk & _);
        split; [intro Hf; subst b; apply Hflag_blk; assumption|];
        split; intro Hf; subst b; [apply Hregs_blk | apply Hst_blk]; assumption.
    }
    rewrite Hvalid_ptr, Hvalid_ptr1.

    eexists; intuition.
  - rewrite Hnull.
    unfold Vnullptr; simpl.
    eexists; intuition.
Qed.
