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

From Coq Require Import List ZArith.
Import ListNotations.

From compcert.lib Require Import Integers.

(** This module presents a generic List as a fix-sized array in C *)

Module List64AsArray.

  Definition t := list int64.
  Definition index (l: t) (idx: int): option int64 := 
    List.nth_error l (Z.to_nat (Int.unsigned idx)).

  Fixpoint assign' (l: t) (cur: nat) (v: int64): option t :=
    match l with
    | [] => None (**r it should be impossible *)
    | hd :: tl =>
      match cur with
      | O => Some (v :: tl)
      | S n =>
        match assign' tl n v with
        | Some nl => Some (hd :: nl)
        | None => None
        end
      end
    end.

  Definition assign (l: t) (cur: nat) (v: int64): t :=
    match assign' l cur v with
    | Some nl => nl
    | None    => []
    end.

End List64AsArray.

Module List16.

  Definition t := list int.
  Definition index (l: t) (idx: int): option int :=
    List.nth_error l (Z.to_nat (Int.unsigned idx)).

  Fixpoint assign' (l: t) (cur: nat) (v: int): option t :=
    match l with
    | [] => None (**r it should be impossible *)
    | hd :: tl =>
      match cur with
      | O => Some (v :: tl)
      | S n =>
        match assign' tl n v with
        | Some nl => Some (hd :: nl)
        | None => None
        end
      end
    end.

  Definition assign (l: t) (cur: nat) (v: int): t :=
    match assign' l cur v with
    | Some nl => nl
    | None    => []
    end.

  Fixpoint create_int_list (l: nat): List16.t :=
    match l with
    | O => []
    | S n => Int.zero :: create_int_list n
    end.

End List16.

Module List32.

  Definition t := list int.
  Definition index (l: t) (idx: int): option int :=
    List.nth_error l (Z.to_nat (Int.unsigned idx)).

  Fixpoint assign' (l: t) (cur: nat) (v: int): option t :=
    match l with
    | [] => None (**r it should be impossible *)
    | hd :: tl =>
      match cur with
      | O => Some (v :: tl)
      | S n =>
        match assign' tl n v with
        | Some nl => Some (hd :: nl)
        | None => None
        end
      end
    end.

  Definition assign (l: t) (cur: nat) (v: int): t :=
    match assign' l cur v with
    | Some nl => nl
    | None    => []
    end.

  Fixpoint create_int_list (l: nat): List32.t :=
    match l with
    | O => []
    | S n => Int.zero :: create_int_list n
    end.

End List32.


Module ListNat.

  Definition t := list nat.
  Definition index (l: t) (idx: nat): nat := 
    match List.nth_error l idx with
    | Some i => i
    | None => 0
    end.
  Fixpoint assign' (l: t) (cur v: nat): option t :=
    match l with
    | [] => None (**r it should be impossible *)
    | hd :: tl =>
      match cur with
      | O => Some (v :: tl)
      | S n =>
        match assign' tl n v with
        | Some nl => Some (hd :: nl)
        | None => None
        end
      end
    end.

  Definition assign (l: t) (cur v: nat): t :=
    match assign' l cur v with
    | Some nl => nl
    | None    => []
    end.

  Fixpoint is_exists (l: t) (cur v: nat): bool :=
    match l with
    | [] => false
    | hd :: tl =>
      match cur with
      | O => false
      | S n =>
        if Nat.eqb hd v then
          true
        else
          is_exists tl n v
      end
    end.

  Fixpoint create_int_list (l: nat): ListNat.t :=
    match l with
    | O => []
    | S n => 0 :: create_int_list n
    end.

(** test
  Compute (is_exists [1;2;3;4;5] 4 5).
  Compute (is_exists [1;2;3;4;5] 4 4). *)

End ListNat.



Fixpoint list_iter {A B:Type} (l: list A) (b: B) (f: A -> B -> B): B :=
  match l with
  | [] => b
  | hd :: tl => list_iter tl (f hd b) f
  end.

Fixpoint list_iter2_aux {A B:Type} (fuel pc: nat) (default: A) (l: list A) (b: B) (f: A -> B -> B): B :=
  match fuel with
  | O => b
  | S n =>
    let hd := nth_default default l pc in
      list_iter2_aux n (S pc) default l (f hd b) f
  end.

Definition list_iter2 {A B:Type} (default: A) (l: list A) (b: B) (f: A -> B -> B): B :=
  list_iter2_aux (length l) 0 default l b f.

Lemma list_app:
  forall {A: Type} (l: list A) (a: A) (l1: list A),
  l1 ++ a :: l = (l1 ++ [a]) ++ l.
Proof.
  intros.
  rewrite <- app_assoc.
  simpl.
  reflexivity.
Qed.

Lemma list_nth_default:
  forall {A:Type} (default: A) l1 a l,
    nth_default default ((l1 ++ [a]) ++ l) (length l1) = a.
Proof.
  unfold nth_default; induction l1; simpl; intros.
  - reflexivity.
  - rewrite IHl1.
    reflexivity.
Qed.

Lemma list_iter2_aux_equiv:
  forall (A B:Type) (default: A) (l: list A) (a: A)(b: B) (f: A -> B -> B) (l1: list A) (l2: list A),
    list_iter2_aux (length l) (length l1) default (l1 ++ l) (f a b) f =
    list_iter2_aux (length l) (length l2) default (l2 ++ l) (f a b) f.
Proof.
  induction l; simpl; intros.
  - reflexivity.
  - rewrite list_app.
    rewrite list_app with (l3 := l2).
    rewrite ! list_nth_default.
    specialize (IHl a (f a0 b) f).
    specialize (IHl (l1 ++ [a]) (l2 ++ [a])).
    rewrite ! last_length in IHl.
    assumption.
Qed.

Lemma list_iter_equiv:
  forall (A B:Type) (default: A) (l: list A) (b: B) (f: A -> B -> B),
    list_iter2 default l b f = list_iter l b f.
Proof.
  unfold list_iter2.
  induction l; simpl; intros.
  - reflexivity.
  - rewrite <- IHl.
    unfold nth_default.
    simpl.
    assert (Heq: list_iter2_aux (length l) 1 default (a :: l) (f a b) f =
                 list_iter2_aux (length l) (length [a]) default ([a] ++ l) (f a b) f). {
      simpl.
      reflexivity.
    }
    rewrite Heq; clear Heq.
    rewrite list_iter2_aux_equiv with (l2 := []).
    simpl.
    reflexivity.
Qed.