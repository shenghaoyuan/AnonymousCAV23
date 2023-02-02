From Coq Require Import List ZArith.
Import ListNotations.

From compcert.lib Require Import Integers.

Record key_value2 := { (**r the key is the index: pc *)
  arm_ofs   : nat; (**r value1 *)
  alu32_ofs : nat; (**r value2 *)
}.

Definition empty_kv := {|
  arm_ofs   := 0;
  alu32_ofs := 0;
|}.

Module ListKeyV.

  Definition t := list key_value2.
  Definition index (l: t) (idx: int): option key_value2 := 
    List.nth_error l (Z.to_nat (Int.unsigned idx)).

  Fixpoint assign' (l: t) (cur: nat ) (v: key_value2): option t :=
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

  Definition assign (l: t) (cur: nat) (v: key_value2): t :=
    match assign' l cur v with
    | Some nl => nl
    | None    => []
    end.

  Fixpoint create_int_list (len: nat): t :=
    match len with
    | O => []
    | S n => empty_kv :: create_int_list n
    end.

End ListKeyV.