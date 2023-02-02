From bpf.comm Require Import Regs.


(** For jitted arm32 instructions, we need extra two sequential instructions
- load_regs: declare which bpf registers should be loaded into arm related registers
- store_regs: show which bpf registers should be updated according to arm related registers

So, we define a type named LoadStoreRegs, there is a usage about this type:
1. Firstly, the initial state is all-false;
2. then, evalulate or update the LoadStoreRegs;
3. finally, reset the LoadStoreRegs.
*)

(** LoadStorePerm is used to declare that if a register should be loaded (i.e. LoadPerm) before executing the jitted arm32 code or be stored aftering executing the jitted arm32 code.
- NonPerm: the initial permission of LoadStoreRegs, do nothing
- LoadPerm: we should add ARM32 Load instruciton, e.g. add R1 R2 R3 where R2 and R3 are LoadPerm **IF** the previous value of R2 (R3) is NonPerm or LoadPerm or LoadBeforeStore
- StorePerm: we should add ARM32 Store instruciton, e.g. add R1 R2 R3 where R1 is StorePerm **IF** the previous value of R1 is NonPerm or StorePerm
- LoadAndStore: we should add both ARM32 Load and Store instructions: e.g.  add R5 R4 R1; add R1 R2 R3 where the previous R1 is LoadPerm or NonPerm, and now R1 is LoadAndStore.
 *)

(** we define two records which should be a part of the monadic state *)

Inductive LoadStorePerm :=
  | NonPerm      (**r = 0 *)
  | LoadPerm     (**r = 1 *)
  | StorePerm    (**r = 2 *)
  | LoadAndStore (**r = 3 *)
.

Lemma LoadStorePerm_eq: forall (x y: LoadStorePerm), {x=y} + {x<>y}.
Proof.
decide equality. Defined.

(** flag_eq: flag -> flag -> bool
  *)
Definition LoadStorePerm_eqb (x y: LoadStorePerm): bool := if LoadStorePerm_eq x y then true else false.


(**
  because rBPF has the form INS dst src where `dst` is always a register, so `dst` should be loadandstoreperm and `src` may be a register (in this case `src` only has the loadperm) or an immeidate number.

  All in all,
  - history perm could be nonperm, loadperm, loadandstoreperm or storeperm (when do mov rj ri, rj is storeperm and ri is loadperm)
  - cur perm could only be loadperm or loadandstoreperm
 *)
Definition upd_LoadStorePerm (history cur: LoadStorePerm): option LoadStorePerm :=
  match cur with
  | NonPerm => None
  | LoadPerm =>
      match history with
      | NonPerm
      | LoadPerm     => Some LoadPerm  (**r before, the register is unused or only be read, the new read will preserve LoadPerm *)
      | StorePerm    => Some StorePerm (**r before, the register is only written, so the value is latest, we change nothing *)
      | LoadAndStore => Some LoadAndStore (**r before, the register is read/written , so the value is latest, we still change nothing *)
      end
  | StorePerm =>
      match history with
      | NonPerm      => Some StorePerm  (**r before, the register is unused, now it should be written *)
      | LoadPerm     => Some LoadAndStore (**r this case is write-after-read *)
      | StorePerm    => Some StorePerm (**r do nothing *)
      | LoadAndStore => Some LoadAndStore (**r do nothing *)
      end
  | LoadAndStore =>
      match history with
      | StorePerm    => Some StorePerm  (**r before, the register is only written, so the value is latest, we change nothing *)
      | NonPerm
      | LoadPerm
      | LoadAndStore => Some LoadAndStore
      end
  end.

Record LoadStoreRegs := {
  is_R0: LoadStorePerm;
  is_R1: LoadStorePerm;
  is_R2: LoadStorePerm;
  is_R3: LoadStorePerm;
  is_R4: LoadStorePerm;
  is_R5: LoadStorePerm;
  is_R6: LoadStorePerm;
  is_R7: LoadStorePerm;
  is_R8: LoadStorePerm;
  is_R9: LoadStorePerm;
  is_R10: LoadStorePerm;
}.

Definition init_LoadStoreRegs: LoadStoreRegs := {|
  is_R0 := NonPerm;
  is_R1 := NonPerm;
  is_R2 := NonPerm;
  is_R3 := NonPerm;
  is_R4 := NonPerm;
  is_R5 := NonPerm;
  is_R6 := NonPerm;
  is_R7 := NonPerm;
  is_R8 := NonPerm;
  is_R9 := NonPerm;
  is_R10 := NonPerm;
|}.

Definition reset_LoadStoreRegs (ls: LoadStoreRegs) : LoadStoreRegs := init_LoadStoreRegs. (**r this part should be manually implemented *)

Definition eval_LoadStoreRegs (ls: LoadStoreRegs) (r: reg) : LoadStorePerm :=
  match r with
  | R0 => is_R0 ls
  | R1 => is_R1 ls
  | R2 => is_R2 ls
  | R3 => is_R3 ls
  | R4 => is_R4 ls
  | R5 => is_R5 ls
  | R6 => is_R6 ls
  | R7 => is_R7 ls
  | R8 => is_R8 ls
  | R9 => is_R9 ls
  | R10 => is_R10 ls
  end.

(** we set the related register with LoadStorePerm *)
Definition upd_LoadStoreRegs (ls: LoadStoreRegs) (r: reg) (cur: LoadStorePerm) : option LoadStoreRegs :=
  let history := eval_LoadStoreRegs ls r in
  let new     := upd_LoadStorePerm history cur in
    match new with
    | None => None
    | Some p => Some
      match r with
      | R0 => {|
                is_R0 := p;
                is_R1 := is_R1 ls;
                is_R2 := is_R2 ls;
                is_R3 := is_R3 ls;
                is_R4 := is_R4 ls;
                is_R5 := is_R5 ls;
                is_R6 := is_R6 ls;
                is_R7 := is_R7 ls;
                is_R8 := is_R8 ls;
                is_R9 := is_R9 ls;
                is_R10 := is_R10 ls;
              |}
      | R1 => {|
                is_R0 := is_R0 ls;
                is_R1 := p;
                is_R2 := is_R2 ls;
                is_R3 := is_R3 ls;
                is_R4 := is_R4 ls;
                is_R5 := is_R5 ls;
                is_R6 := is_R6 ls;
                is_R7 := is_R7 ls;
                is_R8 := is_R8 ls;
                is_R9 := is_R9 ls;
                is_R10 := is_R10 ls;
              |}
      | R2 => {|
                is_R0 := is_R0 ls;
                is_R1 := is_R1 ls;
                is_R2 := p;
                is_R3 := is_R3 ls;
                is_R4 := is_R4 ls;
                is_R5 := is_R5 ls;
                is_R6 := is_R6 ls;
                is_R7 := is_R7 ls;
                is_R8 := is_R8 ls;
                is_R9 := is_R9 ls;
                is_R10 := is_R10 ls;
              |}
      | R3 => {|
                is_R0 := is_R0 ls;
                is_R1 := is_R1 ls;
                is_R2 := is_R2 ls;
                is_R3 := p;
                is_R4 := is_R4 ls;
                is_R5 := is_R5 ls;
                is_R6 := is_R6 ls;
                is_R7 := is_R7 ls;
                is_R8 := is_R8 ls;
                is_R9 := is_R9 ls;
                is_R10 := is_R10 ls;
              |}
      | R4 => {|
                is_R0 := is_R0 ls;
                is_R1 := is_R1 ls;
                is_R2 := is_R2 ls;
                is_R3 := is_R3 ls;
                is_R4 := p;
                is_R5 := is_R5 ls;
                is_R6 := is_R6 ls;
                is_R7 := is_R7 ls;
                is_R8 := is_R8 ls;
                is_R9 := is_R9 ls;
                is_R10 := is_R10 ls;
              |}
      | R5 => {|
                is_R0 := is_R0 ls;
                is_R1 := is_R1 ls;
                is_R2 := is_R2 ls;
                is_R3 := is_R3 ls;
                is_R4 := is_R4 ls;
                is_R5 := p;
                is_R6 := is_R6 ls;
                is_R7 := is_R7 ls;
                is_R8 := is_R8 ls;
                is_R9 := is_R9 ls;
                is_R10 := is_R10 ls;
              |}
      | R6 => {|
                is_R0 := is_R0 ls;
                is_R1 := is_R1 ls;
                is_R2 := is_R2 ls;
                is_R3 := is_R3 ls;
                is_R4 := is_R4 ls;
                is_R5 := is_R5 ls;
                is_R6 := p;
                is_R7 := is_R7 ls;
                is_R8 := is_R8 ls;
                is_R9 := is_R9 ls;
                is_R10 := is_R10 ls;
              |}
      | R7 => {|
                is_R0 := is_R0 ls;
                is_R1 := is_R1 ls;
                is_R2 := is_R2 ls;
                is_R3 := is_R3 ls;
                is_R4 := is_R4 ls;
                is_R5 := is_R5 ls;
                is_R6 := is_R6 ls;
                is_R7 := p;
                is_R8 := is_R8 ls;
                is_R9 := is_R9 ls;
                is_R10 := is_R10 ls;
              |}
      | R8 => {|
                is_R0 := is_R0 ls;
                is_R1 := is_R1 ls;
                is_R2 := is_R2 ls;
                is_R3 := is_R3 ls;
                is_R4 := is_R4 ls;
                is_R5 := is_R5 ls;
                is_R6 := is_R7 ls;
                is_R7 := is_R7 ls;
                is_R8 := p;
                is_R9 := is_R9 ls;
                is_R10 := is_R10 ls;
              |}
      | R9 => {|
                is_R0 := is_R0 ls;
                is_R1 := is_R1 ls;
                is_R2 := is_R2 ls;
                is_R3 := is_R3 ls;
                is_R4 := is_R4 ls;
                is_R5 := is_R5 ls;
                is_R6 := is_R7 ls;
                is_R7 := is_R7 ls;
                is_R8 := is_R8 ls;
                is_R9 := p;
                is_R10 := is_R10 ls;
              |}
      | R10 => {|
                is_R0 := is_R0 ls;
                is_R1 := is_R1 ls;
                is_R2 := is_R2 ls;
                is_R3 := is_R3 ls;
                is_R4 := is_R4 ls;
                is_R5 := is_R5 ls;
                is_R6 := is_R7 ls;
                is_R7 := is_R7 ls;
                is_R8 := is_R8 ls;
                is_R9 := is_R9 ls;
                is_R10 := p;
              |}
      end
    end.



Definition is_load_reg (r: reg) (ls: LoadStoreRegs) : bool :=
  let perm := eval_LoadStoreRegs ls r in
    if LoadStorePerm_eqb perm LoadPerm then
      true
    else if LoadStorePerm_eqb perm LoadAndStore then
      true
    else
      false.

Definition is_store_reg (r: reg) (ls: LoadStoreRegs) : bool :=
  let perm := eval_LoadStoreRegs ls r in
    if LoadStorePerm_eqb perm StorePerm then
      true
    else if LoadStorePerm_eqb perm LoadAndStore then
      true
    else
      false.

Definition is_non_reg (r: reg) (ls: LoadStoreRegs) : bool :=
  let perm := eval_LoadStoreRegs ls r in
    if LoadStorePerm_eqb perm NonPerm then
      false
    else
      true.
