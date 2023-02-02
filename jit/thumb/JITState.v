From compcert.common Require Import Memory Values AST.
From compcert.lib Require Import Integers.
From compcert.arm Require Import ABinSem.

From bpf.comm Require Import ListAsArray Flag Regs MemRegion rBPFAST.
From bpf.jit.thumb Require Import LoadStoreRegs KeyValue2.

From Coq Require Import List ZArith.
Import ListNotations.

(** This module defines the jit state *)

(** This module defines a monadic JIT state where `jittedthumb` is a part of the jit state, for simplification *)

Definition JITTED_LIST_MAX_LENGTH: nat := 1000. (**r NB: the jitted list may be overflow, please check jitted_len of jit_state *)

Definition ENTRY_POINT_MAX_LENGTH: nat := 100.

(** * BPF State Layout *)

(**
  pc_loc   (Byte.byte; Byte.byte; Byte.byte; Byte.byte)
  flag     (Vptr b_flag 0) --> [Byte.byte; Byte.byte; Byte.byte; Byte.byte]
  regs_st  (Vptr b_regs 0) --> [Byte.byte; ... ; Byte.byte;
                                           ...
                                Byte.byte; ... ; Byte.byte] 11*8
  mrs_num  (Byte.byte; Byte.byte; Byte.byte; Byte.byte)
  bpf_mrs  (Vptr b_mrs 0) --> [...]
  ins_len  (Byte.byte; Byte.byte; Byte.byte; Byte.byte)
  ...
*)


Record jit_state := {
  jit_pc          : int;
  jit_flag        : val; (**r Vptr flag_blk 0 *)
  jit_regs        : val; (**r the start address of register map: Vptr regs_blk 0 *)
  jit_mrs_num     : nat;  (**r number of memory regions, put it here to guarantee align *)
  jit_mrs         : MyMemRegionsType;
  jit_ins_len     : nat;
  jit_ins         : List64AsArray.t;(**r updated iBPF binary instructions *)

  kv2             : ListKeyV.t; (**r the length of kv2 = the jit_ins_len *)

  use_IR11        : bool; (**r will use IR11 *)
  load_store_regs : LoadStoreRegs;
  offset          : nat;  (**r how many jitted bpf alu32 instructions *)
  thumb_len       : nat;  (**r how many jitted thumb instructions *)
  thumb           : List16.t;

  jitted_len      : nat;            (**r the current pointer of jitted code *)
  jitted_list     : val; (**r Vptr jit_blk 0 *)  (**r the jitted thumb code*)
  jit_mem         : mem;
}.

Definition empty_jit_state := {|
  jit_pc          := Int.zero;
  jit_flag        := Vundef;
  jit_regs        := Vundef;
  jit_mrs_num     := 0;
  jit_mrs         := [];
  jit_ins_len     := 0;
  jit_ins         := [];

  kv2             := [];

  use_IR11        := false;
  load_store_regs := init_LoadStoreRegs;
  offset          := 0;
  thumb_len       := 0;
  thumb           := List16.create_int_list JITTED_LIST_MAX_LENGTH;

  jitted_len      := 0;
  jitted_list     := Vundef;
  jit_mem         := Mem.empty
|}.

Definition eval_jit_pc (st: jit_state): int := jit_pc st.

Definition upd_jit_pc (p: int) (st: jit_state): jit_state := {|
  jit_pc          := p;
  jit_flag        := jit_flag st;
  jit_regs        := jit_regs st;
  jit_mrs_num     := jit_mrs_num st;
  jit_mrs         := jit_mrs st;
  jit_ins_len     := jit_ins_len st;
  jit_ins         := jit_ins   st;

  kv2             := kv2 st;

  use_IR11        := use_IR11  st;
  load_store_regs := load_store_regs st;
  offset          := offset st;
  thumb_len       := thumb_len st;
  thumb           := thumb st;

  jitted_len      := jitted_len st;
  jitted_list     := jitted_list st;
  jit_mem         := jit_mem st;
|}.

Definition upd_jit_pc_incr (st: jit_state): jit_state := {|
  jit_pc          := Int.add (jit_pc st) Int.one;
  jit_flag        := jit_flag st;
  jit_regs        := jit_regs st;
  jit_mrs_num     := jit_mrs_num st;
  jit_mrs         := jit_mrs st;
  jit_ins_len     := jit_ins_len st;
  jit_ins         := jit_ins   st;

  kv2             := kv2 st;

  use_IR11        := use_IR11  st;
  load_store_regs := load_store_regs st;
  offset          := offset st;
  thumb_len       := thumb_len st;
  thumb           := thumb st;

  jitted_len      := jitted_len st;
  jitted_list     := jitted_list st;
  jit_mem         := jit_mem st;
|}.

Definition eval_jit_flag (st: jit_state): option val :=
  Mem.loadv Mint32 (jit_mem st) (jit_flag st).

Definition upd_jit_flag' (f: val) (st: jit_state): option mem :=
  Mem.storev Mint32 (jit_mem st) (jit_flag st) f.

Definition upd_jit_flag (f: bpf_flag) (st: jit_state): option jit_state :=
  match upd_jit_flag' (Vint (int_of_flag f)) st with
  | Some m => Some
     {|
      jit_pc          := jit_pc st;
      jit_flag        := jit_flag st;
      jit_regs        := jit_regs st;
      jit_mrs_num     := jit_mrs_num st;
      jit_mrs         := jit_mrs st;
      jit_ins_len     := jit_ins_len st;
      jit_ins         := jit_ins   st;

      kv2             := kv2 st;

      use_IR11        := use_IR11  st;
      load_store_regs := load_store_regs st;
      offset          := offset st;
      thumb_len       := thumb_len st;
      thumb           := thumb st;

      jitted_len      := jitted_len st;
      jitted_list     := jitted_list st;
      jit_mem         := m;
    |}
  | None => None
  end.


(**r we will assumption the regster map is also in someplace of the bpf_state: Vptr b ofs *)
Definition eval_jit_reg (r: reg) (st: jit_state): option val :=
  let ptr := Val.add (jit_regs st) (Vint (Int.repr (8 * id_of_reg r)%Z)) in
    Mem.loadv Mint64 (jit_mem st) ptr.

Definition upd_jit_reg' (r: reg) (v: val) (st: jit_state): option mem :=
  let ptr := Val.add (jit_regs st) (Vint (Int.repr (8 * id_of_reg r)%Z)) in
    Mem.storev Mint64 (jit_mem st) ptr v.

Definition upd_jit_reg (r:reg) (v:val) (st: jit_state): option jit_state :=
  match upd_jit_reg' r v st with
  | Some m => Some
    {|
      jit_pc          := jit_pc st;
      jit_flag        := jit_flag st;
      jit_regs        := jit_regs st;
      jit_mrs_num     := jit_mrs_num st;
      jit_mrs         := jit_mrs st;
      jit_ins_len     := jit_ins_len st;
      jit_ins         := jit_ins   st;

      kv2             := kv2 st;

      use_IR11        := use_IR11  st;
      load_store_regs := load_store_regs st;
      offset          := offset st;
      thumb_len       := thumb_len st;
      thumb           := thumb st;

      jitted_len      := jitted_len st;
      jitted_list     := jitted_list st;
      jit_mem         := m;
    |}
  | None => None
  end.

Definition eval_jit_mem_num (st: jit_state): nat := (jit_mrs_num st).

Definition eval_jit_mem_regions (st: jit_state): MyMemRegionsType := jit_mrs st.

Definition eval_jit_mem (st: jit_state): Mem.mem := jit_mem st.

Definition upd_jit_mem (m: Mem.mem) (st: jit_state): jit_state := {|
  jit_pc          := jit_pc st;
  jit_flag        := jit_flag st;
  jit_regs        := jit_regs st;
  jit_mrs_num     := jit_mrs_num st;
  jit_mrs         := jit_mrs st;
  jit_ins_len     := jit_ins_len st;
  jit_ins         := jit_ins   st;

  kv2             := kv2 st;

  use_IR11        := use_IR11  st;
  load_store_regs := load_store_regs st;
  offset          := offset st;
  thumb_len       := thumb_len st;
  thumb           := thumb st;

  jitted_len      := jitted_len st;
  jitted_list     := jitted_list st;
  jit_mem         := m;
|}.

Definition load_jit_mem (chunk: memory_chunk) (ptr: val) (st: jit_state): option val :=
  match chunk with
  | Mint8unsigned | Mint16unsigned | Mint32 =>
    match Mem.loadv chunk (jit_mem st) ptr with
    | Some res => _to_vlong res
    | None => None
    end
  | Mint64 => Mem.loadv chunk (jit_mem st) ptr
  | _ => None
  end
.

Definition store_jit_mem_imm (ptr: val) (chunk: memory_chunk) (v: val) (st: jit_state): option jit_state :=
  match chunk with
  | Mint8unsigned | Mint16unsigned | Mint32 | Mint64 =>
    let src := vint_to_vint_or_vlong chunk v in
      match Mem.storev chunk (jit_mem st) ptr src with
      | Some m => Some (upd_jit_mem m st)
      | None => None
      end
  | _ => None
  end
.

Definition store_jit_mem_reg (ptr: val) (chunk: memory_chunk) (v: val) (st: jit_state): option jit_state :=
  match chunk with
  | Mint8unsigned | Mint16unsigned | Mint32 | Mint64 =>
    let src := vlong_to_vint_or_vlong chunk v in
    match Mem.storev chunk (jit_mem st) ptr src with
    | Some m => Some (upd_jit_mem m st)
    | None => None
    end
  | _ => None
  end.

Definition eval_jit_ins_len (st: jit_state): int := Int.repr (Z.of_nat (jit_ins_len st)).

Definition eval_jit_ins (idx: int) (st: jit_state): option int64 := List64AsArray.index (jit_ins st) idx.


Definition add_key_value2 (pc: nat) (v0 v1: nat) (st: jit_state): jit_state :=
  let kv := {| arm_ofs := v0; alu32_ofs := v1 |} in (*
  if Nat.ltb (kv2_len st) ENTRY_POINT_MAX_LENGTH then
    Some *)
    {|
      jit_pc          := jit_pc st;
      jit_flag        := jit_flag st;
      jit_regs        := jit_regs st;
      jit_mrs_num     := jit_mrs_num st;
      jit_mrs         := jit_mrs st;
      jit_ins_len     := jit_ins_len st;
      jit_ins         := jit_ins   st;

      kv2             := ListKeyV.assign (kv2 st) pc kv;

      use_IR11        := use_IR11  st;
      load_store_regs := load_store_regs st;
      offset          := offset st;
      thumb_len       := thumb_len st;
      thumb           := thumb st;

      jitted_len      := jitted_len st;
      jitted_list     := jitted_list st;
      jit_mem         := jit_mem st;
    |}. (*
  else
    upd_jit_flag BPF_ILLEGAL_EP_LEN st. *)

Definition upd_IR11_jittedthumb (f: bool) (st: jit_state): jit_state := {|
  jit_pc          := jit_pc st;
  jit_flag        := jit_flag st;
  jit_regs        := jit_regs st;
  jit_mrs_num     := jit_mrs_num st;
  jit_mrs         := jit_mrs st;
  jit_ins_len     := jit_ins_len st;
  jit_ins         := jit_ins   st;

  kv2             := kv2 st;

  use_IR11        := f;
  load_store_regs := load_store_regs st;
  offset          := offset st;
  thumb_len       := thumb_len st;
  thumb           := thumb st;

  jitted_len      := jitted_len st;
  jitted_list     := jitted_list st;
  jit_mem         := jit_mem st;
|}.


Definition add_ins_jittedthumb (ins: int) (st: jit_state): jit_state := {|
  jit_pc          := jit_pc st;
  jit_flag        := jit_flag st;
  jit_regs        := jit_regs st;
  jit_mrs_num     := jit_mrs_num st;
  jit_mrs         := jit_mrs st;
  jit_ins_len     := jit_ins_len st;
  jit_ins         := jit_ins   st;

  kv2             := kv2 st;

  use_IR11        := use_IR11  st;
  load_store_regs := load_store_regs st;
  offset          := offset st;
  thumb_len       := S (thumb_len st);
  thumb           := List16.assign (thumb st) (thumb_len st) ins;

  jitted_len      := jitted_len st;
  jitted_list     := jitted_list st;
  jit_mem         := jit_mem st;
|}.

Definition upd_bpf_offset_jittedthumb (st: jit_state): jit_state := {|
  jit_pc          := jit_pc st;
  jit_flag        := jit_flag st;
  jit_regs        := jit_regs st;
  jit_mrs_num     := jit_mrs_num st;
  jit_mrs         := jit_mrs st;
  jit_ins_len     := jit_ins_len st;
  jit_ins         := jit_ins   st;

  kv2             := kv2 st;

  use_IR11        := use_IR11  st;
  load_store_regs := load_store_regs st;
  offset          := S (offset st);
  thumb_len       := thumb_len st;
  thumb           := thumb st;

  jitted_len      := jitted_len st;
  jitted_list     := jitted_list st;
  jit_mem         := jit_mem st;
|}.

Definition upd_load_store_regs_jittedthumb (r: reg) (ls: LoadStorePerm) (st: jit_state): option jit_state :=
  match upd_LoadStoreRegs (load_store_regs st) r ls with
  | Some lsr => Some
    {|
      jit_pc          := jit_pc st;
      jit_flag        := jit_flag st;
      jit_regs        := jit_regs st;
      jit_mrs_num     := jit_mrs_num st;
      jit_mrs         := jit_mrs st;
      jit_ins_len     := jit_ins_len st;
      jit_ins         := jit_ins   st;

      kv2             := kv2 st;

      use_IR11        := use_IR11  st;
      load_store_regs := lsr;
      offset          := offset st;
      thumb_len       := thumb_len st;
      thumb           := thumb st;

      jitted_len      := jitted_len st;
      jitted_list     := jitted_list st;
      jit_mem         := jit_mem st;
    |}
  | None => None
  end.

Definition upd_load_store_regs (lsr: LoadStoreRegs) (st: jit_state): jit_state :=
  {|
    jit_pc          := jit_pc st;
    jit_flag        := jit_flag st;
    jit_regs        := jit_regs st;
    jit_mrs_num     := jit_mrs_num st;
    jit_mrs         := jit_mrs st;
    jit_ins_len     := jit_ins_len st;
    jit_ins         := jit_ins   st;

    kv2             := kv2 st;

    use_IR11        := use_IR11  st;
    load_store_regs := lsr;
    offset          := offset st;
    thumb_len       := thumb_len st;
    thumb           := thumb st;

    jitted_len      := jitted_len st;
    jitted_list     := jitted_list st;
    jit_mem         := jit_mem st;
  |}.

Definition upd_thumb_jittedthumb (ins: int) (pc: nat) (st: jit_state): jit_state := {|
  jit_pc          := jit_pc st;
  jit_flag        := jit_flag st;
  jit_regs        := jit_regs st;
  jit_mrs_num     := jit_mrs_num st;
  jit_mrs         := jit_mrs st;
  jit_ins_len     := jit_ins_len st;
  jit_ins         := jit_ins   st;

  kv2             := kv2 st;

  use_IR11        := use_IR11  st;
  load_store_regs := load_store_regs st;
  offset          := offset st;
  thumb_len       := thumb_len st;
  thumb           := List16.assign (thumb st) pc ins;

  jitted_len      := jitted_len st;
  jitted_list     := jitted_list st;
  jit_mem         := jit_mem st;
|}.

Definition upd_jitted_list' (ins: int) (st: jit_state): option mem :=
  if (Nat.leb ((2 * (jitted_len st)) + 4) JITTED_LIST_MAX_LENGTH)%nat then
    let addr := Val.add (jitted_list st) (Vint (Int.repr (Z.of_nat (2 * (jitted_len st))%nat))) in
      Mem.storev Mint16unsigned (jit_mem st) addr (Vint ins)
  else
    None.

Definition upd_jitted_list (ins: int) (st: jit_state): option jit_state :=
  match upd_jitted_list' ins st with
  | Some m => Some
    {|
      jit_pc          := jit_pc st;
      jit_flag        := jit_flag st;
      jit_regs        := jit_regs st;
      jit_mrs_num     := jit_mrs_num st;
      jit_mrs         := jit_mrs st;
      jit_ins_len     := jit_ins_len st;
      jit_ins         := jit_ins   st;

      kv2             := kv2 st;

      use_IR11        := use_IR11  st;
      load_store_regs := load_store_regs st;
      offset          := offset st;
      thumb_len       := thumb_len st;
      thumb           := thumb st;

      jitted_len      := S (jitted_len st);
      jitted_list     := jitted_list st;
      jit_mem         := m;
    |}
  | None => None
  end.

(**r input: jitted_start_addr -> jit_state_start_addr -> result *)
Definition compcertbin_signature :=
  {| sig_args := [Tint; Tint]; sig_res := Tint; sig_cc := cc_default |}.

(** We assume two memory address:
   - jit_state_start_address: the start address of jit_state, which in C is a pointer pointing to the global variable `jit_state`
   - jit_arm_start_address: the start address of jitted_arm array, which in C is also a pointer pointing to the field of jit_state: `st.jitted_list` *)
Axiom jit_state_start_address : val.

(** @input
  * @fuel : the size of selected jitted_arm list because of no-loop
  * @ofs  : the location of the selected jitted_arm part in the whole jitted_arm array
  * @sz   : the stack_size allocated accroding to the selected jitted_arm part
  * @st   : the initial jit state

  * @output
  * the updated jit state and
  *)
Definition magic_function (fuel: nat)(ofs sz: int) (st: jit_state): option jit_state :=
  let jitted_arm_address := Val.add (jitted_list st) (Vint (Int.mul ofs (Int.repr 2))) in
  let arm_argu_list_val := [jitted_arm_address; jit_state_start_address] in
    match bin_exec fuel compcertbin_signature (Int.unsigned sz) Ptrofs.zero arm_argu_list_val (jit_mem st) with
    | Some (_, m) => Some (upd_jit_mem m st)
    | None => None
    end.

Definition reset_init_jittedthumb (st: jit_state): jit_state := {|
  jit_pc          := jit_pc st;
  jit_flag        := jit_flag st;
  jit_regs        := jit_regs st;
  jit_mrs_num     := jit_mrs_num st;
  jit_mrs         := jit_mrs st;
  jit_ins_len     := jit_ins_len st;
  jit_ins         := jit_ins   st;

  kv2             := kv2 st;

  use_IR11        := false;
  load_store_regs := init_LoadStoreRegs;
  offset          := 0;
  thumb_len       := 0;
  thumb           := thumb st;

  jitted_len      := jitted_len st;
  jitted_list     := jitted_list st;
  jit_mem         := jit_mem st;
|}.

Definition eval_thumb_ins (idx: int) (st: jit_state): option int := List16.index (thumb st) idx.

Definition eval_key_value2_arm_ofs (key: int) (st: jit_state): option nat :=
  match ListKeyV.index (kv2 st) key with
  | Some kv => Some (arm_ofs kv)
  | None => None
  end.

Definition eval_key_value2_alu32_ofs (key: int) (st: jit_state): option nat :=
  match ListKeyV.index (kv2 st) key with
  | Some kv => Some (alu32_ofs kv)
  | None => None
  end.