From compcert.cfrontend Require Csyntax Ctypes Cop.
From compcert.common Require Import Values Memory AST.
From compcert.lib Require Import Integers.

From bpf.comm Require Import ListAsArray Flag Regs MemRegion rBPFAST.

From Coq Require Import List ZArith.
Import ListNotations.


Record state := mkst {
  pc_loc  : int;
  flag    : val; (**r Vptr flag_blk 0 *)
  regs_st : val; (**r the start address of register map: Vptr regs_blk 0 *)
  mrs_num : nat;  (**r number of memory regions, put it here to guarantee align *)
  bpf_mrs : MyMemRegionsType;
  ins_len : nat;
  ins     : List64AsArray.t;
  bpf_m   : mem;
}.

Definition init_mem: mem := Mem.empty.

Definition init_state: state := {|
  pc_loc  := Int.zero;
  flag    := Vnullptr;
  regs_st := Vnullptr;
  mrs_num := 0;
  bpf_mrs := default_memory_regions;
  ins_len := 0;
  ins     := [];
  bpf_m   := init_mem;
 |}.

Definition eval_pc (st: state): int := pc_loc st.

Definition upd_pc (p: int) (st:state): state := {|
  pc_loc  := p;
  flag    := flag st;
  regs_st := regs_st st;
  mrs_num := mrs_num st;
  bpf_mrs := bpf_mrs st;
  ins_len := ins_len st;
  ins     := ins st;
  bpf_m   := bpf_m st;
|}.

Definition upd_pc_incr (st:state): state := {|
  pc_loc  := Int.add (pc_loc st) Int.one;
  flag    := flag st;
  regs_st := regs_st st;
  mrs_num := mrs_num st;
  bpf_mrs := bpf_mrs st;
  ins_len := ins_len st;
  ins     := ins st;
  bpf_m   := bpf_m st;
|}.

Definition eval_mem_regions (st:state): MyMemRegionsType := bpf_mrs st.

Definition eval_mem (st: state):Mem.mem := bpf_m st.

Definition upd_mem (m: Mem.mem) (st: state): state := {| (**r never be used I guess *)
  pc_loc  := pc_loc st;
  flag    := flag st;
  regs_st := regs_st st;
  mrs_num := mrs_num st;
  bpf_mrs := bpf_mrs st;
  ins_len := ins_len st;
  ins     := ins st;
  bpf_m   := m;
|}.

Definition eval_flag (st:state): option val :=
  Mem.loadv Mint32 (bpf_m st) (flag st).

Definition upd_flag' (f: val) (st:state): option mem :=
  Mem.storev Mint32 (bpf_m st) (flag st) f.

Definition upd_flag (f: val) (st:state): option state :=
  match upd_flag' f st with
  | Some m => Some
    {|
      pc_loc  := pc_loc st;
      flag    := flag st;
      regs_st := regs_st st;
      mrs_num := mrs_num st;
      bpf_mrs := bpf_mrs st;
      ins_len := ins_len st;
      ins     := ins st;
      bpf_m   := m;
    |}
  | None => None
  end.

Definition eval_mem_num (st:state): nat := (mrs_num st). (**r uint32_t -> nat*)

(**r we will assumption the regster map is also in someplace of the bpf_state: Vptr b ofs *)
Definition eval_reg (r: reg) (st:state): option val :=
  let ptr := Val.add (regs_st st) (Vint (Int.repr (8 * id_of_reg r)%Z)) in
    Mem.loadv Mint64 (bpf_m st) ptr.

Definition upd_reg' (r: reg) (v: val) (st:state): option mem :=
  let ptr := Val.add (regs_st st) (Vint (Int.repr (8 * id_of_reg r)%Z)) in
    Mem.storev Mint64 (bpf_m st) ptr v.

Definition upd_reg (r:reg) (v:val) (st:state): option state :=
  match upd_reg' r v st with
  | Some m => Some
    {|
      pc_loc  := pc_loc st;
      flag    := flag st;
      regs_st := regs_st st;
      mrs_num := mrs_num st;
      bpf_mrs := bpf_mrs st;
      ins_len := ins_len st;
      ins     := ins st;
      bpf_m   := m;
    |}
  | None => None
  end.

Definition load_mem (chunk: memory_chunk) (ptr: val) (st: state): option val :=
  match chunk with
  | Mint8unsigned | Mint16unsigned | Mint32 =>
    match Mem.loadv chunk (bpf_m st) ptr with
    | Some res => _to_vlong res
    | None => None
    end
  | Mint64 => Mem.loadv chunk (bpf_m st) ptr
  | _ => None
  end
.

Definition store_mem_imm (ptr: val) (chunk: memory_chunk) (v: val) (st: state): option state :=
  match chunk with
  | Mint8unsigned | Mint16unsigned | Mint32 | Mint64 =>
    let src := vint_to_vint_or_vlong chunk v in
      match Mem.storev chunk (bpf_m st) ptr src with
      | Some m => Some (upd_mem m st)
      | None => None
      end
  | _ => None
  end
.

Definition store_mem_reg (ptr: val) (chunk: memory_chunk) (v: val) (st: state): option state :=
  match chunk with
  | Mint8unsigned | Mint16unsigned | Mint32 | Mint64 =>
    let src := vlong_to_vint_or_vlong chunk v in
    match Mem.storev chunk (bpf_m st) ptr src with
    | Some m => Some (upd_mem m st)
    | None => None
    end
  | _ => None
  end.

Definition eval_ins_len (st: state): int := Int.repr (Z.of_nat (ins_len st)).
Definition eval_ins (idx: int) (st: state): option int64 := List64AsArray.index (ins st) idx.