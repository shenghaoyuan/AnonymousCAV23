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

From compcert.cfrontend Require Csyntax Ctypes Cop.
From compcert.common Require Import Values Memory AST.
From compcert.lib Require Import Integers.

From bpf.comm Require Import ListAsArray Flag Regs MemRegion rBPFAST.

From Coq Require Import List ZArith.
Import ListNotations.


Record state := mkst {
  pc_loc  : int;  (**r should pc_loc be u32 or s32: because ofs is s16, res = pc_loc+ofs may be negative! we should test res before calculating *)
  flag    : bpf_flag;
  regs_st : regmap;
  mrs_num : nat;  (**r number of memory regions, put it here to guarantee align *)
  bpf_mrs : MyMemRegionsType;
  ins_len : nat;
  ins     : List64AsArray.t;
  bpf_m   : Memory.mem;
}.

Definition init_mem: mem := Mem.empty.

Definition init_state: state := {|
  pc_loc  := Int.zero;
  flag    := BPF_OK;
  regs_st := init_regmap;
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

Definition eval_flag (st:state): bpf_flag := flag st.

Definition upd_flag (f: bpf_flag) (st:state): state := {|
  pc_loc  := pc_loc st;
  flag    := f;
  regs_st := regs_st st;
  mrs_num := mrs_num st;
  bpf_mrs := bpf_mrs st;
  ins_len := ins_len st;
  ins     := ins st;
  bpf_m   := bpf_m st;
|}.

Definition eval_mem_num (st:state): nat := (mrs_num st). (**r uint32_t -> nat*)

Definition eval_reg (r: reg) (st:state): val :=
  eval_regmap r (regs_st st).

Definition upd_reg (r:reg) (v:val) (st:state): state := {|
  pc_loc  := pc_loc st;
  flag    := flag st;
  regs_st := upd_regmap r v (regs_st st);
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
  | _ => None (*Some (upd_flag BPF_ILLEGAL_MEM st)*)
  end.

Definition eval_ins_len (st: state): int := Int.repr (Z.of_nat (ins_len st)).
Definition eval_ins (idx: int) (st: state): option int64 := List64AsArray.index (ins st) idx.