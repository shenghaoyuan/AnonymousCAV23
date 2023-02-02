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

From Coq Require Import ZArith Lia.
From compcert Require Import Integers Values AST Memory Memdata.

From bpf.comm Require Import Flag Regs State Monad rBPFMonadOp rBPFMemType rBPFValues.

From bpf.monadicmodel2 Require Import ConcreteState.


Open Scope Z_scope.

(** The file defines the equivalence relation between the abstract synthesis model (monadicmodel/) and the concrete synthesis model (monadicmodel2/) *)

(** * Equivalence Relation: abstract synthesis model ``='' concrete synthesis model *)

Definition match_registers (abs_st: State.state) (concr_st: ConcreteState.state) : Prop :=
  forall (r: reg), exists vl,
    Mem.loadv AST.Mint64 (ConcreteState.bpf_m concr_st) (Val.add (ConcreteState.regs_st concr_st) (Vint (Int.repr (8 * (id_of_reg r))))) = Some (Vlong vl) /\
    Vlong vl = (State.eval_reg r abs_st).

Definition ptr_range_perm (m: mem) (chunk: memory_chunk) (ptr: val) (p: permission): Prop :=
  match ptr with
  | Vptr b ofs => Mem.valid_access m chunk b (Ptrofs.unsigned ofs) p
  | _ => False
  end.

(** The relation consists of:
- Concrete Memory = Abstract Memory + 'flag_blk' + `regs_blk` + `st_blk`: munchange, mperm, minvalid
- Other components are same expect for `flag` and `regs`
  - Concrete flag has the form `Vptr flag_blk 0`: well_form
  - the value of Concrete flag is stored into the `flag_blk` and it is equal to Abstract flags: mflag
  - Concrete regs also has the similar form `Vptr regs_blk 0`: well_form
  - the value of Concrete regs is stored into the `regs_blk` and each Ri in `regs_blk` is equal to each Ri of the Abstract regs: mregs
*)

Section Relation.
  Variable flag_blk: block.
  Variable regs_blk: block.
  Variable st_blk: block.

  Record Rel (abs_st: State.state) (concr_st: ConcreteState.state) : Prop :=
  {
    munchange: Mem.unchanged_on (fun b _ => b <> flag_blk /\ b <> regs_blk /\ b <> st_blk) (State.bpf_m abs_st) (ConcreteState.bpf_m concr_st);
    mpc      : State.pc_loc abs_st = ConcreteState.pc_loc concr_st;
    mflags   : ConcreteState.flag concr_st = Vptr flag_blk Ptrofs.zero /\
                Mem.loadv AST.Mint32 (ConcreteState.bpf_m concr_st) (ConcreteState.flag concr_st) = Some (Vint  (int_of_flag (State.flag abs_st)));
    mregs    : ConcreteState.regs_st concr_st = Vptr regs_blk Ptrofs.zero /\
                match_registers abs_st concr_st;
    mmrs_num : State.mrs_num abs_st = ConcreteState.mrs_num concr_st;
    mbpf_mrs : State.bpf_mrs abs_st = ConcreteState.bpf_mrs concr_st;
    mins_len : State.ins_len abs_st = ConcreteState.ins_len concr_st;
    mins     : State.ins abs_st = ConcreteState.ins concr_st;
    mperm    : ptr_range_perm (ConcreteState.bpf_m concr_st) Mint32 (ConcreteState.flag concr_st) Freeable /\
               (forall r, ptr_range_perm (ConcreteState.bpf_m concr_st) Mint64 (Val.add (ConcreteState.regs_st concr_st) (Vint (Int.repr (8 * (id_of_reg r))))) Freeable);
    minvalid : ~Mem.valid_block (State.bpf_m abs_st) flag_blk /\
               ~Mem.valid_block (State.bpf_m abs_st) regs_blk /\
               ~Mem.valid_block (State.bpf_m abs_st) st_blk /\
               (flag_blk <> regs_blk /\ flag_blk <> st_blk /\ regs_blk <> st_blk) /\
               (forall b, b <> flag_blk /\ b <> regs_blk /\ b <> st_blk ->
                Mem.valid_block (ConcreteState.bpf_m concr_st) b -> Mem.valid_block (State.bpf_m abs_st) b);
  }.
End Relation.