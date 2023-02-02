From compcert Require Import Integers Memory AST Ctypes.
From Coq Require Import ZArith Ascii String HexString List.

From bpf.comm Require Import Flag Regs BinrBPF rBPFValues ListAsArray.
From bpf.model Require Import Decode PrintrBPF.
From bpf.jit.thumb Require Import JITState ThumbDecode PrintThumb.

Import ListNotations.

(** This module is used for printing jitted arm32 code *)

Record jit_state_string :={
  ibpf_string   : list string;
  jitted_len_nat: nat;
  jitted_string : list string
}.

Definition print_jit_state (st: jit_state) (phyical_start_addr: int): jit_state_string := {|
  ibpf_string     := print_rBPF_prog (decode_prog (jit_ins st) (List.length (jit_ins st)));
  jitted_len_nat  := jitted_len st;
  jitted_string   := print_arm32_prog (arm32_decode_prog (jitted_list st) (jitted_len st) (jit_mem st)) phyical_start_addr;
|}.