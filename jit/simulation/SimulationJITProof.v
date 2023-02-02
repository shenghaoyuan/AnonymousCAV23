From Coq Require Import List ZArith Lia.
From compcert Require Import Integers Values AST Memory Memdata.

From bpf.comm Require Import Flag Regs State Monad rBPFMonadOp rBPFMemType rBPFValues LemmaInt.

From bpf.monadicmodel2 Require Import ConcreteState rBPFInterpreter2.
(*
From bpf.isolation Require Import MemInv. *)

From bpf.jit.thumb Require Import JITState ThumbJIT.
From bpf.jit.iBPF Require Import ISemantics.
From bpf.jit.simulation Require Import BitfieldLemma SimulationJIT StepAlu32.

From bpf.jit.thumb Require Import KeyValue2 ThumbEncode ThumbDecode ThumbInsOp Arm32Reg ThumbJIT.
From compcert.arm Require Import AsmSyntax BinSyntax.

(**


rbpf_step sti = Some (tt, sti') ->
RelJIT sti stj (*jit_alu32 stj = Some (tt, stj'') -> *) ->
  exists stj', ibpf_step stj = Some (tt, stj').

sti    --------------- R ------------- (stj, sta)
         \
 |          \                              |
 |              \                          |
 |                  \  R'                  |
 |                      \             Save | Load
 |                          \              |
 |                              \          |
 |                                  \      |
 |                                      \
 |                                    (stj, sta')
 |
 | (alu_1)                                 |
 |                                         |
 |                                         |
 |                                         | (arm_alu_1)
 |                                         |
 |                                         |
 |                                         |
 |
 |                                    (stj, sta'')

 |                                     /   |
 |                                 /       |
 |                        R‘  /            |
 |                     /             Store | Reset
 |               /                         |
 |         /                               |
 |    /                                    |

st_i' --------------- R ------------- (stj', sta)
*)


Lemma step_alu32_sim:
  forall flag_blk regs_blk jit_blk sti stj sta sti' kv res
    (Hbefore: Rel flag_blk regs_blk jit_blk sti stj sta)
    (**r jit_alu32 *)
    (Hkv: ListKeyV.index (kv2 stj) (jit_pc stj) = Some kv)
    (Hrbpf: step_alu32 (alu32_ofs kv) sti = Some (res, sti')),
    exists stj', ibpf_step stj = Some (tt, stj') /\
      Rel flag_blk regs_blk jit_blk sti' stj' sta.
