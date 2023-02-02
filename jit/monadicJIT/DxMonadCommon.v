From compcert Require Import Memory Memtype Integers Values Ctypes AST.
From Coq Require Import ZArith Lia.

From bpf.comm Require Import BinrBPF Regs.
From bpf.dxcomm Require Import DxIntegers DxNat.
From bpf.jit.monadicJIT Require Import DxJITMonad.

Open Scope Z_scope.
Open Scope monad_scope.

Definition get_immediate (ins: int64):M sint32_t := returnM (get_immediate ins).

Definition get_offset (ins: int64):M sint32_t := returnM (get_offset ins).

Definition get_opcode_ins (ins: int64): M nat8 := returnM (get_opcode ins).

Close Scope monad_scope.
Close Scope Z_scope.