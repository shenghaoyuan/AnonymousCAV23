# JIT verifier

Here we need a more limited BPF verifier because of CompCert ARM ISA.

CompCert ARM ISA:

- only supports `UDIV R0 R0 R1`
- doesn't support `SHIFT_IMM`
- no `MOD` semantics

## JITVerifier.v

comparing with `verifier/synthesismodel/verifier_synthesis.v`, we only modify the `alu32_imm/reg` function.


## DxJITVerifier.v

**(JITverifier_dx/JITverifier_TestMain/JITverifier_ExtrMain)** + **repatch/**
The dx configuration part

## JITVerifierProp.v

Two theorems:
- Equivalence between JITVerifier and DxJITVerifer
- JITVerifier implies rBPFVerifier
