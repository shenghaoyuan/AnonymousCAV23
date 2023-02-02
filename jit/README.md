# Simulation Relation

There are two simulation relations:

- `match_jit_intp_state`: the simulation relation between the JIT Coq model and the CertrBPF-Interpreter Coq model, it shows that CertrBPF-JIT and CertrBPF-Interpreter are behaviour-equivalent

- `match_jit_c_state`: between the JIT Coq model and the JIT C implementation, this part is trivial because we will reuse most of CertrBPF-Interpreter proofs.
