# The synthesis model of rBPF (concrete)

This folder defines a refined model of the synthesis model:
- the state is refined: `flag` and `regs_st` are refined with `Val` type (has the form `Vptr b ofs`)

This model is used to:
1. pre-prepare for the jit compiler.
