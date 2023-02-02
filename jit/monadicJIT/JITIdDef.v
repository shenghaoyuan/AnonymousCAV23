From compcert.common Require AST.
From dx Require Import IRtoC.
From Coq Require Import ZArith String.
Import UserIdentNotations.
Open Scope string.

Definition arm_ofs_id:          AST.ident := $"arm_ofs".
Definition alu32_ofs_id:        AST.ident := $"alu32_ofs".
Definition key_value2_id:       AST.ident := $"key_value2".

Definition pc_loc_id:           AST.ident := $"pc_loc".
Definition flag_id:             AST.ident := $"flag".
Definition regs_st_id:          AST.ident := $"regs_st".
Definition mrs_num_id:          AST.ident := $"mrs_num".
Definition bpf_mrs_id:          AST.ident := $"bpf_mrs".
Definition ins_len_id:          AST.ident := $"ins_len".
Definition jit_ins_id:          AST.ident := $"jit_ins".

Definition kv2_id:              AST.ident := $"kv2".

Definition use_IR11_id:         AST.ident := $"use_IR11".
Definition load_store_regs_id:  AST.ident := $"load_store_regs".
Definition offset_id:           AST.ident := $"offset".
Definition arm32_len_id:        AST.ident := $"arm32_len".
Definition arm32_id:            AST.ident := $"arm32".
Definition jitted_len_id:       AST.ident := $"jitted_len".
Definition jitted_list_id:      AST.ident := $"jitted_list".
Definition jit_state_id:        AST.ident := $"jit_state".
Close Scope string.