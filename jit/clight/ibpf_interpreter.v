From Coq Require Import String List ZArith.
From compcert Require Import Coqlib Integers Floats AST Ctypes Cop Clight Clightdefs.
Import Clightdefs.ClightNotations.
Local Open Scope Z_scope.
Local Open Scope string_scope.
Local Open Scope clight_scope.

Module Info.
  Definition version := "3.11".
  Definition build_number := "".
  Definition build_tag := "".
  Definition build_branch := "".
  Definition arch := "arm".
  Definition model := "armv7a".
  Definition abi := "eabi".
  Definition bitsize := 32.
  Definition big_endian := false.
  Definition source_file := "ibpf_interpreter.c".
  Definition normalized := false.
End Info.

Definition ___builtin_ais_annot : ident := $"__builtin_ais_annot".
Definition ___builtin_annot : ident := $"__builtin_annot".
Definition ___builtin_annot_intval : ident := $"__builtin_annot_intval".
Definition ___builtin_bswap : ident := $"__builtin_bswap".
Definition ___builtin_bswap16 : ident := $"__builtin_bswap16".
Definition ___builtin_bswap32 : ident := $"__builtin_bswap32".
Definition ___builtin_bswap64 : ident := $"__builtin_bswap64".
Definition ___builtin_clz : ident := $"__builtin_clz".
Definition ___builtin_clzl : ident := $"__builtin_clzl".
Definition ___builtin_clzll : ident := $"__builtin_clzll".
Definition ___builtin_ctz : ident := $"__builtin_ctz".
Definition ___builtin_ctzl : ident := $"__builtin_ctzl".
Definition ___builtin_ctzll : ident := $"__builtin_ctzll".
Definition ___builtin_debug : ident := $"__builtin_debug".
Definition ___builtin_dmb : ident := $"__builtin_dmb".
Definition ___builtin_dsb : ident := $"__builtin_dsb".
Definition ___builtin_expect : ident := $"__builtin_expect".
Definition ___builtin_fabs : ident := $"__builtin_fabs".
Definition ___builtin_fabsf : ident := $"__builtin_fabsf".
Definition ___builtin_fsqrt : ident := $"__builtin_fsqrt".
Definition ___builtin_isb : ident := $"__builtin_isb".
Definition ___builtin_membar : ident := $"__builtin_membar".
Definition ___builtin_memcpy_aligned : ident := $"__builtin_memcpy_aligned".
Definition ___builtin_read16_reversed : ident := $"__builtin_read16_reversed".
Definition ___builtin_read32_reversed : ident := $"__builtin_read32_reversed".
Definition ___builtin_sel : ident := $"__builtin_sel".
Definition ___builtin_sqrt : ident := $"__builtin_sqrt".
Definition ___builtin_unreachable : ident := $"__builtin_unreachable".
Definition ___builtin_va_arg : ident := $"__builtin_va_arg".
Definition ___builtin_va_copy : ident := $"__builtin_va_copy".
Definition ___builtin_va_end : ident := $"__builtin_va_end".
Definition ___builtin_va_start : ident := $"__builtin_va_start".
Definition ___builtin_write16_reversed : ident := $"__builtin_write16_reversed".
Definition ___builtin_write32_reversed : ident := $"__builtin_write32_reversed".
Definition ___compcert_i64_dtos : ident := $"__compcert_i64_dtos".
Definition ___compcert_i64_dtou : ident := $"__compcert_i64_dtou".
Definition ___compcert_i64_sar : ident := $"__compcert_i64_sar".
Definition ___compcert_i64_sdiv : ident := $"__compcert_i64_sdiv".
Definition ___compcert_i64_shl : ident := $"__compcert_i64_shl".
Definition ___compcert_i64_shr : ident := $"__compcert_i64_shr".
Definition ___compcert_i64_smod : ident := $"__compcert_i64_smod".
Definition ___compcert_i64_smulh : ident := $"__compcert_i64_smulh".
Definition ___compcert_i64_stod : ident := $"__compcert_i64_stod".
Definition ___compcert_i64_stof : ident := $"__compcert_i64_stof".
Definition ___compcert_i64_udiv : ident := $"__compcert_i64_udiv".
Definition ___compcert_i64_umod : ident := $"__compcert_i64_umod".
Definition ___compcert_i64_umulh : ident := $"__compcert_i64_umulh".
Definition ___compcert_i64_utod : ident := $"__compcert_i64_utod".
Definition ___compcert_i64_utof : ident := $"__compcert_i64_utof".
Definition ___compcert_va_composite : ident := $"__compcert_va_composite".
Definition ___compcert_va_float64 : ident := $"__compcert_va_float64".
Definition ___compcert_va_int32 : ident := $"__compcert_va_int32".
Definition ___compcert_va_int64 : ident := $"__compcert_va_int64".
Definition ___stringlit_1 : ident := $"__stringlit_1".
Definition ___stringlit_10 : ident := $"__stringlit_10".
Definition ___stringlit_11 : ident := $"__stringlit_11".
Definition ___stringlit_12 : ident := $"__stringlit_12".
Definition ___stringlit_13 : ident := $"__stringlit_13".
Definition ___stringlit_14 : ident := $"__stringlit_14".
Definition ___stringlit_15 : ident := $"__stringlit_15".
Definition ___stringlit_16 : ident := $"__stringlit_16".
Definition ___stringlit_17 : ident := $"__stringlit_17".
Definition ___stringlit_18 : ident := $"__stringlit_18".
Definition ___stringlit_19 : ident := $"__stringlit_19".
Definition ___stringlit_2 : ident := $"__stringlit_2".
Definition ___stringlit_20 : ident := $"__stringlit_20".
Definition ___stringlit_21 : ident := $"__stringlit_21".
Definition ___stringlit_22 : ident := $"__stringlit_22".
Definition ___stringlit_23 : ident := $"__stringlit_23".
Definition ___stringlit_24 : ident := $"__stringlit_24".
Definition ___stringlit_25 : ident := $"__stringlit_25".
Definition ___stringlit_26 : ident := $"__stringlit_26".
Definition ___stringlit_27 : ident := $"__stringlit_27".
Definition ___stringlit_28 : ident := $"__stringlit_28".
Definition ___stringlit_29 : ident := $"__stringlit_29".
Definition ___stringlit_3 : ident := $"__stringlit_3".
Definition ___stringlit_30 : ident := $"__stringlit_30".
Definition ___stringlit_31 : ident := $"__stringlit_31".
Definition ___stringlit_32 : ident := $"__stringlit_32".
Definition ___stringlit_33 : ident := $"__stringlit_33".
Definition ___stringlit_34 : ident := $"__stringlit_34".
Definition ___stringlit_35 : ident := $"__stringlit_35".
Definition ___stringlit_36 : ident := $"__stringlit_36".
Definition ___stringlit_37 : ident := $"__stringlit_37".
Definition ___stringlit_38 : ident := $"__stringlit_38".
Definition ___stringlit_39 : ident := $"__stringlit_39".
Definition ___stringlit_4 : ident := $"__stringlit_4".
Definition ___stringlit_40 : ident := $"__stringlit_40".
Definition ___stringlit_41 : ident := $"__stringlit_41".
Definition ___stringlit_42 : ident := $"__stringlit_42".
Definition ___stringlit_43 : ident := $"__stringlit_43".
Definition ___stringlit_44 : ident := $"__stringlit_44".
Definition ___stringlit_45 : ident := $"__stringlit_45".
Definition ___stringlit_46 : ident := $"__stringlit_46".
Definition ___stringlit_47 : ident := $"__stringlit_47".
Definition ___stringlit_48 : ident := $"__stringlit_48".
Definition ___stringlit_49 : ident := $"__stringlit_49".
Definition ___stringlit_5 : ident := $"__stringlit_5".
Definition ___stringlit_50 : ident := $"__stringlit_50".
Definition ___stringlit_51 : ident := $"__stringlit_51".
Definition ___stringlit_52 : ident := $"__stringlit_52".
Definition ___stringlit_53 : ident := $"__stringlit_53".
Definition ___stringlit_54 : ident := $"__stringlit_54".
Definition ___stringlit_55 : ident := $"__stringlit_55".
Definition ___stringlit_56 : ident := $"__stringlit_56".
Definition ___stringlit_57 : ident := $"__stringlit_57".
Definition ___stringlit_58 : ident := $"__stringlit_58".
Definition ___stringlit_59 : ident := $"__stringlit_59".
Definition ___stringlit_6 : ident := $"__stringlit_6".
Definition ___stringlit_60 : ident := $"__stringlit_60".
Definition ___stringlit_61 : ident := $"__stringlit_61".
Definition ___stringlit_62 : ident := $"__stringlit_62".
Definition ___stringlit_63 : ident := $"__stringlit_63".
Definition ___stringlit_64 : ident := $"__stringlit_64".
Definition ___stringlit_65 : ident := $"__stringlit_65".
Definition ___stringlit_66 : ident := $"__stringlit_66".
Definition ___stringlit_67 : ident := $"__stringlit_67".
Definition ___stringlit_68 : ident := $"__stringlit_68".
Definition ___stringlit_69 : ident := $"__stringlit_69".
Definition ___stringlit_7 : ident := $"__stringlit_7".
Definition ___stringlit_70 : ident := $"__stringlit_70".
Definition ___stringlit_71 : ident := $"__stringlit_71".
Definition ___stringlit_72 : ident := $"__stringlit_72".
Definition ___stringlit_73 : ident := $"__stringlit_73".
Definition ___stringlit_74 : ident := $"__stringlit_74".
Definition ___stringlit_75 : ident := $"__stringlit_75".
Definition ___stringlit_76 : ident := $"__stringlit_76".
Definition ___stringlit_77 : ident := $"__stringlit_77".
Definition ___stringlit_78 : ident := $"__stringlit_78".
Definition ___stringlit_79 : ident := $"__stringlit_79".
Definition ___stringlit_8 : ident := $"__stringlit_8".
Definition ___stringlit_80 : ident := $"__stringlit_80".
Definition ___stringlit_81 : ident := $"__stringlit_81".
Definition ___stringlit_82 : ident := $"__stringlit_82".
Definition ___stringlit_83 : ident := $"__stringlit_83".
Definition ___stringlit_84 : ident := $"__stringlit_84".
Definition ___stringlit_85 : ident := $"__stringlit_85".
Definition ___stringlit_86 : ident := $"__stringlit_86".
Definition ___stringlit_87 : ident := $"__stringlit_87".
Definition ___stringlit_88 : ident := $"__stringlit_88".
Definition ___stringlit_89 : ident := $"__stringlit_89".
Definition ___stringlit_9 : ident := $"__stringlit_9".
Definition ___stringlit_90 : ident := $"__stringlit_90".
Definition ___stringlit_91 : ident := $"__stringlit_91".
Definition __bpf_get_call : ident := $"_bpf_get_call".
Definition __magic_function : ident := $"_magic_function".
Definition _add_ins_jittedthumb : ident := $"add_ins_jittedthumb".
Definition _add_key_value2 : ident := $"add_key_value2".
Definition _addr : ident := $"addr".
Definition _addr_ptr : ident := $"addr_ptr".
Definition _alu32_ofs : ident := $"alu32_ofs".
Definition _arm_ofs : ident := $"arm_ofs".
Definition _asr_hi : ident := $"asr_hi".
Definition _asr_lo : ident := $"asr_lo".
Definition _b : ident := $"b".
Definition _b0 : ident := $"b0".
Definition _b1 : ident := $"b1".
Definition _b10 : ident := $"b10".
Definition _b2 : ident := $"b2".
Definition _b3 : ident := $"b3".
Definition _b4 : ident := $"b4".
Definition _b5 : ident := $"b5".
Definition _b6 : ident := $"b6".
Definition _b7 : ident := $"b7".
Definition _b8 : ident := $"b8".
Definition _b9 : ident := $"b9".
Definition _b_lt : ident := $"b_lt".
Definition _b_ne : ident := $"b_ne".
Definition _b_r1 : ident := $"b_r1".
Definition _block_perm : ident := $"block_perm".
Definition _block_ptr : ident := $"block_ptr".
Definition _block_size : ident := $"block_size".
Definition _bpf_alu32_to_thumb : ident := $"bpf_alu32_to_thumb".
Definition _bpf_alu32_to_thumb_imm : ident := $"bpf_alu32_to_thumb_imm".
Definition _bpf_alu32_to_thumb_reg : ident := $"bpf_alu32_to_thumb_reg".
Definition _bpf_mrs : ident := $"bpf_mrs".
Definition _cd : ident := $"cd".
Definition _check_mem : ident := $"check_mem".
Definition _check_mem__1 : ident := $"check_mem__1".
Definition _check_mem_aux : ident := $"check_mem_aux".
Definition _check_mem_aux2 : ident := $"check_mem_aux2".
Definition _chunk : ident := $"chunk".
Definition _cmp_lo : ident := $"cmp_lo".
Definition _cmp_ptr32_nullM : ident := $"cmp_ptr32_nullM".
Definition _construct_thumb2_shift_rd_rm : ident := $"construct_thumb2_shift_rd_rm".
Definition _construct_thumb_b : ident := $"construct_thumb_b".
Definition _copy_thumb_list_from_to : ident := $"copy_thumb_list_from_to".
Definition _copy_thumb_list_from_to_aux : ident := $"copy_thumb_list_from_to_aux".
Definition _cur_mr : ident := $"cur_mr".
Definition _d : ident := $"d".
Definition _decode_thumb : ident := $"decode_thumb".
Definition _dst : ident := $"dst".
Definition _dst64 : ident := $"dst64".
Definition _encode_thumb : ident := $"encode_thumb".
Definition _entry_point : ident := $"entry_point".
Definition _eval_flag : ident := $"eval_flag".
Definition _eval_immediate : ident := $"eval_immediate".
Definition _eval_ins : ident := $"eval_ins".
Definition _eval_ins_len : ident := $"eval_ins_len".
Definition _eval_jitted_len : ident := $"eval_jitted_len".
Definition _eval_key_value2_alu32_ofs : ident := $"eval_key_value2_alu32_ofs".
Definition _eval_key_value2_arm_ofs : ident := $"eval_key_value2_arm_ofs".
Definition _eval_mrs_num : ident := $"eval_mrs_num".
Definition _eval_mrs_regions : ident := $"eval_mrs_regions".
Definition _eval_offset : ident := $"eval_offset".
Definition _eval_pc : ident := $"eval_pc".
Definition _eval_reg : ident := $"eval_reg".
Definition _eval_thumb_ins : ident := $"eval_thumb_ins".
Definition _eval_thumb_len : ident := $"eval_thumb_len".
Definition _eval_use_IR11 : ident := $"eval_use_IR11".
Definition _exec_function : ident := $"exec_function".
Definition _f : ident := $"f".
Definition _f_ptr : ident := $"f_ptr".
Definition _flag : ident := $"flag".
Definition _from : ident := $"from".
Definition _fuel : ident := $"fuel".
Definition _fuel0 : ident := $"fuel0".
Definition _get_add : ident := $"get_add".
Definition _get_addr_ofs : ident := $"get_addr_ofs".
Definition _get_block_perm : ident := $"get_block_perm".
Definition _get_block_size : ident := $"get_block_size".
Definition _get_dst : ident := $"get_dst".
Definition _get_immediate : ident := $"get_immediate".
Definition _get_mem_region : ident := $"get_mem_region".
Definition _get_offset : ident := $"get_offset".
Definition _get_opcode : ident := $"get_opcode".
Definition _get_opcode_alu32 : ident := $"get_opcode_alu32".
Definition _get_opcode_alu64 : ident := $"get_opcode_alu64".
Definition _get_opcode_branch : ident := $"get_opcode_branch".
Definition _get_opcode_ins : ident := $"get_opcode_ins".
Definition _get_opcode_mem_ld_imm : ident := $"get_opcode_mem_ld_imm".
Definition _get_opcode_mem_ld_reg : ident := $"get_opcode_mem_ld_reg".
Definition _get_opcode_mem_st_imm : ident := $"get_opcode_mem_st_imm".
Definition _get_opcode_mem_st_reg : ident := $"get_opcode_mem_st_reg".
Definition _get_src : ident := $"get_src".
Definition _get_src64 : ident := $"get_src64".
Definition _get_start_addr : ident := $"get_start_addr".
Definition _get_store_ins_num : ident := $"get_store_ins_num".
Definition _get_sub : ident := $"get_sub".
Definition _hi_32 : ident := $"hi_32".
Definition _hi_i : ident := $"hi_i".
Definition _hi_imm3 : ident := $"hi_imm3".
Definition _hi_imm4 : ident := $"hi_imm4".
Definition _hi_imm8 : ident := $"hi_imm8".
Definition _hi_ofs : ident := $"hi_ofs".
Definition _history : ident := $"history".
Definition _i : ident := $"i".
Definition _ibpf_interpreter : ident := $"ibpf_interpreter".
Definition _ibpf_interpreter_aux : ident := $"ibpf_interpreter_aux".
Definition _idx : ident := $"idx".
Definition _imm : ident := $"imm".
Definition _imm12 : ident := $"imm12".
Definition _imm32 : ident := $"imm32".
Definition _imm64 : ident := $"imm64".
Definition _imm8 : ident := $"imm8".
Definition _ins : ident := $"ins".
Definition _ins0 : ident := $"ins0".
Definition _ins_hi : ident := $"ins_hi".
Definition _ins_hi0 : ident := $"ins_hi0".
Definition _ins_imm8 : ident := $"ins_imm8".
Definition _ins_is_bpf_alu32 : ident := $"ins_is_bpf_alu32".
Definition _ins_is_bpf_jump : ident := $"ins_is_bpf_jump".
Definition _ins_len : ident := $"ins_len".
Definition _ins_lo : ident := $"ins_lo".
Definition _ins_mov : ident := $"ins_mov".
Definition _ins_rd : ident := $"ins_rd".
Definition _ins_rdn : ident := $"ins_rdn".
Definition _ins_rm : ident := $"ins_rm".
Definition _int_r : ident := $"int_r".
Definition _ir : ident := $"ir".
Definition _is_load_reg : ident := $"is_load_reg".
Definition _is_non_reg : ident := $"is_non_reg".
Definition _is_null : ident := $"is_null".
Definition _is_store_reg : ident := $"is_store_reg".
Definition _is_well_chunk_bool : ident := $"is_well_chunk_bool".
Definition _jit_alu32 : ident := $"jit_alu32".
Definition _jit_alu32_aux : ident := $"jit_alu32_aux".
Definition _jit_alu32_post : ident := $"jit_alu32_post".
Definition _jit_alu32_pre : ident := $"jit_alu32_pre".
Definition _jit_alu32_store_flag : ident := $"jit_alu32_store_flag".
Definition _jit_alu32_thumb_load : ident := $"jit_alu32_thumb_load".
Definition _jit_alu32_thumb_load_template_ins : ident := $"jit_alu32_thumb_load_template_ins".
Definition _jit_alu32_thumb_load_template_jit : ident := $"jit_alu32_thumb_load_template_jit".
Definition _jit_alu32_thumb_reset : ident := $"jit_alu32_thumb_reset".
Definition _jit_alu32_thumb_save : ident := $"jit_alu32_thumb_save".
Definition _jit_alu32_thumb_store : ident := $"jit_alu32_thumb_store".
Definition _jit_alu32_thumb_store_template_ins : ident := $"jit_alu32_thumb_store_template_ins".
Definition _jit_alu32_thumb_store_template_jit : ident := $"jit_alu32_thumb_store_template_jit".
Definition _jit_alu32_thumb_upd_load : ident := $"jit_alu32_thumb_upd_load".
Definition _jit_alu32_thumb_upd_reset : ident := $"jit_alu32_thumb_upd_reset".
Definition _jit_alu32_thumb_upd_save : ident := $"jit_alu32_thumb_upd_save".
Definition _jit_alu32_thumb_upd_store : ident := $"jit_alu32_thumb_upd_store".
Definition _jit_alu32_to_thumb : ident := $"jit_alu32_to_thumb".
Definition _jit_alu32_to_thumb_pass1 : ident := $"jit_alu32_to_thumb_pass1".
Definition _jit_alu32_to_thumb_pass2 : ident := $"jit_alu32_to_thumb_pass2".
Definition _jit_alu32_to_thumb_pass2_aux : ident := $"jit_alu32_to_thumb_pass2_aux".
Definition _jit_ins : ident := $"jit_ins".
Definition _jit_state : ident := $"jit_state".
Definition _jitted_len : ident := $"jitted_len".
Definition _jitted_list : ident := $"jitted_list".
Definition _key : ident := $"key".
Definition _key_value2 : ident := $"key_value2".
Definition _kv2 : ident := $"kv2".
Definition _len : ident := $"len".
Definition _len0 : ident := $"len0".
Definition _lo_i : ident := $"lo_i".
Definition _lo_imm3 : ident := $"lo_imm3".
Definition _lo_imm4 : ident := $"lo_imm4".
Definition _lo_imm8 : ident := $"lo_imm8".
Definition _lo_ofs : ident := $"lo_ofs".
Definition _load_mem : ident := $"load_mem".
Definition _load_store_regs : ident := $"load_store_regs".
Definition _ls : ident := $"ls".
Definition _lsl_hi : ident := $"lsl_hi".
Definition _lsl_lo : ident := $"lsl_lo".
Definition _lsr_hi : ident := $"lsr_hi".
Definition _lsr_lo : ident := $"lsr_lo".
Definition _magic_function : ident := $"magic_function".
Definition _main : ident := $"main".
Definition _mask : ident := $"mask".
Definition _mem_reg_num : ident := $"mem_reg_num".
Definition _memory_region : ident := $"memory_region".
Definition _mov_int_to_reg_binary : ident := $"mov_int_to_reg_binary".
Definition _movt_hi : ident := $"movt_hi".
Definition _movt_hi_0 : ident := $"movt_hi_0".
Definition _movt_lo : ident := $"movt_lo".
Definition _movt_lo_0 : ident := $"movt_lo_0".
Definition _movw_hi : ident := $"movw_hi".
Definition _movw_hi_0 : ident := $"movw_hi_0".
Definition _movw_lo : ident := $"movw_lo".
Definition _movw_lo_0 : ident := $"movw_lo_0".
Definition _mr : ident := $"mr".
Definition _mr_perm : ident := $"mr_perm".
Definition _mrs : ident := $"mrs".
Definition _mrs_num : ident := $"mrs_num".
Definition _n : ident := $"n".
Definition _n0 : ident := $"n0".
Definition _n1 : ident := $"n1".
Definition _n2 : ident := $"n2".
Definition _n3 : ident := $"n3".
Definition _n4 : ident := $"n4".
Definition _n5 : ident := $"n5".
Definition _n6 : ident := $"n6".
Definition _n7 : ident := $"n7".
Definition _n8 : ident := $"n8".
Definition _n9 : ident := $"n9".
Definition _nat_to_opcode_alu32 : ident := $"nat_to_opcode_alu32".
Definition _nat_to_opcode_alu32_imm : ident := $"nat_to_opcode_alu32_imm".
Definition _nat_to_opcode_alu32_reg : ident := $"nat_to_opcode_alu32_reg".
Definition _next_ins : ident := $"next_ins".
Definition _next_pc : ident := $"next_pc".
Definition _no_reg_load : ident := $"no_reg_load".
Definition _num : ident := $"num".
Definition _offset : ident := $"offset".
Definition _ofs : ident := $"ofs".
Definition _ofs0 : ident := $"ofs0".
Definition _ofs1 : ident := $"ofs1".
Definition _op : ident := $"op".
Definition _opc : ident := $"opc".
Definition _opcode_alu32 : ident := $"opcode_alu32".
Definition _opcode_alu64 : ident := $"opcode_alu64".
Definition _opcode_jmp : ident := $"opcode_jmp".
Definition _opcode_ld : ident := $"opcode_ld".
Definition _opcode_reg_of_imm : ident := $"opcode_reg_of_imm".
Definition _opcode_st : ident := $"opcode_st".
Definition _opi : ident := $"opi".
Definition _opk : ident := $"opk".
Definition _opr : ident := $"opr".
Definition _pc : ident := $"pc".
Definition _pc0 : ident := $"pc0".
Definition _pc_loc : ident := $"pc_loc".
Definition _perm : ident := $"perm".
Definition _power2 : ident := $"power2".
Definition _pre_is_alu32 : ident := $"pre_is_alu32".
Definition _print_bpf_insstruction : ident := $"print_bpf_insstruction".
Definition _print_ibpf : ident := $"print_ibpf".
Definition _print_jit_state : ident := $"print_jit_state".
Definition _print_jit_state_all : ident := $"print_jit_state_all".
Definition _print_jitted_arm : ident := $"print_jitted_arm".
Definition _print_load_store_regs : ident := $"print_load_store_regs".
Definition _print_reg : ident := $"print_reg".
Definition _print_thumb : ident := $"print_thumb".
Definition _print_u64_dec : ident := $"print_u64_dec".
Definition _printf : ident := $"printf".
Definition _ptr : ident := $"ptr".
Definition _r : ident := $"r".
Definition _rd : ident := $"rd".
Definition _rdn : ident := $"rdn".
Definition _reg64_to_reg32 : ident := $"reg64_to_reg32".
Definition _reg_of_ireg : ident := $"reg_of_ireg".
Definition _regs_st : ident := $"regs_st".
Definition _res : ident := $"res".
Definition _reset_init_jittedthumb : ident := $"reset_init_jittedthumb".
Definition _rm : ident := $"rm".
Definition _rn : ident := $"rn".
Definition _rt : ident := $"rt".
Definition _size : ident := $"size".
Definition _src : ident := $"src".
Definition _src32 : ident := $"src32".
Definition _src64 : ident := $"src64".
Definition _st : ident := $"st".
Definition _start : ident := $"start".
Definition _start_addr : ident := $"start_addr".
Definition _step : ident := $"step".
Definition _step_opcode_alu32 : ident := $"step_opcode_alu32".
Definition _step_opcode_alu64 : ident := $"step_opcode_alu64".
Definition _step_opcode_branch : ident := $"step_opcode_branch".
Definition _step_opcode_mem_ld_imm : ident := $"step_opcode_mem_ld_imm".
Definition _step_opcode_mem_ld_reg : ident := $"step_opcode_mem_ld_reg".
Definition _step_opcode_mem_st_imm : ident := $"step_opcode_mem_st_imm".
Definition _step_opcode_mem_st_reg : ident := $"step_opcode_mem_st_reg".
Definition _store_len : ident := $"store_len".
Definition _store_mem_imm : ident := $"store_mem_imm".
Definition _store_mem_reg : ident := $"store_mem_reg".
Definition _str_high : ident := $"str_high".
Definition _str_low : ident := $"str_low".
Definition _thumb : ident := $"thumb".
Definition _thumb_len : ident := $"thumb_len".
Definition _upd_IR11_jittedthumb : ident := $"upd_IR11_jittedthumb".
Definition _upd_bpf_offset_jittedthumb : ident := $"upd_bpf_offset_jittedthumb".
Definition _upd_flag : ident := $"upd_flag".
Definition _upd_jitted_list : ident := $"upd_jitted_list".
Definition _upd_load_store_regs_jittedthumb : ident := $"upd_load_store_regs_jittedthumb".
Definition _upd_pc : ident := $"upd_pc".
Definition _upd_pc_incr : ident := $"upd_pc_incr".
Definition _upd_reg : ident := $"upd_reg".
Definition _upd_thumb_jittedthumb : ident := $"upd_thumb_jittedthumb".
Definition _use_IR11 : ident := $"use_IR11".
Definition _v : ident := $"v".
Definition _well_chunk : ident := $"well_chunk".
Definition _width : ident := $"width".
Definition _x : ident := $"x".
Definition _y : ident := $"y".
Definition _t'1 : ident := 128%positive.
Definition _t'10 : ident := 137%positive.
Definition _t'11 : ident := 138%positive.
Definition _t'12 : ident := 139%positive.
Definition _t'13 : ident := 140%positive.
Definition _t'14 : ident := 141%positive.
Definition _t'15 : ident := 142%positive.
Definition _t'16 : ident := 143%positive.
Definition _t'17 : ident := 144%positive.
Definition _t'18 : ident := 145%positive.
Definition _t'19 : ident := 146%positive.
Definition _t'2 : ident := 129%positive.
Definition _t'20 : ident := 147%positive.
Definition _t'21 : ident := 148%positive.
Definition _t'22 : ident := 149%positive.
Definition _t'23 : ident := 150%positive.
Definition _t'24 : ident := 151%positive.
Definition _t'25 : ident := 152%positive.
Definition _t'26 : ident := 153%positive.
Definition _t'27 : ident := 154%positive.
Definition _t'28 : ident := 155%positive.
Definition _t'29 : ident := 156%positive.
Definition _t'3 : ident := 130%positive.
Definition _t'30 : ident := 157%positive.
Definition _t'31 : ident := 158%positive.
Definition _t'32 : ident := 159%positive.
Definition _t'33 : ident := 160%positive.
Definition _t'34 : ident := 161%positive.
Definition _t'35 : ident := 162%positive.
Definition _t'36 : ident := 163%positive.
Definition _t'37 : ident := 164%positive.
Definition _t'38 : ident := 165%positive.
Definition _t'39 : ident := 166%positive.
Definition _t'4 : ident := 131%positive.
Definition _t'40 : ident := 167%positive.
Definition _t'41 : ident := 168%positive.
Definition _t'42 : ident := 169%positive.
Definition _t'43 : ident := 170%positive.
Definition _t'44 : ident := 171%positive.
Definition _t'45 : ident := 172%positive.
Definition _t'46 : ident := 173%positive.
Definition _t'47 : ident := 174%positive.
Definition _t'48 : ident := 175%positive.
Definition _t'49 : ident := 176%positive.
Definition _t'5 : ident := 132%positive.
Definition _t'50 : ident := 177%positive.
Definition _t'51 : ident := 178%positive.
Definition _t'6 : ident := 133%positive.
Definition _t'7 : ident := 134%positive.
Definition _t'8 : ident := 135%positive.
Definition _t'9 : ident := 136%positive.

Definition v___stringlit_69 := {|
  gvar_info := (tarray tuchar 6);
  gvar_init := (Init_int8 (Int.repr 40) :: Init_int8 (Int.repr 82) ::
                Init_int8 (Int.repr 49) :: Init_int8 (Int.repr 41) ::
                Init_int8 (Int.repr 10) :: Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_26 := {|
  gvar_info := (tarray tuchar 11);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 115) :: Init_int8 (Int.repr 116) ::
                Init_int8 (Int.repr 120) :: Init_int8 (Int.repr 104) ::
                Init_int8 (Int.repr 32) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_77 := {|
  gvar_info := (tarray tuchar 6);
  gvar_init := (Init_int8 (Int.repr 40) :: Init_int8 (Int.repr 82) ::
                Init_int8 (Int.repr 57) :: Init_int8 (Int.repr 41) ::
                Init_int8 (Int.repr 10) :: Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_32 := {|
  gvar_info := (tarray tuchar 11);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 108) :: Init_int8 (Int.repr 100) ::
                Init_int8 (Int.repr 120) :: Init_int8 (Int.repr 100) ::
                Init_int8 (Int.repr 119) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_51 := {|
  gvar_info := (tarray tuchar 11);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 97) :: Init_int8 (Int.repr 100) ::
                Init_int8 (Int.repr 100) :: Init_int8 (Int.repr 51) ::
                Init_int8 (Int.repr 50) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_63 := {|
  gvar_info := (tarray tuchar 11);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 109) :: Init_int8 (Int.repr 117) ::
                Init_int8 (Int.repr 108) :: Init_int8 (Int.repr 54) ::
                Init_int8 (Int.repr 52) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_74 := {|
  gvar_info := (tarray tuchar 6);
  gvar_init := (Init_int8 (Int.repr 40) :: Init_int8 (Int.repr 82) ::
                Init_int8 (Int.repr 54) :: Init_int8 (Int.repr 41) ::
                Init_int8 (Int.repr 10) :: Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_9 := {|
  gvar_info := (tarray tuchar 10);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 106) :: Init_int8 (Int.repr 115) ::
                Init_int8 (Int.repr 108) :: Init_int8 (Int.repr 116) ::
                Init_int8 (Int.repr 32) :: Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_72 := {|
  gvar_info := (tarray tuchar 6);
  gvar_init := (Init_int8 (Int.repr 40) :: Init_int8 (Int.repr 82) ::
                Init_int8 (Int.repr 52) :: Init_int8 (Int.repr 41) ::
                Init_int8 (Int.repr 10) :: Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_36 := {|
  gvar_info := (tarray tuchar 11);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 108) :: Init_int8 (Int.repr 100) ::
                Init_int8 (Int.repr 120) :: Init_int8 (Int.repr 119) ::
                Init_int8 (Int.repr 32) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_62 := {|
  gvar_info := (tarray tuchar 11);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 100) :: Init_int8 (Int.repr 105) ::
                Init_int8 (Int.repr 118) :: Init_int8 (Int.repr 54) ::
                Init_int8 (Int.repr 52) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_66 := {|
  gvar_info := (tarray tuchar 11);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 110) :: Init_int8 (Int.repr 101) ::
                Init_int8 (Int.repr 103) :: Init_int8 (Int.repr 54) ::
                Init_int8 (Int.repr 52) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_44 := {|
  gvar_info := (tarray tuchar 11);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 114) :: Init_int8 (Int.repr 115) ::
                Init_int8 (Int.repr 104) :: Init_int8 (Int.repr 51) ::
                Init_int8 (Int.repr 50) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_57 := {|
  gvar_info := (tarray tuchar 11);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 109) :: Init_int8 (Int.repr 111) ::
                Init_int8 (Int.repr 100) :: Init_int8 (Int.repr 54) ::
                Init_int8 (Int.repr 52) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_90 := {|
  gvar_info := (tarray tuchar 20);
  gvar_init := (Init_int8 (Int.repr 106) :: Init_int8 (Int.repr 105) ::
                Init_int8 (Int.repr 116) :: Init_int8 (Int.repr 116) ::
                Init_int8 (Int.repr 101) :: Init_int8 (Int.repr 100) ::
                Init_int8 (Int.repr 32) :: Init_int8 (Int.repr 116) ::
                Init_int8 (Int.repr 104) :: Init_int8 (Int.repr 117) ::
                Init_int8 (Int.repr 109) :: Init_int8 (Int.repr 98) ::
                Init_int8 (Int.repr 32) :: Init_int8 (Int.repr 108) ::
                Init_int8 (Int.repr 105) :: Init_int8 (Int.repr 115) ::
                Init_int8 (Int.repr 116) :: Init_int8 (Int.repr 58) ::
                Init_int8 (Int.repr 32) :: Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_3 := {|
  gvar_info := (tarray tuchar 10);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 101) :: Init_int8 (Int.repr 120) ::
                Init_int8 (Int.repr 105) :: Init_int8 (Int.repr 116) ::
                Init_int8 (Int.repr 32) :: Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_10 := {|
  gvar_info := (tarray tuchar 10);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 106) :: Init_int8 (Int.repr 115) ::
                Init_int8 (Int.repr 103) :: Init_int8 (Int.repr 101) ::
                Init_int8 (Int.repr 32) :: Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_16 := {|
  gvar_info := (tarray tuchar 9);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 106) :: Init_int8 (Int.repr 103) ::
                Init_int8 (Int.repr 101) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_29 := {|
  gvar_info := (tarray tuchar 10);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 115) :: Init_int8 (Int.repr 116) ::
                Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 32) :: Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_50 := {|
  gvar_info := (tarray tuchar 11);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 115) :: Init_int8 (Int.repr 117) ::
                Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 51) ::
                Init_int8 (Int.repr 50) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_54 := {|
  gvar_info := (tarray tuchar 12);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 97) :: Init_int8 (Int.repr 114) ::
                Init_int8 (Int.repr 115) :: Init_int8 (Int.repr 104) ::
                Init_int8 (Int.repr 54) :: Init_int8 (Int.repr 52) ::
                Init_int8 (Int.repr 32) :: Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_39 := {|
  gvar_info := (tarray tuchar 14);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 108) :: Init_int8 (Int.repr 100) ::
                Init_int8 (Int.repr 100) :: Init_int8 (Int.repr 119) ::
                Init_int8 (Int.repr 95) :: Init_int8 (Int.repr 108) ::
                Init_int8 (Int.repr 111) :: Init_int8 (Int.repr 119) ::
                Init_int8 (Int.repr 32) :: Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_82 := {|
  gvar_info := (tarray tuchar 20);
  gvar_init := (Init_int8 (Int.repr 95) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 101) :: Init_int8 (Int.repr 114) ::
                Init_int8 (Int.repr 109) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 61) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 83) :: Init_int8 (Int.repr 116) ::
                Init_int8 (Int.repr 111) :: Init_int8 (Int.repr 114) ::
                Init_int8 (Int.repr 101) :: Init_int8 (Int.repr 80) ::
                Init_int8 (Int.repr 101) :: Init_int8 (Int.repr 114) ::
                Init_int8 (Int.repr 109) :: Init_int8 (Int.repr 59) ::
                Init_int8 (Int.repr 32) :: Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_13 := {|
  gvar_info := (tarray tuchar 10);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 106) :: Init_int8 (Int.repr 115) ::
                Init_int8 (Int.repr 101) :: Init_int8 (Int.repr 116) ::
                Init_int8 (Int.repr 32) :: Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_60 := {|
  gvar_info := (tarray tuchar 11);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 97) :: Init_int8 (Int.repr 110) ::
                Init_int8 (Int.repr 100) :: Init_int8 (Int.repr 54) ::
                Init_int8 (Int.repr 52) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_1 := {|
  gvar_info := (tarray tuchar 5);
  gvar_init := (Init_int8 (Int.repr 82) :: Init_int8 (Int.repr 37) ::
                Init_int8 (Int.repr 100) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_64 := {|
  gvar_info := (tarray tuchar 11);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 115) :: Init_int8 (Int.repr 117) ::
                Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 54) ::
                Init_int8 (Int.repr 52) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_48 := {|
  gvar_info := (tarray tuchar 11);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 100) :: Init_int8 (Int.repr 105) ::
                Init_int8 (Int.repr 118) :: Init_int8 (Int.repr 51) ::
                Init_int8 (Int.repr 50) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_49 := {|
  gvar_info := (tarray tuchar 11);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 109) :: Init_int8 (Int.repr 117) ::
                Init_int8 (Int.repr 108) :: Init_int8 (Int.repr 51) ::
                Init_int8 (Int.repr 50) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_24 := {|
  gvar_info := (tarray tuchar 6);
  gvar_init := (Init_int8 (Int.repr 43) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 37) :: Init_int8 (Int.repr 100) ::
                Init_int8 (Int.repr 93) :: Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_20 := {|
  gvar_info := (tarray tuchar 8);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 106) :: Init_int8 (Int.repr 97) ::
                Init_int8 (Int.repr 32) :: Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_22 := {|
  gvar_info := (tarray tuchar 11);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 115) :: Init_int8 (Int.repr 116) ::
                Init_int8 (Int.repr 120) :: Init_int8 (Int.repr 100) ::
                Init_int8 (Int.repr 119) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_6 := {|
  gvar_info := (tarray tuchar 10);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 106) :: Init_int8 (Int.repr 115) ::
                Init_int8 (Int.repr 108) :: Init_int8 (Int.repr 101) ::
                Init_int8 (Int.repr 32) :: Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_43 := {|
  gvar_info := (tarray tuchar 11);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 109) :: Init_int8 (Int.repr 111) ::
                Init_int8 (Int.repr 100) :: Init_int8 (Int.repr 51) ::
                Init_int8 (Int.repr 50) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_70 := {|
  gvar_info := (tarray tuchar 6);
  gvar_init := (Init_int8 (Int.repr 40) :: Init_int8 (Int.repr 82) ::
                Init_int8 (Int.repr 50) :: Init_int8 (Int.repr 41) ::
                Init_int8 (Int.repr 10) :: Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_15 := {|
  gvar_info := (tarray tuchar 9);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 106) :: Init_int8 (Int.repr 108) ::
                Init_int8 (Int.repr 116) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_34 := {|
  gvar_info := (tarray tuchar 11);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 108) :: Init_int8 (Int.repr 100) ::
                Init_int8 (Int.repr 120) :: Init_int8 (Int.repr 98) ::
                Init_int8 (Int.repr 32) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_80 := {|
  gvar_info := (tarray tuchar 16);
  gvar_init := (Init_int8 (Int.repr 95) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 101) :: Init_int8 (Int.repr 114) ::
                Init_int8 (Int.repr 109) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 61) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 85) :: Init_int8 (Int.repr 110) ::
                Init_int8 (Int.repr 100) :: Init_int8 (Int.repr 101) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 59) ::
                Init_int8 (Int.repr 32) :: Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_2 := {|
  gvar_info := (tarray tuchar 15);
  gvar_init := (Init_int8 (Int.repr 101) :: Init_int8 (Int.repr 114) ::
                Init_int8 (Int.repr 114) :: Init_int8 (Int.repr 111) ::
                Init_int8 (Int.repr 114) :: Init_int8 (Int.repr 58) ::
                Init_int8 (Int.repr 32) :: Init_int8 (Int.repr 111) ::
                Init_int8 (Int.repr 112) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 61) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 37) :: Init_int8 (Int.repr 120) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_28 := {|
  gvar_info := (tarray tuchar 10);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 115) :: Init_int8 (Int.repr 116) ::
                Init_int8 (Int.repr 100) :: Init_int8 (Int.repr 119) ::
                Init_int8 (Int.repr 32) :: Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_4 := {|
  gvar_info := (tarray tuchar 10);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 99) :: Init_int8 (Int.repr 97) ::
                Init_int8 (Int.repr 108) :: Init_int8 (Int.repr 108) ::
                Init_int8 (Int.repr 32) :: Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_21 := {|
  gvar_info := (tarray tuchar 6);
  gvar_init := (Init_int8 (Int.repr 32) :: Init_int8 (Int.repr 43) ::
                Init_int8 (Int.repr 37) :: Init_int8 (Int.repr 100) ::
                Init_int8 (Int.repr 93) :: Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_11 := {|
  gvar_info := (tarray tuchar 10);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 106) :: Init_int8 (Int.repr 115) ::
                Init_int8 (Int.repr 103) :: Init_int8 (Int.repr 116) ::
                Init_int8 (Int.repr 32) :: Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_56 := {|
  gvar_info := (tarray tuchar 11);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 120) :: Init_int8 (Int.repr 111) ::
                Init_int8 (Int.repr 114) :: Init_int8 (Int.repr 54) ::
                Init_int8 (Int.repr 52) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_46 := {|
  gvar_info := (tarray tuchar 11);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 97) :: Init_int8 (Int.repr 110) ::
                Init_int8 (Int.repr 100) :: Init_int8 (Int.repr 51) ::
                Init_int8 (Int.repr 50) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_88 := {|
  gvar_info := (tarray tuchar 12);
  gvar_init := (Init_int8 (Int.repr 105) :: Init_int8 (Int.repr 98) ::
                Init_int8 (Int.repr 112) :: Init_int8 (Int.repr 102) ::
                Init_int8 (Int.repr 32) :: Init_int8 (Int.repr 108) ::
                Init_int8 (Int.repr 105) :: Init_int8 (Int.repr 115) ::
                Init_int8 (Int.repr 116) :: Init_int8 (Int.repr 58) ::
                Init_int8 (Int.repr 32) :: Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_91 := {|
  gvar_info := (tarray tuchar 13);
  gvar_init := (Init_int8 (Int.repr 48) :: Init_int8 (Int.repr 120) ::
                Init_int8 (Int.repr 37) :: Init_int8 (Int.repr 120) ::
                Init_int8 (Int.repr 58) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 48) :: Init_int8 (Int.repr 120) ::
                Init_int8 (Int.repr 37) :: Init_int8 (Int.repr 120) ::
                Init_int8 (Int.repr 10) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_19 := {|
  gvar_info := (tarray tuchar 5);
  gvar_init := (Init_int8 (Int.repr 44) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 37) :: Init_int8 (Int.repr 100) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_38 := {|
  gvar_info := (tarray tuchar 3);
  gvar_init := (Init_int8 (Int.repr 37) :: Init_int8 (Int.repr 100) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_71 := {|
  gvar_info := (tarray tuchar 6);
  gvar_init := (Init_int8 (Int.repr 40) :: Init_int8 (Int.repr 82) ::
                Init_int8 (Int.repr 51) :: Init_int8 (Int.repr 41) ::
                Init_int8 (Int.repr 10) :: Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_86 := {|
  gvar_info := (tarray tuchar 13);
  gvar_init := (Init_int8 (Int.repr 116) :: Init_int8 (Int.repr 104) ::
                Init_int8 (Int.repr 117) :: Init_int8 (Int.repr 109) ::
                Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 108) :: Init_int8 (Int.repr 105) ::
                Init_int8 (Int.repr 115) :: Init_int8 (Int.repr 116) ::
                Init_int8 (Int.repr 58) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_14 := {|
  gvar_info := (tarray tuchar 9);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 106) :: Init_int8 (Int.repr 108) ::
                Init_int8 (Int.repr 101) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_67 := {|
  gvar_info := (tarray tuchar 19);
  gvar_init := (Init_int8 (Int.repr 112) :: Init_int8 (Int.repr 99) ::
                Init_int8 (Int.repr 61) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 37) :: Init_int8 (Int.repr 48) ::
                Init_int8 (Int.repr 50) :: Init_int8 (Int.repr 100) ::
                Init_int8 (Int.repr 32) :: Init_int8 (Int.repr 102) ::
                Init_int8 (Int.repr 108) :: Init_int8 (Int.repr 97) ::
                Init_int8 (Int.repr 103) :: Init_int8 (Int.repr 61) ::
                Init_int8 (Int.repr 32) :: Init_int8 (Int.repr 37) ::
                Init_int8 (Int.repr 100) :: Init_int8 (Int.repr 10) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_75 := {|
  gvar_info := (tarray tuchar 6);
  gvar_init := (Init_int8 (Int.repr 40) :: Init_int8 (Int.repr 82) ::
                Init_int8 (Int.repr 55) :: Init_int8 (Int.repr 41) ::
                Init_int8 (Int.repr 10) :: Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_18 := {|
  gvar_info := (tarray tuchar 9);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 106) :: Init_int8 (Int.repr 101) ::
                Init_int8 (Int.repr 113) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_40 := {|
  gvar_info := (tarray tuchar 12);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 97) :: Init_int8 (Int.repr 114) ::
                Init_int8 (Int.repr 115) :: Init_int8 (Int.repr 104) ::
                Init_int8 (Int.repr 51) :: Init_int8 (Int.repr 50) ::
                Init_int8 (Int.repr 32) :: Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_35 := {|
  gvar_info := (tarray tuchar 11);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 108) :: Init_int8 (Int.repr 100) ::
                Init_int8 (Int.repr 120) :: Init_int8 (Int.repr 104) ::
                Init_int8 (Int.repr 32) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_45 := {|
  gvar_info := (tarray tuchar 11);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 108) :: Init_int8 (Int.repr 115) ::
                Init_int8 (Int.repr 104) :: Init_int8 (Int.repr 51) ::
                Init_int8 (Int.repr 50) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_53 := {|
  gvar_info := (tarray tuchar 11);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 110) :: Init_int8 (Int.repr 101) ::
                Init_int8 (Int.repr 103) :: Init_int8 (Int.repr 51) ::
                Init_int8 (Int.repr 50) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_5 := {|
  gvar_info := (tarray tuchar 4);
  gvar_init := (Init_int8 (Int.repr 32) :: Init_int8 (Int.repr 37) ::
                Init_int8 (Int.repr 100) :: Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_42 := {|
  gvar_info := (tarray tuchar 11);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 120) :: Init_int8 (Int.repr 111) ::
                Init_int8 (Int.repr 114) :: Init_int8 (Int.repr 51) ::
                Init_int8 (Int.repr 50) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_68 := {|
  gvar_info := (tarray tuchar 6);
  gvar_init := (Init_int8 (Int.repr 40) :: Init_int8 (Int.repr 82) ::
                Init_int8 (Int.repr 48) :: Init_int8 (Int.repr 41) ::
                Init_int8 (Int.repr 10) :: Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_12 := {|
  gvar_info := (tarray tuchar 9);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 106) :: Init_int8 (Int.repr 110) ::
                Init_int8 (Int.repr 101) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_59 := {|
  gvar_info := (tarray tuchar 11);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 108) :: Init_int8 (Int.repr 115) ::
                Init_int8 (Int.repr 104) :: Init_int8 (Int.repr 54) ::
                Init_int8 (Int.repr 52) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_61 := {|
  gvar_info := (tarray tuchar 11);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 111) :: Init_int8 (Int.repr 114) ::
                Init_int8 (Int.repr 54) :: Init_int8 (Int.repr 52) ::
                Init_int8 (Int.repr 32) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_55 := {|
  gvar_info := (tarray tuchar 11);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 109) :: Init_int8 (Int.repr 111) ::
                Init_int8 (Int.repr 118) :: Init_int8 (Int.repr 54) ::
                Init_int8 (Int.repr 52) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_37 := {|
  gvar_info := (tarray tuchar 15);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 108) :: Init_int8 (Int.repr 100) ::
                Init_int8 (Int.repr 100) :: Init_int8 (Int.repr 119) ::
                Init_int8 (Int.repr 95) :: Init_int8 (Int.repr 104) ::
                Init_int8 (Int.repr 105) :: Init_int8 (Int.repr 103) ::
                Init_int8 (Int.repr 104) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_76 := {|
  gvar_info := (tarray tuchar 6);
  gvar_init := (Init_int8 (Int.repr 40) :: Init_int8 (Int.repr 82) ::
                Init_int8 (Int.repr 56) :: Init_int8 (Int.repr 41) ::
                Init_int8 (Int.repr 10) :: Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_85 := {|
  gvar_info := (tarray tuchar 2);
  gvar_init := (Init_int8 (Int.repr 10) :: Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_87 := {|
  gvar_info := (tarray tuchar 9);
  gvar_init := (Init_int8 (Int.repr 37) :: Init_int8 (Int.repr 120) ::
                Init_int8 (Int.repr 58) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 37) :: Init_int8 (Int.repr 117) ::
                Init_int8 (Int.repr 59) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_47 := {|
  gvar_info := (tarray tuchar 11);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 111) :: Init_int8 (Int.repr 114) ::
                Init_int8 (Int.repr 51) :: Init_int8 (Int.repr 50) ::
                Init_int8 (Int.repr 32) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_84 := {|
  gvar_info := (tarray tuchar 18);
  gvar_init := (Init_int8 (Int.repr 95) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 101) :: Init_int8 (Int.repr 114) ::
                Init_int8 (Int.repr 109) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 61) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 78) :: Init_int8 (Int.repr 111) ::
                Init_int8 (Int.repr 110) :: Init_int8 (Int.repr 80) ::
                Init_int8 (Int.repr 101) :: Init_int8 (Int.repr 114) ::
                Init_int8 (Int.repr 109) :: Init_int8 (Int.repr 59) ::
                Init_int8 (Int.repr 32) :: Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_23 := {|
  gvar_info := (tarray tuchar 2);
  gvar_init := (Init_int8 (Int.repr 91) :: Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_33 := {|
  gvar_info := (tarray tuchar 4);
  gvar_init := (Init_int8 (Int.repr 44) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 91) :: Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_89 := {|
  gvar_info := (tarray tuchar 6);
  gvar_init := (Init_int8 (Int.repr 40) :: Init_int8 (Int.repr 37) ::
                Init_int8 (Int.repr 100) :: Init_int8 (Int.repr 41) ::
                Init_int8 (Int.repr 10) :: Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_79 := {|
  gvar_info := (tarray tuchar 4);
  gvar_init := (Init_int8 (Int.repr 82) :: Init_int8 (Int.repr 37) ::
                Init_int8 (Int.repr 100) :: Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_27 := {|
  gvar_info := (tarray tuchar 11);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 115) :: Init_int8 (Int.repr 116) ::
                Init_int8 (Int.repr 120) :: Init_int8 (Int.repr 119) ::
                Init_int8 (Int.repr 32) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_31 := {|
  gvar_info := (tarray tuchar 10);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 115) :: Init_int8 (Int.repr 116) ::
                Init_int8 (Int.repr 119) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 32) :: Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_73 := {|
  gvar_info := (tarray tuchar 6);
  gvar_init := (Init_int8 (Int.repr 40) :: Init_int8 (Int.repr 82) ::
                Init_int8 (Int.repr 53) :: Init_int8 (Int.repr 41) ::
                Init_int8 (Int.repr 10) :: Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_65 := {|
  gvar_info := (tarray tuchar 11);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 97) :: Init_int8 (Int.repr 100) ::
                Init_int8 (Int.repr 100) :: Init_int8 (Int.repr 54) ::
                Init_int8 (Int.repr 52) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_58 := {|
  gvar_info := (tarray tuchar 11);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 114) :: Init_int8 (Int.repr 115) ::
                Init_int8 (Int.repr 104) :: Init_int8 (Int.repr 54) ::
                Init_int8 (Int.repr 52) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_17 := {|
  gvar_info := (tarray tuchar 9);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 106) :: Init_int8 (Int.repr 103) ::
                Init_int8 (Int.repr 116) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_30 := {|
  gvar_info := (tarray tuchar 10);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 115) :: Init_int8 (Int.repr 116) ::
                Init_int8 (Int.repr 104) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 32) :: Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_25 := {|
  gvar_info := (tarray tuchar 11);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 115) :: Init_int8 (Int.repr 116) ::
                Init_int8 (Int.repr 120) :: Init_int8 (Int.repr 98) ::
                Init_int8 (Int.repr 32) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_41 := {|
  gvar_info := (tarray tuchar 11);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 109) :: Init_int8 (Int.repr 111) ::
                Init_int8 (Int.repr 118) :: Init_int8 (Int.repr 51) ::
                Init_int8 (Int.repr 50) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_52 := {|
  gvar_info := (tarray tuchar 9);
  gvar_init := (Init_int8 (Int.repr 98) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 102) :: Init_int8 (Int.repr 95) ::
                Init_int8 (Int.repr 106) :: Init_int8 (Int.repr 105) ::
                Init_int8 (Int.repr 116) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_81 := {|
  gvar_info := (tarray tuchar 24);
  gvar_init := (Init_int8 (Int.repr 95) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 101) :: Init_int8 (Int.repr 114) ::
                Init_int8 (Int.repr 109) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 61) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 76) :: Init_int8 (Int.repr 111) ::
                Init_int8 (Int.repr 97) :: Init_int8 (Int.repr 100) ::
                Init_int8 (Int.repr 83) :: Init_int8 (Int.repr 116) ::
                Init_int8 (Int.repr 111) :: Init_int8 (Int.repr 114) ::
                Init_int8 (Int.repr 101) :: Init_int8 (Int.repr 80) ::
                Init_int8 (Int.repr 101) :: Init_int8 (Int.repr 114) ::
                Init_int8 (Int.repr 109) :: Init_int8 (Int.repr 59) ::
                Init_int8 (Int.repr 32) :: Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_8 := {|
  gvar_info := (tarray tuchar 6);
  gvar_init := (Init_int8 (Int.repr 44) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 43) :: Init_int8 (Int.repr 37) ::
                Init_int8 (Int.repr 100) :: Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_83 := {|
  gvar_info := (tarray tuchar 19);
  gvar_init := (Init_int8 (Int.repr 95) :: Init_int8 (Int.repr 112) ::
                Init_int8 (Int.repr 101) :: Init_int8 (Int.repr 114) ::
                Init_int8 (Int.repr 109) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 61) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 76) :: Init_int8 (Int.repr 111) ::
                Init_int8 (Int.repr 97) :: Init_int8 (Int.repr 100) ::
                Init_int8 (Int.repr 80) :: Init_int8 (Int.repr 101) ::
                Init_int8 (Int.repr 114) :: Init_int8 (Int.repr 109) ::
                Init_int8 (Int.repr 59) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_7 := {|
  gvar_info := (tarray tuchar 3);
  gvar_init := (Init_int8 (Int.repr 44) :: Init_int8 (Int.repr 32) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition v___stringlit_78 := {|
  gvar_info := (tarray tuchar 7);
  gvar_init := (Init_int8 (Int.repr 40) :: Init_int8 (Int.repr 82) ::
                Init_int8 (Int.repr 49) :: Init_int8 (Int.repr 48) ::
                Init_int8 (Int.repr 41) :: Init_int8 (Int.repr 10) ::
                Init_int8 (Int.repr 0) :: nil);
  gvar_readonly := true;
  gvar_volatile := false
|}.

Definition f_print_reg := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_r, tuint) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Ssequence
  (Scall None
    (Evar _printf (Tfunction (Tcons (tptr tuchar) Tnil) tint
                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
    ((Evar ___stringlit_1 (tarray tuchar 5)) :: (Etempvar _r tuint) :: nil))
  (Sreturn None))
|}.

Definition f_print_bpf_insstruction := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_ins, tulong) :: nil);
  fn_vars := nil;
  fn_temps := ((_op, tuint) :: (_dst, tuint) :: (_src, tuint) ::
               (_imm, tint) :: (_ofs, tint) :: nil);
  fn_body :=
(Ssequence
  (Sset _op
    (Ecast
      (Ebinop Oand (Ecast (Etempvar _ins tulong) tuint)
        (Econst_long (Int64.repr 255) tulong) tulong) tuint))
  (Ssequence
    (Sset _dst
      (Ecast
        (Ebinop Oshr
          (Ebinop Oand (Etempvar _ins tulong)
            (Econst_long (Int64.repr 4095) tulong) tulong)
          (Econst_long (Int64.repr 8) tulong) tulong) tuint))
    (Ssequence
      (Sset _src
        (Ecast
          (Ebinop Oshr
            (Ebinop Oand (Etempvar _ins tulong)
              (Econst_long (Int64.repr 65535) tulong) tulong)
            (Econst_long (Int64.repr 12) tulong) tulong) tuint))
      (Ssequence
        (Sset _imm
          (Ecast
            (Ebinop Oshr (Etempvar _ins tulong)
              (Econst_long (Int64.repr 32) tulong) tulong) tint))
        (Ssequence
          (Sset _ofs
            (Ecast
              (Ecast
                (Ebinop Oshr
                  (Ebinop Oshl (Etempvar _ins tulong)
                    (Econst_long (Int64.repr 32) tulong) tulong)
                  (Econst_long (Int64.repr 48) tulong) tulong) tshort) tint))
          (Sswitch (Etempvar _op tuint)
            (LScons (Some 7)
              (Ssequence
                (Scall None
                  (Evar _printf (Tfunction (Tcons (tptr tuchar) Tnil) tint
                                  {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                  ((Evar ___stringlit_65 (tarray tuchar 11)) :: nil))
                (Ssequence
                  (Scall None
                    (Evar _print_reg (Tfunction (Tcons tuint Tnil) tvoid
                                       cc_default))
                    ((Etempvar _dst tuint) :: nil))
                  (Ssequence
                    (Scall None
                      (Evar _printf (Tfunction (Tcons (tptr tuchar) Tnil)
                                      tint
                                      {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                      ((Evar ___stringlit_38 (tarray tuchar 3)) ::
                       (Etempvar _imm tint) :: nil))
                    (Sreturn None))))
              (LScons (Some 23)
                (Ssequence
                  (Scall None
                    (Evar _printf (Tfunction (Tcons (tptr tuchar) Tnil) tint
                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                    ((Evar ___stringlit_64 (tarray tuchar 11)) :: nil))
                  (Ssequence
                    (Scall None
                      (Evar _print_reg (Tfunction (Tcons tuint Tnil) tvoid
                                         cc_default))
                      ((Etempvar _dst tuint) :: nil))
                    (Ssequence
                      (Scall None
                        (Evar _printf (Tfunction (Tcons (tptr tuchar) Tnil)
                                        tint
                                        {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                        ((Evar ___stringlit_38 (tarray tuchar 3)) ::
                         (Etempvar _imm tint) :: nil))
                      (Sreturn None))))
                (LScons (Some 39)
                  (Ssequence
                    (Scall None
                      (Evar _printf (Tfunction (Tcons (tptr tuchar) Tnil)
                                      tint
                                      {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                      ((Evar ___stringlit_63 (tarray tuchar 11)) :: nil))
                    (Ssequence
                      (Scall None
                        (Evar _print_reg (Tfunction (Tcons tuint Tnil) tvoid
                                           cc_default))
                        ((Etempvar _dst tuint) :: nil))
                      (Ssequence
                        (Scall None
                          (Evar _printf (Tfunction (Tcons (tptr tuchar) Tnil)
                                          tint
                                          {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                          ((Evar ___stringlit_38 (tarray tuchar 3)) ::
                           (Etempvar _imm tint) :: nil))
                        (Sreturn None))))
                  (LScons (Some 55)
                    (Ssequence
                      (Scall None
                        (Evar _printf (Tfunction (Tcons (tptr tuchar) Tnil)
                                        tint
                                        {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                        ((Evar ___stringlit_62 (tarray tuchar 11)) :: nil))
                      (Ssequence
                        (Scall None
                          (Evar _print_reg (Tfunction (Tcons tuint Tnil)
                                             tvoid cc_default))
                          ((Etempvar _dst tuint) :: nil))
                        (Ssequence
                          (Scall None
                            (Evar _printf (Tfunction
                                            (Tcons (tptr tuchar) Tnil) tint
                                            {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                            ((Evar ___stringlit_38 (tarray tuchar 3)) ::
                             (Etempvar _imm tint) :: nil))
                          (Sreturn None))))
                    (LScons (Some 71)
                      (Ssequence
                        (Scall None
                          (Evar _printf (Tfunction (Tcons (tptr tuchar) Tnil)
                                          tint
                                          {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                          ((Evar ___stringlit_61 (tarray tuchar 11)) :: nil))
                        (Ssequence
                          (Scall None
                            (Evar _print_reg (Tfunction (Tcons tuint Tnil)
                                               tvoid cc_default))
                            ((Etempvar _dst tuint) :: nil))
                          (Ssequence
                            (Scall None
                              (Evar _printf (Tfunction
                                              (Tcons (tptr tuchar) Tnil) tint
                                              {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                              ((Evar ___stringlit_38 (tarray tuchar 3)) ::
                               (Etempvar _imm tint) :: nil))
                            (Sreturn None))))
                      (LScons (Some 87)
                        (Ssequence
                          (Scall None
                            (Evar _printf (Tfunction
                                            (Tcons (tptr tuchar) Tnil) tint
                                            {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                            ((Evar ___stringlit_60 (tarray tuchar 11)) ::
                             nil))
                          (Ssequence
                            (Scall None
                              (Evar _print_reg (Tfunction (Tcons tuint Tnil)
                                                 tvoid cc_default))
                              ((Etempvar _dst tuint) :: nil))
                            (Ssequence
                              (Scall None
                                (Evar _printf (Tfunction
                                                (Tcons (tptr tuchar) Tnil)
                                                tint
                                                {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                ((Evar ___stringlit_38 (tarray tuchar 3)) ::
                                 (Etempvar _imm tint) :: nil))
                              (Sreturn None))))
                        (LScons (Some 103)
                          (Ssequence
                            (Scall None
                              (Evar _printf (Tfunction
                                              (Tcons (tptr tuchar) Tnil) tint
                                              {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                              ((Evar ___stringlit_59 (tarray tuchar 11)) ::
                               nil))
                            (Ssequence
                              (Scall None
                                (Evar _print_reg (Tfunction
                                                   (Tcons tuint Tnil) tvoid
                                                   cc_default))
                                ((Etempvar _dst tuint) :: nil))
                              (Ssequence
                                (Scall None
                                  (Evar _printf (Tfunction
                                                  (Tcons (tptr tuchar) Tnil)
                                                  tint
                                                  {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                  ((Evar ___stringlit_38 (tarray tuchar 3)) ::
                                   (Etempvar _imm tint) :: nil))
                                (Sreturn None))))
                          (LScons (Some 119)
                            (Ssequence
                              (Scall None
                                (Evar _printf (Tfunction
                                                (Tcons (tptr tuchar) Tnil)
                                                tint
                                                {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                ((Evar ___stringlit_58 (tarray tuchar 11)) ::
                                 nil))
                              (Ssequence
                                (Scall None
                                  (Evar _print_reg (Tfunction
                                                     (Tcons tuint Tnil) tvoid
                                                     cc_default))
                                  ((Etempvar _dst tuint) :: nil))
                                (Ssequence
                                  (Scall None
                                    (Evar _printf (Tfunction
                                                    (Tcons (tptr tuchar)
                                                      Tnil) tint
                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                    ((Evar ___stringlit_38 (tarray tuchar 3)) ::
                                     (Etempvar _imm tint) :: nil))
                                  (Sreturn None))))
                            (LScons (Some 135)
                              (Ssequence
                                (Scall None
                                  (Evar _printf (Tfunction
                                                  (Tcons (tptr tuchar) Tnil)
                                                  tint
                                                  {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                  ((Evar ___stringlit_66 (tarray tuchar 11)) ::
                                   nil))
                                (Ssequence
                                  (Scall None
                                    (Evar _print_reg (Tfunction
                                                       (Tcons tuint Tnil)
                                                       tvoid cc_default))
                                    ((Etempvar _dst tuint) :: nil))
                                  (Ssequence
                                    (Scall None
                                      (Evar _printf (Tfunction
                                                      (Tcons (tptr tuchar)
                                                        Tnil) tint
                                                      {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                      ((Evar ___stringlit_38 (tarray tuchar 3)) ::
                                       (Etempvar _imm tint) :: nil))
                                    (Sreturn None))))
                              (LScons (Some 151)
                                (Ssequence
                                  (Scall None
                                    (Evar _printf (Tfunction
                                                    (Tcons (tptr tuchar)
                                                      Tnil) tint
                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                    ((Evar ___stringlit_57 (tarray tuchar 11)) ::
                                     nil))
                                  (Ssequence
                                    (Scall None
                                      (Evar _print_reg (Tfunction
                                                         (Tcons tuint Tnil)
                                                         tvoid cc_default))
                                      ((Etempvar _dst tuint) :: nil))
                                    (Ssequence
                                      (Scall None
                                        (Evar _printf (Tfunction
                                                        (Tcons (tptr tuchar)
                                                          Tnil) tint
                                                        {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                        ((Evar ___stringlit_38 (tarray tuchar 3)) ::
                                         (Etempvar _imm tint) :: nil))
                                      (Sreturn None))))
                                (LScons (Some 167)
                                  (Ssequence
                                    (Scall None
                                      (Evar _printf (Tfunction
                                                      (Tcons (tptr tuchar)
                                                        Tnil) tint
                                                      {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                      ((Evar ___stringlit_56 (tarray tuchar 11)) ::
                                       nil))
                                    (Ssequence
                                      (Scall None
                                        (Evar _print_reg (Tfunction
                                                           (Tcons tuint Tnil)
                                                           tvoid cc_default))
                                        ((Etempvar _dst tuint) :: nil))
                                      (Ssequence
                                        (Scall None
                                          (Evar _printf (Tfunction
                                                          (Tcons
                                                            (tptr tuchar)
                                                            Tnil) tint
                                                          {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                          ((Evar ___stringlit_38 (tarray tuchar 3)) ::
                                           (Etempvar _imm tint) :: nil))
                                        (Sreturn None))))
                                  (LScons (Some 183)
                                    (Ssequence
                                      (Scall None
                                        (Evar _printf (Tfunction
                                                        (Tcons (tptr tuchar)
                                                          Tnil) tint
                                                        {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                        ((Evar ___stringlit_55 (tarray tuchar 11)) ::
                                         nil))
                                      (Ssequence
                                        (Scall None
                                          (Evar _print_reg (Tfunction
                                                             (Tcons tuint
                                                               Tnil) tvoid
                                                             cc_default))
                                          ((Etempvar _dst tuint) :: nil))
                                        (Ssequence
                                          (Scall None
                                            (Evar _printf (Tfunction
                                                            (Tcons
                                                              (tptr tuchar)
                                                              Tnil) tint
                                                            {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                            ((Evar ___stringlit_38 (tarray tuchar 3)) ::
                                             (Etempvar _imm tint) :: nil))
                                          (Sreturn None))))
                                    (LScons (Some 199)
                                      (Ssequence
                                        (Scall None
                                          (Evar _printf (Tfunction
                                                          (Tcons
                                                            (tptr tuchar)
                                                            Tnil) tint
                                                          {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                          ((Evar ___stringlit_54 (tarray tuchar 12)) ::
                                           nil))
                                        (Ssequence
                                          (Scall None
                                            (Evar _print_reg (Tfunction
                                                               (Tcons tuint
                                                                 Tnil) tvoid
                                                               cc_default))
                                            ((Etempvar _dst tuint) :: nil))
                                          (Ssequence
                                            (Scall None
                                              (Evar _printf (Tfunction
                                                              (Tcons
                                                                (tptr tuchar)
                                                                Tnil) tint
                                                              {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                              ((Evar ___stringlit_38 (tarray tuchar 3)) ::
                                               (Etempvar _imm tint) :: nil))
                                            (Sreturn None))))
                                      (LScons (Some 15)
                                        (Ssequence
                                          (Scall None
                                            (Evar _printf (Tfunction
                                                            (Tcons
                                                              (tptr tuchar)
                                                              Tnil) tint
                                                            {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                            ((Evar ___stringlit_65 (tarray tuchar 11)) ::
                                             nil))
                                          (Ssequence
                                            (Scall None
                                              (Evar _print_reg (Tfunction
                                                                 (Tcons tuint
                                                                   Tnil)
                                                                 tvoid
                                                                 cc_default))
                                              ((Etempvar _dst tuint) :: nil))
                                            (Ssequence
                                              (Scall None
                                                (Evar _print_reg (Tfunction
                                                                   (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                   tvoid
                                                                   cc_default))
                                                ((Etempvar _src tuint) ::
                                                 nil))
                                              (Sreturn None))))
                                        (LScons (Some 31)
                                          (Ssequence
                                            (Scall None
                                              (Evar _printf (Tfunction
                                                              (Tcons
                                                                (tptr tuchar)
                                                                Tnil) tint
                                                              {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                              ((Evar ___stringlit_64 (tarray tuchar 11)) ::
                                               nil))
                                            (Ssequence
                                              (Scall None
                                                (Evar _print_reg (Tfunction
                                                                   (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                   tvoid
                                                                   cc_default))
                                                ((Etempvar _dst tuint) ::
                                                 nil))
                                              (Ssequence
                                                (Scall None
                                                  (Evar _print_reg (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                  ((Etempvar _src tuint) ::
                                                   nil))
                                                (Sreturn None))))
                                          (LScons (Some 47)
                                            (Ssequence
                                              (Scall None
                                                (Evar _printf (Tfunction
                                                                (Tcons
                                                                  (tptr tuchar)
                                                                  Tnil) tint
                                                                {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                ((Evar ___stringlit_63 (tarray tuchar 11)) ::
                                                 nil))
                                              (Ssequence
                                                (Scall None
                                                  (Evar _print_reg (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                  ((Etempvar _dst tuint) ::
                                                   nil))
                                                (Ssequence
                                                  (Scall None
                                                    (Evar _print_reg 
                                                    (Tfunction
                                                      (Tcons tuint Tnil)
                                                      tvoid cc_default))
                                                    ((Etempvar _src tuint) ::
                                                     nil))
                                                  (Sreturn None))))
                                            (LScons (Some 63)
                                              (Ssequence
                                                (Scall None
                                                  (Evar _printf (Tfunction
                                                                  (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                  tint
                                                                  {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                  ((Evar ___stringlit_62 (tarray tuchar 11)) ::
                                                   nil))
                                                (Ssequence
                                                  (Scall None
                                                    (Evar _print_reg 
                                                    (Tfunction
                                                      (Tcons tuint Tnil)
                                                      tvoid cc_default))
                                                    ((Etempvar _dst tuint) ::
                                                     nil))
                                                  (Ssequence
                                                    (Scall None
                                                      (Evar _print_reg 
                                                      (Tfunction
                                                        (Tcons tuint Tnil)
                                                        tvoid cc_default))
                                                      ((Etempvar _src tuint) ::
                                                       nil))
                                                    (Sreturn None))))
                                              (LScons (Some 79)
                                                (Ssequence
                                                  (Scall None
                                                    (Evar _printf (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                    ((Evar ___stringlit_61 (tarray tuchar 11)) ::
                                                     nil))
                                                  (Ssequence
                                                    (Scall None
                                                      (Evar _print_reg 
                                                      (Tfunction
                                                        (Tcons tuint Tnil)
                                                        tvoid cc_default))
                                                      ((Etempvar _dst tuint) ::
                                                       nil))
                                                    (Ssequence
                                                      (Scall None
                                                        (Evar _print_reg 
                                                        (Tfunction
                                                          (Tcons tuint Tnil)
                                                          tvoid cc_default))
                                                        ((Etempvar _src tuint) ::
                                                         nil))
                                                      (Sreturn None))))
                                                (LScons (Some 95)
                                                  (Ssequence
                                                    (Scall None
                                                      (Evar _printf (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                      ((Evar ___stringlit_60 (tarray tuchar 11)) ::
                                                       nil))
                                                    (Ssequence
                                                      (Scall None
                                                        (Evar _print_reg 
                                                        (Tfunction
                                                          (Tcons tuint Tnil)
                                                          tvoid cc_default))
                                                        ((Etempvar _dst tuint) ::
                                                         nil))
                                                      (Ssequence
                                                        (Scall None
                                                          (Evar _print_reg 
                                                          (Tfunction
                                                            (Tcons tuint
                                                              Tnil) tvoid
                                                            cc_default))
                                                          ((Etempvar _src tuint) ::
                                                           nil))
                                                        (Sreturn None))))
                                                  (LScons (Some 111)
                                                    (Ssequence
                                                      (Scall None
                                                        (Evar _printf 
                                                        (Tfunction
                                                          (Tcons
                                                            (tptr tuchar)
                                                            Tnil) tint
                                                          {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                        ((Evar ___stringlit_59 (tarray tuchar 11)) ::
                                                         nil))
                                                      (Ssequence
                                                        (Scall None
                                                          (Evar _print_reg 
                                                          (Tfunction
                                                            (Tcons tuint
                                                              Tnil) tvoid
                                                            cc_default))
                                                          ((Etempvar _dst tuint) ::
                                                           nil))
                                                        (Ssequence
                                                          (Scall None
                                                            (Evar _print_reg 
                                                            (Tfunction
                                                              (Tcons tuint
                                                                Tnil) tvoid
                                                              cc_default))
                                                            ((Etempvar _src tuint) ::
                                                             nil))
                                                          (Sreturn None))))
                                                    (LScons (Some 127)
                                                      (Ssequence
                                                        (Scall None
                                                          (Evar _printf 
                                                          (Tfunction
                                                            (Tcons
                                                              (tptr tuchar)
                                                              Tnil) tint
                                                            {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                          ((Evar ___stringlit_58 (tarray tuchar 11)) ::
                                                           nil))
                                                        (Ssequence
                                                          (Scall None
                                                            (Evar _print_reg 
                                                            (Tfunction
                                                              (Tcons tuint
                                                                Tnil) tvoid
                                                              cc_default))
                                                            ((Etempvar _dst tuint) ::
                                                             nil))
                                                          (Ssequence
                                                            (Scall None
                                                              (Evar _print_reg 
                                                              (Tfunction
                                                                (Tcons tuint
                                                                  Tnil) tvoid
                                                                cc_default))
                                                              ((Etempvar _src tuint) ::
                                                               nil))
                                                            (Sreturn None))))
                                                      (LScons (Some 159)
                                                        (Ssequence
                                                          (Scall None
                                                            (Evar _printf 
                                                            (Tfunction
                                                              (Tcons
                                                                (tptr tuchar)
                                                                Tnil) tint
                                                              {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                            ((Evar ___stringlit_57 (tarray tuchar 11)) ::
                                                             nil))
                                                          (Ssequence
                                                            (Scall None
                                                              (Evar _print_reg 
                                                              (Tfunction
                                                                (Tcons tuint
                                                                  Tnil) tvoid
                                                                cc_default))
                                                              ((Etempvar _dst tuint) ::
                                                               nil))
                                                            (Ssequence
                                                              (Scall None
                                                                (Evar _print_reg 
                                                                (Tfunction
                                                                  (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                  tvoid
                                                                  cc_default))
                                                                ((Etempvar _src tuint) ::
                                                                 nil))
                                                              (Sreturn None))))
                                                        (LScons (Some 175)
                                                          (Ssequence
                                                            (Scall None
                                                              (Evar _printf 
                                                              (Tfunction
                                                                (Tcons
                                                                  (tptr tuchar)
                                                                  Tnil) tint
                                                                {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                              ((Evar ___stringlit_56 (tarray tuchar 11)) ::
                                                               nil))
                                                            (Ssequence
                                                              (Scall None
                                                                (Evar _print_reg 
                                                                (Tfunction
                                                                  (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                  tvoid
                                                                  cc_default))
                                                                ((Etempvar _dst tuint) ::
                                                                 nil))
                                                              (Ssequence
                                                                (Scall None
                                                                  (Evar _print_reg 
                                                                  (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                  ((Etempvar _src tuint) ::
                                                                   nil))
                                                                (Sreturn None))))
                                                          (LScons (Some 191)
                                                            (Ssequence
                                                              (Scall None
                                                                (Evar _printf 
                                                                (Tfunction
                                                                  (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                  tint
                                                                  {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                ((Evar ___stringlit_55 (tarray tuchar 11)) ::
                                                                 nil))
                                                              (Ssequence
                                                                (Scall None
                                                                  (Evar _print_reg 
                                                                  (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                  ((Etempvar _dst tuint) ::
                                                                   nil))
                                                                (Ssequence
                                                                  (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _src tuint) ::
                                                                    nil))
                                                                  (Sreturn None))))
                                                            (LScons (Some 207)
                                                              (Ssequence
                                                                (Scall None
                                                                  (Evar _printf 
                                                                  (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                  ((Evar ___stringlit_54 (tarray tuchar 12)) ::
                                                                   nil))
                                                                (Ssequence
                                                                  (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                  (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _src tuint) ::
                                                                    nil))
                                                                    (Sreturn None))))
                                                              (LScons (Some 4)
                                                                (Ssequence
                                                                  (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_51 (tarray tuchar 11)) ::
                                                                    nil))
                                                                  (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_38 (tarray tuchar 3)) ::
                                                                    (Etempvar _imm tint) ::
                                                                    nil))
                                                                    (Sreturn None))))
                                                                (LScons (Some 20)
                                                                  (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_50 (tarray tuchar 11)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_38 (tarray tuchar 3)) ::
                                                                    (Etempvar _imm tint) ::
                                                                    nil))
                                                                    (Sreturn None))))
                                                                  (LScons (Some 36)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_49 (tarray tuchar 11)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_38 (tarray tuchar 3)) ::
                                                                    (Etempvar _imm tint) ::
                                                                    nil))
                                                                    (Sreturn None))))
                                                                    (LScons (Some 52)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_48 (tarray tuchar 11)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_38 (tarray tuchar 3)) ::
                                                                    (Etempvar _imm tint) ::
                                                                    nil))
                                                                    (Sreturn None))))
                                                                    (LScons (Some 68)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_47 (tarray tuchar 11)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_38 (tarray tuchar 3)) ::
                                                                    (Etempvar _imm tint) ::
                                                                    nil))
                                                                    (Sreturn None))))
                                                                    (LScons (Some 84)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_46 (tarray tuchar 11)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_38 (tarray tuchar 3)) ::
                                                                    (Etempvar _imm tint) ::
                                                                    nil))
                                                                    (Sreturn None))))
                                                                    (LScons (Some 100)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_45 (tarray tuchar 11)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_38 (tarray tuchar 3)) ::
                                                                    (Etempvar _imm tint) ::
                                                                    nil))
                                                                    (Sreturn None))))
                                                                    (LScons (Some 116)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_44 (tarray tuchar 11)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_38 (tarray tuchar 3)) ::
                                                                    (Etempvar _imm tint) ::
                                                                    nil))
                                                                    (Sreturn None))))
                                                                    (LScons (Some 132)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_53 (tarray tuchar 11)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_38 (tarray tuchar 3)) ::
                                                                    (Etempvar _imm tint) ::
                                                                    nil))
                                                                    (Sreturn None))))
                                                                    (LScons (Some 148)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_43 (tarray tuchar 11)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_38 (tarray tuchar 3)) ::
                                                                    (Etempvar _imm tint) ::
                                                                    nil))
                                                                    (Sreturn None))))
                                                                    (LScons (Some 164)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_42 (tarray tuchar 11)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_38 (tarray tuchar 3)) ::
                                                                    (Etempvar _imm tint) ::
                                                                    nil))
                                                                    (Sreturn None))))
                                                                    (LScons (Some 180)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_41 (tarray tuchar 11)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_38 (tarray tuchar 3)) ::
                                                                    (Etempvar _imm tint) ::
                                                                    nil))
                                                                    (Sreturn None))))
                                                                    (LScons (Some 196)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_40 (tarray tuchar 12)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_38 (tarray tuchar 3)) ::
                                                                    (Etempvar _imm tint) ::
                                                                    nil))
                                                                    (Sreturn None))))
                                                                    (LScons (Some 212)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_52 (tarray tuchar 9)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_38 (tarray tuchar 3)) ::
                                                                    (Etempvar _ofs tint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_19 (tarray tuchar 5)) ::
                                                                    (Etempvar _imm tint) ::
                                                                    nil))
                                                                    (Sreturn None))))
                                                                    (LScons (Some 12)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_51 (tarray tuchar 11)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _src tuint) ::
                                                                    nil))
                                                                    (Sreturn None))))
                                                                    (LScons (Some 28)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_50 (tarray tuchar 11)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _src tuint) ::
                                                                    nil))
                                                                    (Sreturn None))))
                                                                    (LScons (Some 44)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_49 (tarray tuchar 11)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _src tuint) ::
                                                                    nil))
                                                                    (Sreturn None))))
                                                                    (LScons (Some 60)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_48 (tarray tuchar 11)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _src tuint) ::
                                                                    nil))
                                                                    (Sreturn None))))
                                                                    (LScons (Some 76)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_47 (tarray tuchar 11)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _src tuint) ::
                                                                    nil))
                                                                    (Sreturn None))))
                                                                    (LScons (Some 92)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_46 (tarray tuchar 11)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _src tuint) ::
                                                                    nil))
                                                                    (Sreturn None))))
                                                                    (LScons (Some 108)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_45 (tarray tuchar 11)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _src tuint) ::
                                                                    nil))
                                                                    (Sreturn None))))
                                                                    (LScons (Some 124)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_44 (tarray tuchar 11)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _src tuint) ::
                                                                    nil))
                                                                    (Sreturn None))))
                                                                    (LScons (Some 156)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_43 (tarray tuchar 11)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _src tuint) ::
                                                                    nil))
                                                                    (Sreturn None))))
                                                                    (LScons (Some 172)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_42 (tarray tuchar 11)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _src tuint) ::
                                                                    nil))
                                                                    (Sreturn None))))
                                                                    (LScons (Some 188)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_41 (tarray tuchar 11)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _src tuint) ::
                                                                    nil))
                                                                    (Sreturn None))))
                                                                    (LScons (Some 204)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_40 (tarray tuchar 12)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _src tuint) ::
                                                                    nil))
                                                                    (Sreturn None))))
                                                                    (LScons (Some 16)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_39 (tarray tuchar 14)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_38 (tarray tuchar 3)) ::
                                                                    (Etempvar _imm tint) ::
                                                                    nil))
                                                                    (Sreturn None))))
                                                                    (LScons (Some 24)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_37 (tarray tuchar 15)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_38 (tarray tuchar 3)) ::
                                                                    (Etempvar _imm tint) ::
                                                                    nil))
                                                                    (Sreturn None))))
                                                                    (LScons (Some 97)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_36 (tarray tuchar 11)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_33 (tarray tuchar 4)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _src tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_24 (tarray tuchar 6)) ::
                                                                    (Etempvar _ofs tint) ::
                                                                    nil))
                                                                    (Sreturn None))))))
                                                                    (LScons (Some 105)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_35 (tarray tuchar 11)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_33 (tarray tuchar 4)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _src tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_24 (tarray tuchar 6)) ::
                                                                    (Etempvar _ofs tint) ::
                                                                    nil))
                                                                    (Sreturn None))))))
                                                                    (LScons (Some 113)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_34 (tarray tuchar 11)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_33 (tarray tuchar 4)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _src tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_24 (tarray tuchar 6)) ::
                                                                    (Etempvar _ofs tint) ::
                                                                    nil))
                                                                    (Sreturn None))))))
                                                                    (LScons (Some 121)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_32 (tarray tuchar 11)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_33 (tarray tuchar 4)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _src tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_24 (tarray tuchar 6)) ::
                                                                    (Etempvar _ofs tint) ::
                                                                    nil))
                                                                    (Sreturn None))))))
                                                                    (LScons (Some 98)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_31 (tarray tuchar 10)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_23 (tarray tuchar 2)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_24 (tarray tuchar 6)) ::
                                                                    (Etempvar _ofs tint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_19 (tarray tuchar 5)) ::
                                                                    (Etempvar _imm tint) ::
                                                                    nil))
                                                                    (Sreturn None))))))
                                                                    (LScons (Some 106)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_30 (tarray tuchar 10)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_23 (tarray tuchar 2)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_24 (tarray tuchar 6)) ::
                                                                    (Etempvar _ofs tint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_19 (tarray tuchar 5)) ::
                                                                    (Etempvar _imm tint) ::
                                                                    nil))
                                                                    (Sreturn None))))))
                                                                    (LScons (Some 114)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_29 (tarray tuchar 10)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_23 (tarray tuchar 2)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_24 (tarray tuchar 6)) ::
                                                                    (Etempvar _ofs tint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_19 (tarray tuchar 5)) ::
                                                                    (Etempvar _imm tint) ::
                                                                    nil))
                                                                    (Sreturn None))))))
                                                                    (LScons (Some 122)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_28 (tarray tuchar 10)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_23 (tarray tuchar 2)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_24 (tarray tuchar 6)) ::
                                                                    (Etempvar _ofs tint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_19 (tarray tuchar 5)) ::
                                                                    (Etempvar _imm tint) ::
                                                                    nil))
                                                                    (Sreturn None))))))
                                                                    (LScons (Some 99)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_27 (tarray tuchar 11)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_23 (tarray tuchar 2)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_24 (tarray tuchar 6)) ::
                                                                    (Etempvar _ofs tint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_19 (tarray tuchar 5)) ::
                                                                    (Etempvar _imm tint) ::
                                                                    nil))
                                                                    (Sreturn None))))))
                                                                    (LScons (Some 107)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_26 (tarray tuchar 11)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_23 (tarray tuchar 2)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_24 (tarray tuchar 6)) ::
                                                                    (Etempvar _ofs tint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_19 (tarray tuchar 5)) ::
                                                                    (Etempvar _imm tint) ::
                                                                    nil))
                                                                    (Sreturn None))))))
                                                                    (LScons (Some 115)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_25 (tarray tuchar 11)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_23 (tarray tuchar 2)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_24 (tarray tuchar 6)) ::
                                                                    (Etempvar _ofs tint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_19 (tarray tuchar 5)) ::
                                                                    (Etempvar _imm tint) ::
                                                                    nil))
                                                                    (Sreturn None))))))
                                                                    (LScons (Some 123)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_22 (tarray tuchar 11)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_23 (tarray tuchar 2)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_24 (tarray tuchar 6)) ::
                                                                    (Etempvar _ofs tint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_19 (tarray tuchar 5)) ::
                                                                    (Etempvar _imm tint) ::
                                                                    nil))
                                                                    (Sreturn None))))))
                                                                    (LScons (Some 5)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_20 (tarray tuchar 8)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_21 (tarray tuchar 6)) ::
                                                                    (Etempvar _ofs tint) ::
                                                                    nil))
                                                                    (Sreturn None)))
                                                                    (LScons (Some 21)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_18 (tarray tuchar 9)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_19 (tarray tuchar 5)) ::
                                                                    (Etempvar _imm tint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_8 (tarray tuchar 6)) ::
                                                                    (Etempvar _ofs tint) ::
                                                                    nil))
                                                                    (Sreturn None)))))
                                                                    (LScons (Some 37)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_17 (tarray tuchar 9)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_19 (tarray tuchar 5)) ::
                                                                    (Etempvar _imm tint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_8 (tarray tuchar 6)) ::
                                                                    (Etempvar _ofs tint) ::
                                                                    nil))
                                                                    (Sreturn None)))))
                                                                    (LScons (Some 53)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_16 (tarray tuchar 9)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_19 (tarray tuchar 5)) ::
                                                                    (Etempvar _imm tint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_8 (tarray tuchar 6)) ::
                                                                    (Etempvar _ofs tint) ::
                                                                    nil))
                                                                    (Sreturn None)))))
                                                                    (LScons (Some 165)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_15 (tarray tuchar 9)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_19 (tarray tuchar 5)) ::
                                                                    (Etempvar _imm tint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_8 (tarray tuchar 6)) ::
                                                                    (Etempvar _ofs tint) ::
                                                                    nil))
                                                                    (Sreturn None)))))
                                                                    (LScons (Some 181)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_14 (tarray tuchar 9)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_19 (tarray tuchar 5)) ::
                                                                    (Etempvar _imm tint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_8 (tarray tuchar 6)) ::
                                                                    (Etempvar _ofs tint) ::
                                                                    nil))
                                                                    (Sreturn None)))))
                                                                    (LScons (Some 69)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_13 (tarray tuchar 10)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_19 (tarray tuchar 5)) ::
                                                                    (Etempvar _imm tint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_8 (tarray tuchar 6)) ::
                                                                    (Etempvar _ofs tint) ::
                                                                    nil))
                                                                    (Sreturn None)))))
                                                                    (LScons (Some 85)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_12 (tarray tuchar 9)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_19 (tarray tuchar 5)) ::
                                                                    (Etempvar _imm tint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_8 (tarray tuchar 6)) ::
                                                                    (Etempvar _ofs tint) ::
                                                                    nil))
                                                                    (Sreturn None)))))
                                                                    (LScons (Some 101)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_11 (tarray tuchar 10)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_19 (tarray tuchar 5)) ::
                                                                    (Etempvar _imm tint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_8 (tarray tuchar 6)) ::
                                                                    (Etempvar _ofs tint) ::
                                                                    nil))
                                                                    (Sreturn None)))))
                                                                    (LScons (Some 117)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_10 (tarray tuchar 10)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_19 (tarray tuchar 5)) ::
                                                                    (Etempvar _imm tint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_8 (tarray tuchar 6)) ::
                                                                    (Etempvar _ofs tint) ::
                                                                    nil))
                                                                    (Sreturn None)))))
                                                                    (LScons (Some 197)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_9 (tarray tuchar 10)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_19 (tarray tuchar 5)) ::
                                                                    (Etempvar _imm tint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_8 (tarray tuchar 6)) ::
                                                                    (Etempvar _ofs tint) ::
                                                                    nil))
                                                                    (Sreturn None)))))
                                                                    (LScons (Some 213)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_6 (tarray tuchar 10)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_19 (tarray tuchar 5)) ::
                                                                    (Etempvar _imm tint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_8 (tarray tuchar 6)) ::
                                                                    (Etempvar _ofs tint) ::
                                                                    nil))
                                                                    (Sreturn None)))))
                                                                    (LScons (Some 29)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_18 (tarray tuchar 9)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_7 (tarray tuchar 3)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _src tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_8 (tarray tuchar 6)) ::
                                                                    (Etempvar _ofs tint) ::
                                                                    nil))
                                                                    (Sreturn None))))))
                                                                    (LScons (Some 45)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_17 (tarray tuchar 9)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_7 (tarray tuchar 3)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _src tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_8 (tarray tuchar 6)) ::
                                                                    (Etempvar _ofs tint) ::
                                                                    nil))
                                                                    (Sreturn None))))))
                                                                    (LScons (Some 61)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_16 (tarray tuchar 9)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_7 (tarray tuchar 3)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _src tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_8 (tarray tuchar 6)) ::
                                                                    (Etempvar _ofs tint) ::
                                                                    nil))
                                                                    (Sreturn None))))))
                                                                    (LScons (Some 173)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_15 (tarray tuchar 9)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_7 (tarray tuchar 3)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _src tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_8 (tarray tuchar 6)) ::
                                                                    (Etempvar _ofs tint) ::
                                                                    nil))
                                                                    (Sreturn None))))))
                                                                    (LScons (Some 189)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_14 (tarray tuchar 9)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_7 (tarray tuchar 3)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _src tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_8 (tarray tuchar 6)) ::
                                                                    (Etempvar _ofs tint) ::
                                                                    nil))
                                                                    (Sreturn None))))))
                                                                    (LScons (Some 77)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_13 (tarray tuchar 10)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_7 (tarray tuchar 3)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _src tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_8 (tarray tuchar 6)) ::
                                                                    (Etempvar _ofs tint) ::
                                                                    nil))
                                                                    (Sreturn None))))))
                                                                    (LScons (Some 93)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_12 (tarray tuchar 9)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_7 (tarray tuchar 3)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _src tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_8 (tarray tuchar 6)) ::
                                                                    (Etempvar _ofs tint) ::
                                                                    nil))
                                                                    (Sreturn None))))))
                                                                    (LScons (Some 109)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_11 (tarray tuchar 10)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_7 (tarray tuchar 3)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _src tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_8 (tarray tuchar 6)) ::
                                                                    (Etempvar _ofs tint) ::
                                                                    nil))
                                                                    (Sreturn None))))))
                                                                    (LScons (Some 125)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_10 (tarray tuchar 10)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_7 (tarray tuchar 3)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _src tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_8 (tarray tuchar 6)) ::
                                                                    (Etempvar _ofs tint) ::
                                                                    nil))
                                                                    (Sreturn None))))))
                                                                    (LScons (Some 205)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_9 (tarray tuchar 10)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_7 (tarray tuchar 3)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _src tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_8 (tarray tuchar 6)) ::
                                                                    (Etempvar _ofs tint) ::
                                                                    nil))
                                                                    (Sreturn None))))))
                                                                    (LScons (Some 221)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_6 (tarray tuchar 10)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _dst tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_7 (tarray tuchar 3)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _print_reg 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                    tvoid
                                                                    cc_default))
                                                                    ((Etempvar _src tuint) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_8 (tarray tuchar 6)) ::
                                                                    (Etempvar _ofs tint) ::
                                                                    nil))
                                                                    (Sreturn None))))))
                                                                    (LScons (Some 133)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_4 (tarray tuchar 10)) ::
                                                                    nil))
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_5 (tarray tuchar 4)) ::
                                                                    (Etempvar _imm tint) ::
                                                                    nil))
                                                                    (Sreturn None)))
                                                                    (LScons (Some 149)
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_3 (tarray tuchar 10)) ::
                                                                    nil))
                                                                    (Sreturn None))
                                                                    (LScons None
                                                                    (Ssequence
                                                                    (Scall None
                                                                    (Evar _printf 
                                                                    (Tfunction
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil)
                                                                    tint
                                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                                    ((Evar ___stringlit_2 (tarray tuchar 15)) ::
                                                                    (Etempvar _op tuint) ::
                                                                    nil))
                                                                    (Sreturn None))
                                                                    LSnil)))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))
|}.

Definition f_print_jit_state := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Ssequence
  (Scall None
    (Evar _printf (Tfunction (Tcons (tptr tuchar) Tnil) tint
                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
    ((Evar ___stringlit_67 (tarray tuchar 19)) ::
     (Efield
       (Ederef (Etempvar _st (tptr (Tstruct _jit_state noattr)))
         (Tstruct _jit_state noattr)) _pc_loc tuint) ::
     (Ederef
       (Efield
         (Ederef (Etempvar _st (tptr (Tstruct _jit_state noattr)))
           (Tstruct _jit_state noattr)) _flag (tptr tuint)) tuint) :: nil))
  (Ssequence
    (Scall None
      (Evar _print_u64_dec (Tfunction Tnil tint
                             {|cc_vararg:=None; cc_unproto:=true; cc_structret:=false|}))
      ((Ederef
         (Ebinop Oadd
           (Efield
             (Ederef (Etempvar _st (tptr (Tstruct _jit_state noattr)))
               (Tstruct _jit_state noattr)) _regs_st (tptr tulong))
           (Econst_int (Int.repr 0) tint) (tptr tulong)) tulong) :: nil))
    (Ssequence
      (Scall None
        (Evar _printf (Tfunction (Tcons (tptr tuchar) Tnil) tint
                        {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
        ((Evar ___stringlit_68 (tarray tuchar 6)) :: nil))
      (Ssequence
        (Scall None
          (Evar _print_u64_dec (Tfunction Tnil tint
                                 {|cc_vararg:=None; cc_unproto:=true; cc_structret:=false|}))
          ((Ederef
             (Ebinop Oadd
               (Efield
                 (Ederef (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                   (Tstruct _jit_state noattr)) _regs_st (tptr tulong))
               (Econst_int (Int.repr 1) tint) (tptr tulong)) tulong) :: nil))
        (Ssequence
          (Scall None
            (Evar _printf (Tfunction (Tcons (tptr tuchar) Tnil) tint
                            {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
            ((Evar ___stringlit_69 (tarray tuchar 6)) :: nil))
          (Ssequence
            (Scall None
              (Evar _print_u64_dec (Tfunction Tnil tint
                                     {|cc_vararg:=None; cc_unproto:=true; cc_structret:=false|}))
              ((Ederef
                 (Ebinop Oadd
                   (Efield
                     (Ederef
                       (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                       (Tstruct _jit_state noattr)) _regs_st (tptr tulong))
                   (Econst_int (Int.repr 2) tint) (tptr tulong)) tulong) ::
               nil))
            (Ssequence
              (Scall None
                (Evar _printf (Tfunction (Tcons (tptr tuchar) Tnil) tint
                                {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                ((Evar ___stringlit_70 (tarray tuchar 6)) :: nil))
              (Ssequence
                (Scall None
                  (Evar _print_u64_dec (Tfunction Tnil tint
                                         {|cc_vararg:=None; cc_unproto:=true; cc_structret:=false|}))
                  ((Ederef
                     (Ebinop Oadd
                       (Efield
                         (Ederef
                           (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                           (Tstruct _jit_state noattr)) _regs_st
                         (tptr tulong)) (Econst_int (Int.repr 3) tint)
                       (tptr tulong)) tulong) :: nil))
                (Ssequence
                  (Scall None
                    (Evar _printf (Tfunction (Tcons (tptr tuchar) Tnil) tint
                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                    ((Evar ___stringlit_71 (tarray tuchar 6)) :: nil))
                  (Ssequence
                    (Scall None
                      (Evar _print_u64_dec (Tfunction Tnil tint
                                             {|cc_vararg:=None; cc_unproto:=true; cc_structret:=false|}))
                      ((Ederef
                         (Ebinop Oadd
                           (Efield
                             (Ederef
                               (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                               (Tstruct _jit_state noattr)) _regs_st
                             (tptr tulong)) (Econst_int (Int.repr 4) tint)
                           (tptr tulong)) tulong) :: nil))
                    (Ssequence
                      (Scall None
                        (Evar _printf (Tfunction (Tcons (tptr tuchar) Tnil)
                                        tint
                                        {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                        ((Evar ___stringlit_72 (tarray tuchar 6)) :: nil))
                      (Ssequence
                        (Scall None
                          (Evar _print_u64_dec (Tfunction Tnil tint
                                                 {|cc_vararg:=None; cc_unproto:=true; cc_structret:=false|}))
                          ((Ederef
                             (Ebinop Oadd
                               (Efield
                                 (Ederef
                                   (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                                   (Tstruct _jit_state noattr)) _regs_st
                                 (tptr tulong))
                               (Econst_int (Int.repr 5) tint) (tptr tulong))
                             tulong) :: nil))
                        (Ssequence
                          (Scall None
                            (Evar _printf (Tfunction
                                            (Tcons (tptr tuchar) Tnil) tint
                                            {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                            ((Evar ___stringlit_73 (tarray tuchar 6)) :: nil))
                          (Ssequence
                            (Scall None
                              (Evar _print_u64_dec (Tfunction Tnil tint
                                                     {|cc_vararg:=None; cc_unproto:=true; cc_structret:=false|}))
                              ((Ederef
                                 (Ebinop Oadd
                                   (Efield
                                     (Ederef
                                       (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                                       (Tstruct _jit_state noattr)) _regs_st
                                     (tptr tulong))
                                   (Econst_int (Int.repr 6) tint)
                                   (tptr tulong)) tulong) :: nil))
                            (Ssequence
                              (Scall None
                                (Evar _printf (Tfunction
                                                (Tcons (tptr tuchar) Tnil)
                                                tint
                                                {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                ((Evar ___stringlit_74 (tarray tuchar 6)) ::
                                 nil))
                              (Ssequence
                                (Scall None
                                  (Evar _print_u64_dec (Tfunction Tnil tint
                                                         {|cc_vararg:=None; cc_unproto:=true; cc_structret:=false|}))
                                  ((Ederef
                                     (Ebinop Oadd
                                       (Efield
                                         (Ederef
                                           (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                                           (Tstruct _jit_state noattr))
                                         _regs_st (tptr tulong))
                                       (Econst_int (Int.repr 7) tint)
                                       (tptr tulong)) tulong) :: nil))
                                (Ssequence
                                  (Scall None
                                    (Evar _printf (Tfunction
                                                    (Tcons (tptr tuchar)
                                                      Tnil) tint
                                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                    ((Evar ___stringlit_75 (tarray tuchar 6)) ::
                                     nil))
                                  (Ssequence
                                    (Scall None
                                      (Evar _print_u64_dec (Tfunction Tnil
                                                             tint
                                                             {|cc_vararg:=None; cc_unproto:=true; cc_structret:=false|}))
                                      ((Ederef
                                         (Ebinop Oadd
                                           (Efield
                                             (Ederef
                                               (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                                               (Tstruct _jit_state noattr))
                                             _regs_st (tptr tulong))
                                           (Econst_int (Int.repr 8) tint)
                                           (tptr tulong)) tulong) :: nil))
                                    (Ssequence
                                      (Scall None
                                        (Evar _printf (Tfunction
                                                        (Tcons (tptr tuchar)
                                                          Tnil) tint
                                                        {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                        ((Evar ___stringlit_76 (tarray tuchar 6)) ::
                                         nil))
                                      (Ssequence
                                        (Scall None
                                          (Evar _print_u64_dec (Tfunction
                                                                 Tnil tint
                                                                 {|cc_vararg:=None; cc_unproto:=true; cc_structret:=false|}))
                                          ((Ederef
                                             (Ebinop Oadd
                                               (Efield
                                                 (Ederef
                                                   (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                                                   (Tstruct _jit_state noattr))
                                                 _regs_st (tptr tulong))
                                               (Econst_int (Int.repr 9) tint)
                                               (tptr tulong)) tulong) :: nil))
                                        (Ssequence
                                          (Scall None
                                            (Evar _printf (Tfunction
                                                            (Tcons
                                                              (tptr tuchar)
                                                              Tnil) tint
                                                            {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                            ((Evar ___stringlit_77 (tarray tuchar 6)) ::
                                             nil))
                                          (Ssequence
                                            (Scall None
                                              (Evar _print_u64_dec (Tfunction
                                                                    Tnil tint
                                                                    {|cc_vararg:=None; cc_unproto:=true; cc_structret:=false|}))
                                              ((Ederef
                                                 (Ebinop Oadd
                                                   (Efield
                                                     (Ederef
                                                       (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                                                       (Tstruct _jit_state noattr))
                                                     _regs_st (tptr tulong))
                                                   (Econst_int (Int.repr 10) tint)
                                                   (tptr tulong)) tulong) ::
                                               nil))
                                            (Ssequence
                                              (Scall None
                                                (Evar _printf (Tfunction
                                                                (Tcons
                                                                  (tptr tuchar)
                                                                  Tnil) tint
                                                                {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                                                ((Evar ___stringlit_78 (tarray tuchar 7)) ::
                                                 nil))
                                              (Sreturn None))))))))))))))))))))))))
|}.

Definition f_print_load_store_regs := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: nil);
  fn_vars := nil;
  fn_temps := ((_i, tuint) :: nil);
  fn_body :=
(Ssequence
  (Ssequence
    (Sset _i (Econst_int (Int.repr 0) tint))
    (Sloop
      (Ssequence
        (Sifthenelse (Ebinop Olt (Etempvar _i tuint)
                       (Econst_int (Int.repr 11) tint) tint)
          Sskip
          Sbreak)
        (Ssequence
          (Scall None
            (Evar _printf (Tfunction (Tcons (tptr tuchar) Tnil) tint
                            {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
            ((Evar ___stringlit_79 (tarray tuchar 4)) ::
             (Etempvar _i tuint) :: nil))
          (Sifthenelse (Ebinop Oeq
                         (Ederef
                           (Ebinop Oadd
                             (Efield
                               (Ederef
                                 (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                                 (Tstruct _jit_state noattr))
                               _load_store_regs (tptr tuint))
                             (Etempvar _i tuint) (tptr tuint)) tuint)
                         (Econst_int (Int.repr 0) tint) tint)
            (Scall None
              (Evar _printf (Tfunction (Tcons (tptr tuchar) Tnil) tint
                              {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
              ((Evar ___stringlit_84 (tarray tuchar 18)) :: nil))
            (Sifthenelse (Ebinop Oeq
                           (Ederef
                             (Ebinop Oadd
                               (Efield
                                 (Ederef
                                   (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                                   (Tstruct _jit_state noattr))
                                 _load_store_regs (tptr tuint))
                               (Etempvar _i tuint) (tptr tuint)) tuint)
                           (Econst_int (Int.repr 1) tint) tint)
              (Scall None
                (Evar _printf (Tfunction (Tcons (tptr tuchar) Tnil) tint
                                {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                ((Evar ___stringlit_83 (tarray tuchar 19)) :: nil))
              (Sifthenelse (Ebinop Oeq
                             (Ederef
                               (Ebinop Oadd
                                 (Efield
                                   (Ederef
                                     (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                                     (Tstruct _jit_state noattr))
                                   _load_store_regs (tptr tuint))
                                 (Etempvar _i tuint) (tptr tuint)) tuint)
                             (Econst_int (Int.repr 2) tint) tint)
                (Scall None
                  (Evar _printf (Tfunction (Tcons (tptr tuchar) Tnil) tint
                                  {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                  ((Evar ___stringlit_82 (tarray tuchar 20)) :: nil))
                (Sifthenelse (Ebinop Oeq
                               (Ederef
                                 (Ebinop Oadd
                                   (Efield
                                     (Ederef
                                       (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                                       (Tstruct _jit_state noattr))
                                     _load_store_regs (tptr tuint))
                                   (Etempvar _i tuint) (tptr tuint)) tuint)
                               (Econst_int (Int.repr 3) tint) tint)
                  (Scall None
                    (Evar _printf (Tfunction (Tcons (tptr tuchar) Tnil) tint
                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                    ((Evar ___stringlit_81 (tarray tuchar 24)) :: nil))
                  (Scall None
                    (Evar _printf (Tfunction (Tcons (tptr tuchar) Tnil) tint
                                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                    ((Evar ___stringlit_80 (tarray tuchar 16)) :: nil))))))))
      (Sset _i
        (Ebinop Oadd (Etempvar _i tuint) (Econst_int (Int.repr 1) tint)
          tuint))))
  (Ssequence
    (Scall None
      (Evar _printf (Tfunction (Tcons (tptr tuchar) Tnil) tint
                      {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
      ((Evar ___stringlit_85 (tarray tuchar 2)) :: nil))
    (Sreturn None)))
|}.

Definition f_print_thumb := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: nil);
  fn_vars := nil;
  fn_temps := ((_i, tuint) :: nil);
  fn_body :=
(Ssequence
  (Scall None
    (Evar _printf (Tfunction (Tcons (tptr tuchar) Tnil) tint
                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
    ((Evar ___stringlit_86 (tarray tuchar 13)) :: nil))
  (Ssequence
    (Ssequence
      (Sset _i (Econst_int (Int.repr 0) tint))
      (Sloop
        (Ssequence
          (Sifthenelse (Ebinop Olt (Etempvar _i tuint)
                         (Efield
                           (Ederef
                             (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                             (Tstruct _jit_state noattr)) _thumb_len tuint)
                         tint)
            Sskip
            Sbreak)
          (Ssequence
            (Scall None
              (Evar _printf (Tfunction (Tcons (tptr tuchar) Tnil) tint
                              {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
              ((Evar ___stringlit_87 (tarray tuchar 9)) ::
               (Etempvar _i tuint) ::
               (Ederef
                 (Ebinop Oadd
                   (Efield
                     (Ederef
                       (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                       (Tstruct _jit_state noattr)) _thumb (tptr tushort))
                   (Etempvar _i tuint) (tptr tushort)) tushort) :: nil))
            (Sifthenelse (Ebinop Oeq
                           (Ebinop Omod
                             (Ebinop Oadd (Etempvar _i tuint)
                               (Econst_int (Int.repr 1) tint) tuint)
                             (Econst_int (Int.repr 8) tint) tuint)
                           (Econst_int (Int.repr 0) tint) tint)
              (Scall None
                (Evar _printf (Tfunction (Tcons (tptr tuchar) Tnil) tint
                                {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
                ((Evar ___stringlit_85 (tarray tuchar 2)) :: nil))
              Sskip)))
        (Sset _i
          (Ebinop Oadd (Etempvar _i tuint) (Econst_int (Int.repr 1) tint)
            tuint))))
    (Ssequence
      (Scall None
        (Evar _printf (Tfunction (Tcons (tptr tuchar) Tnil) tint
                        {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
        ((Evar ___stringlit_85 (tarray tuchar 2)) :: nil))
      (Sreturn None))))
|}.

Definition f_print_ibpf := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: nil);
  fn_vars := nil;
  fn_temps := ((_i, tuint) :: nil);
  fn_body :=
(Ssequence
  (Scall None
    (Evar _printf (Tfunction (Tcons (tptr tuchar) Tnil) tint
                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
    ((Evar ___stringlit_88 (tarray tuchar 12)) :: nil))
  (Ssequence
    (Ssequence
      (Sset _i (Econst_int (Int.repr 0) tint))
      (Sloop
        (Ssequence
          (Sifthenelse (Ebinop Olt (Etempvar _i tuint)
                         (Efield
                           (Ederef
                             (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                             (Tstruct _jit_state noattr)) _ins_len tuint)
                         tint)
            Sskip
            Sbreak)
          (Ssequence
            (Scall None
              (Evar _print_bpf_insstruction (Tfunction (Tcons tulong Tnil)
                                              tvoid cc_default))
              ((Ederef
                 (Ebinop Oadd
                   (Efield
                     (Ederef
                       (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                       (Tstruct _jit_state noattr)) _jit_ins (tptr tulong))
                   (Etempvar _i tuint) (tptr tulong)) tulong) :: nil))
            (Scall None
              (Evar _printf (Tfunction (Tcons (tptr tuchar) Tnil) tint
                              {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
              ((Evar ___stringlit_89 (tarray tuchar 6)) ::
               (Etempvar _i tuint) :: nil))))
        (Sset _i
          (Ebinop Oadd (Etempvar _i tuint) (Econst_int (Int.repr 1) tint)
            tuint))))
    (Ssequence
      (Scall None
        (Evar _printf (Tfunction (Tcons (tptr tuchar) Tnil) tint
                        {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
        ((Evar ___stringlit_85 (tarray tuchar 2)) :: nil))
      (Sreturn None))))
|}.

Definition f_print_jitted_arm := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: nil);
  fn_vars := nil;
  fn_temps := ((_i, tuint) :: nil);
  fn_body :=
(Ssequence
  (Scall None
    (Evar _printf (Tfunction (Tcons (tptr tuchar) Tnil) tint
                    {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
    ((Evar ___stringlit_90 (tarray tuchar 20)) :: nil))
  (Ssequence
    (Ssequence
      (Sset _i (Econst_int (Int.repr 0) tint))
      (Sloop
        (Ssequence
          (Sifthenelse (Ebinop Olt (Etempvar _i tuint)
                         (Efield
                           (Ederef
                             (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                             (Tstruct _jit_state noattr)) _jitted_len tuint)
                         tint)
            Sskip
            Sbreak)
          (Scall None
            (Evar _printf (Tfunction (Tcons (tptr tuchar) Tnil) tint
                            {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
            ((Evar ___stringlit_91 (tarray tuchar 13)) ::
             (Etempvar _i tuint) ::
             (Ederef
               (Ebinop Oadd
                 (Efield
                   (Ederef (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                     (Tstruct _jit_state noattr)) _jitted_list
                   (tptr tushort)) (Etempvar _i tuint) (tptr tushort))
               tushort) :: nil)))
        (Sset _i
          (Ebinop Oadd (Etempvar _i tuint) (Econst_int (Int.repr 1) tint)
            tuint))))
    (Ssequence
      (Scall None
        (Evar _printf (Tfunction (Tcons (tptr tuchar) Tnil) tint
                        {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
        ((Evar ___stringlit_85 (tarray tuchar 2)) :: nil))
      (Sreturn None))))
|}.

Definition f_print_jit_state_all := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Ssequence
  (Scall None
    (Evar _print_jit_state (Tfunction
                             (Tcons (tptr (Tstruct _jit_state noattr)) Tnil)
                             tvoid cc_default))
    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) :: nil))
  (Ssequence
    (Scall None
      (Evar _print_ibpf (Tfunction
                          (Tcons (tptr (Tstruct _jit_state noattr)) Tnil)
                          tvoid cc_default))
      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) :: nil))
    (Ssequence
      (Scall None
        (Evar _print_load_store_regs (Tfunction
                                       (Tcons
                                         (tptr (Tstruct _jit_state noattr))
                                         Tnil) tvoid cc_default))
        ((Etempvar _st (tptr (Tstruct _jit_state noattr))) :: nil))
      (Ssequence
        (Scall None
          (Evar _print_jitted_arm (Tfunction
                                    (Tcons (tptr (Tstruct _jit_state noattr))
                                      Tnil) tvoid cc_default))
          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) :: nil))
        (Sreturn None)))))
|}.

Definition f_eval_pc := {|
  fn_return := tuint;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sreturn (Some (Efield
                 (Ederef (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                   (Tstruct _jit_state noattr)) _pc_loc tuint)))
|}.

Definition f_upd_pc := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: (_pc, tuint) ::
                nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Ssequence
  (Sassign
    (Efield
      (Ederef (Etempvar _st (tptr (Tstruct _jit_state noattr)))
        (Tstruct _jit_state noattr)) _pc_loc tuint) (Etempvar _pc tuint))
  (Sreturn None))
|}.

Definition f_upd_pc_incr := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Ssequence
  (Sassign
    (Efield
      (Ederef (Etempvar _st (tptr (Tstruct _jit_state noattr)))
        (Tstruct _jit_state noattr)) _pc_loc tuint)
    (Ebinop Oadd
      (Efield
        (Ederef (Etempvar _st (tptr (Tstruct _jit_state noattr)))
          (Tstruct _jit_state noattr)) _pc_loc tuint)
      (Econst_int (Int.repr 1) tint) tuint))
  (Sreturn None))
|}.

Definition f_eval_reg := {|
  fn_return := tulong;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: (_i, tuint) ::
                nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sreturn (Some (Ederef
                 (Ebinop Oadd
                   (Efield
                     (Ederef
                       (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                       (Tstruct _jit_state noattr)) _regs_st (tptr tulong))
                   (Etempvar _i tuint) (tptr tulong)) tulong)))
|}.

Definition f_upd_reg := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: (_i, tuint) ::
                (_v, tulong) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Ssequence
  (Sassign
    (Ederef
      (Ebinop Oadd
        (Efield
          (Ederef (Etempvar _st (tptr (Tstruct _jit_state noattr)))
            (Tstruct _jit_state noattr)) _regs_st (tptr tulong))
        (Etempvar _i tuint) (tptr tulong)) tulong) (Etempvar _v tulong))
  (Sreturn None))
|}.

Definition f_eval_flag := {|
  fn_return := tuint;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sreturn (Some (Ederef
                 (Efield
                   (Ederef (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                     (Tstruct _jit_state noattr)) _flag (tptr tuint)) tuint)))
|}.

Definition f_upd_flag := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: (_f, tuint) ::
                nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Ssequence
  (Sassign
    (Ederef
      (Efield
        (Ederef (Etempvar _st (tptr (Tstruct _jit_state noattr)))
          (Tstruct _jit_state noattr)) _flag (tptr tuint)) tuint)
    (Etempvar _f tuint))
  (Sreturn None))
|}.

Definition f_eval_mrs_num := {|
  fn_return := tuint;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sreturn (Some (Efield
                 (Ederef (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                   (Tstruct _jit_state noattr)) _mrs_num tuint)))
|}.

Definition f_eval_mrs_regions := {|
  fn_return := (tptr (Tstruct _memory_region noattr));
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sreturn (Some (Efield
                 (Ederef (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                   (Tstruct _jit_state noattr)) _bpf_mrs
                 (tptr (Tstruct _memory_region noattr)))))
|}.

Definition f_load_mem := {|
  fn_return := tulong;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) ::
                (_chunk, tuint) :: (_addr, (tptr tuchar)) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sswitch (Etempvar _chunk tuint)
  (LScons (Some 1)
    (Sreturn (Some (Ederef
                     (Ecast (Etempvar _addr (tptr tuchar)) (tptr tuchar))
                     tuchar)))
    (LScons (Some 2)
      (Sreturn (Some (Ederef
                       (Ecast (Etempvar _addr (tptr tuchar)) (tptr tushort))
                       tushort)))
      (LScons (Some 4)
        (Sreturn (Some (Ederef
                         (Ecast (Etempvar _addr (tptr tuchar)) (tptr tuint))
                         tuint)))
        (LScons (Some 8)
          (Sreturn (Some (Ederef
                           (Ecast (Etempvar _addr (tptr tuchar))
                             (tptr tulong)) tulong)))
          (LScons None
            (Sreturn (Some (Econst_long (Int64.repr 0) tulong)))
            LSnil))))))
|}.

Definition f_store_mem_reg := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) ::
                (_addr, (tptr tuchar)) :: (_chunk, tuint) :: (_v, tulong) ::
                nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sswitch (Etempvar _chunk tuint)
  (LScons (Some 1)
    (Ssequence
      (Sassign
        (Ederef (Ecast (Etempvar _addr (tptr tuchar)) (tptr tuchar)) tuchar)
        (Etempvar _v tulong))
      (Sreturn None))
    (LScons (Some 2)
      (Ssequence
        (Sassign
          (Ederef (Ecast (Etempvar _addr (tptr tuchar)) (tptr tushort))
            tushort) (Etempvar _v tulong))
        (Sreturn None))
      (LScons (Some 4)
        (Ssequence
          (Sassign
            (Ederef (Ecast (Etempvar _addr (tptr tuchar)) (tptr tuint))
              tuint) (Etempvar _v tulong))
          (Sreturn None))
        (LScons (Some 8)
          (Ssequence
            (Sassign
              (Ederef (Ecast (Etempvar _addr (tptr tuchar)) (tptr tulong))
                tulong) (Etempvar _v tulong))
            (Sreturn None))
          (LScons None (Sreturn None) LSnil))))))
|}.

Definition f_store_mem_imm := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) ::
                (_addr, (tptr tuchar)) :: (_chunk, tuint) :: (_v, tint) ::
                nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sswitch (Etempvar _chunk tuint)
  (LScons (Some 1)
    (Ssequence
      (Sassign
        (Ederef (Ecast (Etempvar _addr (tptr tuchar)) (tptr tuchar)) tuchar)
        (Etempvar _v tint))
      (Sreturn None))
    (LScons (Some 2)
      (Ssequence
        (Sassign
          (Ederef (Ecast (Etempvar _addr (tptr tuchar)) (tptr tushort))
            tushort) (Etempvar _v tint))
        (Sreturn None))
      (LScons (Some 4)
        (Ssequence
          (Sassign
            (Ederef (Ecast (Etempvar _addr (tptr tuchar)) (tptr tuint))
              tuint) (Etempvar _v tint))
          (Sreturn None))
        (LScons (Some 8)
          (Ssequence
            (Sassign
              (Ederef (Ecast (Etempvar _addr (tptr tuchar)) (tptr tulong))
                tulong) (Etempvar _v tint))
            (Sreturn None))
          (LScons None (Sreturn None) LSnil))))))
|}.

Definition f_eval_ins_len := {|
  fn_return := tuint;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sreturn (Some (Efield
                 (Ederef (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                   (Tstruct _jit_state noattr)) _ins_len tuint)))
|}.

Definition f_eval_ins := {|
  fn_return := tulong;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: (_idx, tuint) ::
                nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sreturn (Some (Ederef
                 (Ebinop Oadd
                   (Efield
                     (Ederef
                       (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                       (Tstruct _jit_state noattr)) _jit_ins (tptr tulong))
                   (Etempvar _idx tuint) (tptr tulong)) tulong)))
|}.

Definition f_cmp_ptr32_nullM := {|
  fn_return := tbool;
  fn_callconv := cc_default;
  fn_params := ((_addr, (tptr tuchar)) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sreturn (Some (Ebinop Oeq (Etempvar _addr (tptr tuchar))
                 (Ecast (Econst_int (Int.repr 0) tint) (tptr tvoid)) tint)))
|}.

Definition f_get_dst := {|
  fn_return := tuint;
  fn_callconv := cc_default;
  fn_params := ((_ins, tulong) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sreturn (Some (Ecast
                 (Ebinop Oshr
                   (Ebinop Oand (Etempvar _ins tulong)
                     (Econst_long (Int64.repr 4095) tulong) tulong)
                   (Econst_long (Int64.repr 8) tulong) tulong) tuint)))
|}.

Definition f_get_src := {|
  fn_return := tuint;
  fn_callconv := cc_default;
  fn_params := ((_ins, tulong) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sreturn (Some (Ecast
                 (Ebinop Oshr
                   (Ebinop Oand (Etempvar _ins tulong)
                     (Econst_long (Int64.repr 65535) tulong) tulong)
                   (Econst_long (Int64.repr 12) tulong) tulong) tuint)))
|}.

Definition f_get_mem_region := {|
  fn_return := (tptr (Tstruct _memory_region noattr));
  fn_callconv := cc_default;
  fn_params := ((_n, tuint) ::
                (_mrs, (tptr (Tstruct _memory_region noattr))) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sreturn (Some (Ebinop Oadd
                 (Etempvar _mrs (tptr (Tstruct _memory_region noattr)))
                 (Etempvar _n tuint) (tptr (Tstruct _memory_region noattr)))))
|}.

Definition f__bpf_get_call := {|
  fn_return := (tptr tuchar);
  fn_callconv := cc_default;
  fn_params := ((_imm, tint) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sreturn (Some (Ecast (Econst_int (Int.repr 0) tint) (tptr tvoid))))
|}.

Definition f_exec_function := {|
  fn_return := tuint;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) ::
                (_ptr, (tptr tuchar)) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sifthenelse (Ebinop Oeq (Etempvar _ptr (tptr tuchar))
               (Ecast (Econst_int (Int.repr 0) tint) (tptr tvoid)) tint)
  (Ssequence
    (Sassign
      (Ederef
        (Efield
          (Ederef (Etempvar _st (tptr (Tstruct _jit_state noattr)))
            (Tstruct _jit_state noattr)) _flag (tptr tuint)) tuint)
      (Econst_int (Int.repr 5) tint))
    (Sreturn (Some (Econst_int (Int.repr 0) tuint))))
  (Sreturn (Some (Econst_int (Int.repr 0) tuint))))
|}.

Definition f_upd_IR11_jittedthumb := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: (_f, tbool) ::
                nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Ssequence
  (Sassign
    (Efield
      (Ederef (Etempvar _st (tptr (Tstruct _jit_state noattr)))
        (Tstruct _jit_state noattr)) _use_IR11 tbool) (Etempvar _f tbool))
  (Sreturn None))
|}.

Definition f_add_ins_jittedthumb := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: (_ins, tuint) ::
                nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sifthenelse (Ebinop Olt
               (Efield
                 (Ederef (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                   (Tstruct _jit_state noattr)) _ins_len tuint)
               (Econst_int (Int.repr 1000) tint) tint)
  (Ssequence
    (Sassign
      (Ederef
        (Ebinop Oadd
          (Efield
            (Ederef (Etempvar _st (tptr (Tstruct _jit_state noattr)))
              (Tstruct _jit_state noattr)) _thumb (tptr tushort))
          (Efield
            (Ederef (Etempvar _st (tptr (Tstruct _jit_state noattr)))
              (Tstruct _jit_state noattr)) _thumb_len tuint) (tptr tushort))
        tushort) (Etempvar _ins tuint))
    (Ssequence
      (Sassign
        (Efield
          (Ederef (Etempvar _st (tptr (Tstruct _jit_state noattr)))
            (Tstruct _jit_state noattr)) _thumb_len tuint)
        (Ebinop Oadd
          (Efield
            (Ederef (Etempvar _st (tptr (Tstruct _jit_state noattr)))
              (Tstruct _jit_state noattr)) _thumb_len tuint)
          (Econst_int (Int.repr 1) tuint) tuint))
      (Sreturn None)))
  (Ssequence
    (Sassign
      (Ederef
        (Efield
          (Ederef (Etempvar _st (tptr (Tstruct _jit_state noattr)))
            (Tstruct _jit_state noattr)) _flag (tptr tuint)) tuint)
      (Econst_int (Int.repr 14) tint))
    (Sreturn None)))
|}.

Definition f_upd_bpf_offset_jittedthumb := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Ssequence
  (Sassign
    (Efield
      (Ederef (Etempvar _st (tptr (Tstruct _jit_state noattr)))
        (Tstruct _jit_state noattr)) _offset tuint)
    (Ebinop Oadd
      (Efield
        (Ederef (Etempvar _st (tptr (Tstruct _jit_state noattr)))
          (Tstruct _jit_state noattr)) _offset tuint)
      (Econst_int (Int.repr 1) tuint) tuint))
  (Sreturn None))
|}.

Definition f_upd_load_store_regs_jittedthumb := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: (_r, tuint) ::
                (_ls, tuint) :: nil);
  fn_vars := nil;
  fn_temps := ((_history, tuint) :: (_t'1, tint) :: nil);
  fn_body :=
(Ssequence
  (Sset _history
    (Ederef
      (Ebinop Oadd
        (Efield
          (Ederef (Etempvar _st (tptr (Tstruct _jit_state noattr)))
            (Tstruct _jit_state noattr)) _load_store_regs (tptr tuint))
        (Etempvar _r tuint) (tptr tuint)) tuint))
  (Ssequence
    (Sifthenelse (Ebinop Oeq (Etempvar _ls tuint)
                   (Econst_int (Int.repr 1) tint) tint)
      (Ssequence
        (Sifthenelse (Ebinop Oeq (Etempvar _history tuint)
                       (Econst_int (Int.repr 0) tint) tint)
          (Sset _t'1 (Econst_int (Int.repr 1) tint))
          (Sset _t'1
            (Ecast
              (Ebinop Oeq (Etempvar _history tuint)
                (Econst_int (Int.repr 1) tint) tint) tbool)))
        (Sifthenelse (Etempvar _t'1 tint)
          (Sassign
            (Ederef
              (Ebinop Oadd
                (Efield
                  (Ederef (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                    (Tstruct _jit_state noattr)) _load_store_regs
                  (tptr tuint)) (Etempvar _r tuint) (tptr tuint)) tuint)
            (Econst_int (Int.repr 1) tint))
          (Sifthenelse (Ebinop Oeq (Etempvar _history tuint)
                         (Econst_int (Int.repr 2) tint) tint)
            (Sassign
              (Ederef
                (Ebinop Oadd
                  (Efield
                    (Ederef (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                      (Tstruct _jit_state noattr)) _load_store_regs
                    (tptr tuint)) (Etempvar _r tuint) (tptr tuint)) tuint)
              (Econst_int (Int.repr 2) tint))
            (Sifthenelse (Ebinop Oeq (Etempvar _history tuint)
                           (Econst_int (Int.repr 3) tint) tint)
              (Sassign
                (Ederef
                  (Ebinop Oadd
                    (Efield
                      (Ederef
                        (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                        (Tstruct _jit_state noattr)) _load_store_regs
                      (tptr tuint)) (Etempvar _r tuint) (tptr tuint)) tuint)
                (Econst_int (Int.repr 3) tint))
              Sskip))))
      (Sifthenelse (Ebinop Oeq (Etempvar _ls tuint)
                     (Econst_int (Int.repr 2) tint) tint)
        (Sifthenelse (Ebinop Oeq (Etempvar _history tuint)
                       (Econst_int (Int.repr 0) tint) tint)
          (Sassign
            (Ederef
              (Ebinop Oadd
                (Efield
                  (Ederef (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                    (Tstruct _jit_state noattr)) _load_store_regs
                  (tptr tuint)) (Etempvar _r tuint) (tptr tuint)) tuint)
            (Econst_int (Int.repr 2) tint))
          (Sifthenelse (Ebinop Oeq (Etempvar _history tuint)
                         (Econst_int (Int.repr 1) tint) tint)
            (Sassign
              (Ederef
                (Ebinop Oadd
                  (Efield
                    (Ederef (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                      (Tstruct _jit_state noattr)) _load_store_regs
                    (tptr tuint)) (Etempvar _r tuint) (tptr tuint)) tuint)
              (Econst_int (Int.repr 3) tint))
            (Sifthenelse (Ebinop Oeq (Etempvar _history tuint)
                           (Econst_int (Int.repr 2) tint) tint)
              (Sassign
                (Ederef
                  (Ebinop Oadd
                    (Efield
                      (Ederef
                        (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                        (Tstruct _jit_state noattr)) _load_store_regs
                      (tptr tuint)) (Etempvar _r tuint) (tptr tuint)) tuint)
                (Econst_int (Int.repr 2) tint))
              (Sifthenelse (Ebinop Oeq (Etempvar _history tuint)
                             (Econst_int (Int.repr 3) tint) tint)
                (Sassign
                  (Ederef
                    (Ebinop Oadd
                      (Efield
                        (Ederef
                          (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                          (Tstruct _jit_state noattr)) _load_store_regs
                        (tptr tuint)) (Etempvar _r tuint) (tptr tuint))
                    tuint) (Econst_int (Int.repr 3) tint))
                Sskip))))
        (Sifthenelse (Ebinop Oeq (Etempvar _ls tuint)
                       (Econst_int (Int.repr 3) tint) tint)
          (Sifthenelse (Ebinop Oeq (Etempvar _history tuint)
                         (Econst_int (Int.repr 0) tint) tint)
            (Sassign
              (Ederef
                (Ebinop Oadd
                  (Efield
                    (Ederef (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                      (Tstruct _jit_state noattr)) _load_store_regs
                    (tptr tuint)) (Etempvar _r tuint) (tptr tuint)) tuint)
              (Econst_int (Int.repr 3) tint))
            (Sifthenelse (Ebinop Oeq (Etempvar _history tuint)
                           (Econst_int (Int.repr 1) tint) tint)
              (Sassign
                (Ederef
                  (Ebinop Oadd
                    (Efield
                      (Ederef
                        (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                        (Tstruct _jit_state noattr)) _load_store_regs
                      (tptr tuint)) (Etempvar _r tuint) (tptr tuint)) tuint)
                (Econst_int (Int.repr 3) tint))
              (Sifthenelse (Ebinop Oeq (Etempvar _history tuint)
                             (Econst_int (Int.repr 2) tint) tint)
                (Sassign
                  (Ederef
                    (Ebinop Oadd
                      (Efield
                        (Ederef
                          (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                          (Tstruct _jit_state noattr)) _load_store_regs
                        (tptr tuint)) (Etempvar _r tuint) (tptr tuint))
                    tuint) (Econst_int (Int.repr 2) tint))
                (Sifthenelse (Ebinop Oeq (Etempvar _history tuint)
                               (Econst_int (Int.repr 3) tint) tint)
                  (Sassign
                    (Ederef
                      (Ebinop Oadd
                        (Efield
                          (Ederef
                            (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                            (Tstruct _jit_state noattr)) _load_store_regs
                          (tptr tuint)) (Etempvar _r tuint) (tptr tuint))
                      tuint) (Econst_int (Int.repr 3) tint))
                  Sskip))))
          Sskip)))
    (Sreturn None)))
|}.

Definition f_upd_thumb_jittedthumb := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: (_ins, tuint) ::
                (_pc, tuint) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Ssequence
  (Sassign
    (Ederef
      (Ebinop Oadd
        (Efield
          (Ederef (Etempvar _st (tptr (Tstruct _jit_state noattr)))
            (Tstruct _jit_state noattr)) _thumb (tptr tushort))
        (Etempvar _pc tuint) (tptr tushort)) tushort) (Etempvar _ins tuint))
  (Sreturn None))
|}.

Definition f_upd_jitted_list := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: (_ins, tuint) ::
                nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Ssequence
  (Sassign
    (Ederef
      (Ebinop Oadd
        (Efield
          (Ederef (Etempvar _st (tptr (Tstruct _jit_state noattr)))
            (Tstruct _jit_state noattr)) _jitted_list (tptr tushort))
        (Efield
          (Ederef (Etempvar _st (tptr (Tstruct _jit_state noattr)))
            (Tstruct _jit_state noattr)) _jitted_len tuint) (tptr tushort))
      tushort) (Etempvar _ins tuint))
  (Ssequence
    (Sassign
      (Efield
        (Ederef (Etempvar _st (tptr (Tstruct _jit_state noattr)))
          (Tstruct _jit_state noattr)) _jitted_len tuint)
      (Ebinop Oadd
        (Efield
          (Ederef (Etempvar _st (tptr (Tstruct _jit_state noattr)))
            (Tstruct _jit_state noattr)) _jitted_len tuint)
        (Econst_int (Int.repr 1) tuint) tuint))
    (Sreturn None)))
|}.

Definition f_magic_function := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: (_ofs, tuint) ::
                nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Ssequence
  (Scall None
    (Evar __magic_function (Tfunction
                             (Tcons tuint
                               (Tcons (tptr (Tstruct _jit_state noattr))
                                 Tnil)) tvoid cc_default))
    ((Etempvar _ofs tuint) ::
     (Etempvar _st (tptr (Tstruct _jit_state noattr))) :: nil))
  (Sreturn None))
|}.

Definition f_eval_use_IR11 := {|
  fn_return := tbool;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sreturn (Some (Efield
                 (Ederef (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                   (Tstruct _jit_state noattr)) _use_IR11 tbool)))
|}.

Definition f_eval_offset := {|
  fn_return := tuint;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sreturn (Some (Efield
                 (Ederef (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                   (Tstruct _jit_state noattr)) _offset tuint)))
|}.

Definition f_eval_thumb_len := {|
  fn_return := tuint;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sreturn (Some (Efield
                 (Ederef (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                   (Tstruct _jit_state noattr)) _thumb_len tuint)))
|}.

Definition f_eval_jitted_len := {|
  fn_return := tuint;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sreturn (Some (Efield
                 (Ederef (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                   (Tstruct _jit_state noattr)) _jitted_len tuint)))
|}.

Definition f_is_non_reg := {|
  fn_return := tbool;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: (_r, tuint) ::
                nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sreturn (Some (Ebinop Oeq
                 (Ederef
                   (Ebinop Oadd
                     (Efield
                       (Ederef
                         (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                         (Tstruct _jit_state noattr)) _load_store_regs
                       (tptr tuint)) (Etempvar _r tuint) (tptr tuint)) tuint)
                 (Econst_int (Int.repr 0) tuint) tint)))
|}.

Definition f_is_load_reg := {|
  fn_return := tbool;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: (_r, tuint) ::
                nil);
  fn_vars := nil;
  fn_temps := ((_t'1, tint) :: nil);
  fn_body :=
(Ssequence
  (Sifthenelse (Ebinop Oeq
                 (Ederef
                   (Ebinop Oadd
                     (Efield
                       (Ederef
                         (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                         (Tstruct _jit_state noattr)) _load_store_regs
                       (tptr tuint)) (Etempvar _r tuint) (tptr tuint)) tuint)
                 (Econst_int (Int.repr 1) tuint) tint)
    (Sset _t'1 (Econst_int (Int.repr 1) tint))
    (Sset _t'1
      (Ecast
        (Ebinop Oeq
          (Ederef
            (Ebinop Oadd
              (Efield
                (Ederef (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                  (Tstruct _jit_state noattr)) _load_store_regs (tptr tuint))
              (Etempvar _r tuint) (tptr tuint)) tuint)
          (Econst_int (Int.repr 3) tuint) tint) tbool)))
  (Sreturn (Some (Etempvar _t'1 tint))))
|}.

Definition f_is_store_reg := {|
  fn_return := tbool;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: (_r, tuint) ::
                nil);
  fn_vars := nil;
  fn_temps := ((_t'1, tint) :: nil);
  fn_body :=
(Ssequence
  (Sifthenelse (Ebinop Oeq
                 (Ederef
                   (Ebinop Oadd
                     (Efield
                       (Ederef
                         (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                         (Tstruct _jit_state noattr)) _load_store_regs
                       (tptr tuint)) (Etempvar _r tuint) (tptr tuint)) tuint)
                 (Econst_int (Int.repr 2) tuint) tint)
    (Sset _t'1 (Econst_int (Int.repr 1) tint))
    (Sset _t'1
      (Ecast
        (Ebinop Oeq
          (Ederef
            (Ebinop Oadd
              (Efield
                (Ederef (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                  (Tstruct _jit_state noattr)) _load_store_regs (tptr tuint))
              (Etempvar _r tuint) (tptr tuint)) tuint)
          (Econst_int (Int.repr 3) tuint) tint) tbool)))
  (Sreturn (Some (Etempvar _t'1 tint))))
|}.

Definition f_power2 := {|
  fn_return := tuint;
  fn_callconv := cc_default;
  fn_params := ((_width, tuint) :: nil);
  fn_vars := nil;
  fn_temps := ((_t'1, tuint) :: nil);
  fn_body :=
(Sifthenelse (Ebinop Oeq (Etempvar _width tuint)
               (Econst_int (Int.repr 0) tuint) tint)
  (Sreturn (Some (Econst_int (Int.repr 1) tuint)))
  (Ssequence
    (Scall (Some _t'1)
      (Evar _power2 (Tfunction (Tcons tuint Tnil) tuint cc_default))
      ((Ebinop Osub (Etempvar _width tuint) (Econst_int (Int.repr 1) tuint)
         tuint) :: nil))
    (Sreturn (Some (Ebinop Omul (Econst_int (Int.repr 2) tuint)
                     (Etempvar _t'1 tuint) tuint)))))
|}.

Definition f_decode_thumb := {|
  fn_return := tuint;
  fn_callconv := cc_default;
  fn_params := ((_ins, tuint) :: (_from, tuint) :: (_size, tuint) :: nil);
  fn_vars := nil;
  fn_temps := ((_t'1, tuint) :: nil);
  fn_body :=
(Ssequence
  (Scall (Some _t'1)
    (Evar _power2 (Tfunction (Tcons tuint Tnil) tuint cc_default))
    ((Etempvar _size tuint) :: nil))
  (Sreturn (Some (Ebinop Oand
                   (Ebinop Oshr (Etempvar _ins tuint) (Etempvar _from tuint)
                     tuint)
                   (Ebinop Osub (Etempvar _t'1 tuint)
                     (Econst_int (Int.repr 1) tuint) tuint) tuint))))
|}.

Definition f_encode_thumb := {|
  fn_return := tuint;
  fn_callconv := cc_default;
  fn_params := ((_v, tuint) :: (_ins, tuint) :: (_from, tuint) ::
                (_size, tuint) :: nil);
  fn_vars := nil;
  fn_temps := ((_mask, tuint) :: (_t'2, tuint) :: (_t'1, tuint) :: nil);
  fn_body :=
(Ssequence
  (Ssequence
    (Scall (Some _t'1)
      (Evar _power2 (Tfunction (Tcons tuint Tnil) tuint cc_default))
      ((Etempvar _size tuint) :: nil))
    (Sset _mask
      (Ebinop Oshl
        (Ebinop Osub (Etempvar _t'1 tuint) (Econst_int (Int.repr 1) tuint)
          tuint) (Etempvar _from tuint) tuint)))
  (Ssequence
    (Scall (Some _t'2)
      (Evar _power2 (Tfunction (Tcons tuint Tnil) tuint cc_default))
      ((Etempvar _size tuint) :: nil))
    (Sreturn (Some (Ebinop Oor
                     (Ebinop Oshl
                       (Ebinop Oand (Etempvar _v tuint)
                         (Ebinop Osub (Etempvar _t'2 tuint)
                           (Econst_int (Int.repr 1) tuint) tuint) tuint)
                       (Etempvar _from tuint) tuint)
                     (Ebinop Oand (Etempvar _ins tuint)
                       (Eunop Onotint (Etempvar _mask tuint) tuint) tuint)
                     tuint)))))
|}.

Definition f_reg_of_ireg := {|
  fn_return := tuint;
  fn_callconv := cc_default;
  fn_params := ((_ir, tuint) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sreturn (Some (Etempvar _ir tuint)))
|}.

Definition f_opcode_reg_of_imm := {|
  fn_return := tuchar;
  fn_callconv := cc_default;
  fn_params := ((_op, tuchar) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sswitch (Etempvar _op tuchar)
  (LScons (Some 4)
    (Sreturn (Some (Econst_int (Int.repr 12) tint)))
    (LScons (Some 20)
      (Sreturn (Some (Econst_int (Int.repr 28) tint)))
      (LScons (Some 36)
        (Sreturn (Some (Econst_int (Int.repr 44) tint)))
        (LScons (Some 68)
          (Sreturn (Some (Econst_int (Int.repr 76) tint)))
          (LScons (Some 84)
            (Sreturn (Some (Econst_int (Int.repr 92) tint)))
            (LScons (Some 164)
              (Sreturn (Some (Econst_int (Int.repr 172) tint)))
              (LScons (Some 180)
                (Sreturn (Some (Econst_int (Int.repr 188) tint)))
                (LScons None
                  (Sreturn (Some (Econst_int (Int.repr 0) tint)))
                  LSnil)))))))))
|}.

Definition f_eval_thumb_ins := {|
  fn_return := tuint;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: (_idx, tuint) ::
                nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sreturn (Some (Ederef
                 (Ebinop Oadd
                   (Efield
                     (Ederef
                       (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                       (Tstruct _jit_state noattr)) _thumb (tptr tushort))
                   (Etempvar _idx tuint) (tptr tushort)) tushort)))
|}.

Definition f_ins_is_bpf_alu32 := {|
  fn_return := tbool;
  fn_callconv := cc_default;
  fn_params := ((_ins, tulong) :: nil);
  fn_vars := nil;
  fn_temps := ((_op, tuchar) :: (_t'18, tint) :: (_t'17, tint) ::
               (_t'16, tint) :: (_t'15, tint) :: (_t'14, tint) ::
               (_t'13, tint) :: (_t'12, tint) :: (_t'11, tint) ::
               (_t'10, tint) :: (_t'9, tint) :: (_t'8, tint) ::
               (_t'7, tint) :: (_t'6, tint) :: (_t'5, tint) ::
               (_t'4, tint) :: (_t'3, tint) :: (_t'2, tint) ::
               (_t'1, tint) :: nil);
  fn_body :=
(Ssequence
  (Sset _op
    (Ecast
      (Ecast
        (Ebinop Oand (Etempvar _ins tulong)
          (Econst_long (Int64.repr 255) tulong) tulong) tuchar) tuchar))
  (Ssequence
    (Ssequence
      (Ssequence
        (Ssequence
          (Ssequence
            (Ssequence
              (Ssequence
                (Ssequence
                  (Ssequence
                    (Ssequence
                      (Ssequence
                        (Ssequence
                          (Ssequence
                            (Ssequence
                              (Ssequence
                                (Ssequence
                                  (Ssequence
                                    (Ssequence
                                      (Sifthenelse (Ebinop Oeq
                                                     (Etempvar _op tuchar)
                                                     (Econst_int (Int.repr 4) tint)
                                                     tint)
                                        (Sset _t'1
                                          (Econst_int (Int.repr 1) tint))
                                        (Sset _t'1
                                          (Ecast
                                            (Ebinop Oeq (Etempvar _op tuchar)
                                              (Econst_int (Int.repr 12) tint)
                                              tint) tbool)))
                                      (Sifthenelse (Etempvar _t'1 tint)
                                        (Sset _t'2
                                          (Econst_int (Int.repr 1) tint))
                                        (Sset _t'2
                                          (Ecast
                                            (Ebinop Oeq (Etempvar _op tuchar)
                                              (Econst_int (Int.repr 20) tint)
                                              tint) tbool))))
                                    (Sifthenelse (Etempvar _t'2 tint)
                                      (Sset _t'3
                                        (Econst_int (Int.repr 1) tint))
                                      (Sset _t'3
                                        (Ecast
                                          (Ebinop Oeq (Etempvar _op tuchar)
                                            (Econst_int (Int.repr 28) tint)
                                            tint) tbool))))
                                  (Sifthenelse (Etempvar _t'3 tint)
                                    (Sset _t'4
                                      (Econst_int (Int.repr 1) tint))
                                    (Sset _t'4
                                      (Ecast
                                        (Ebinop Oeq (Etempvar _op tuchar)
                                          (Econst_int (Int.repr 36) tint)
                                          tint) tbool))))
                                (Sifthenelse (Etempvar _t'4 tint)
                                  (Sset _t'5 (Econst_int (Int.repr 1) tint))
                                  (Sset _t'5
                                    (Ecast
                                      (Ebinop Oeq (Etempvar _op tuchar)
                                        (Econst_int (Int.repr 44) tint) tint)
                                      tbool))))
                              (Sifthenelse (Etempvar _t'5 tint)
                                (Sset _t'6 (Econst_int (Int.repr 1) tint))
                                (Sset _t'6
                                  (Ecast
                                    (Ebinop Oeq (Etempvar _op tuchar)
                                      (Econst_int (Int.repr 60) tint) tint)
                                    tbool))))
                            (Sifthenelse (Etempvar _t'6 tint)
                              (Sset _t'7 (Econst_int (Int.repr 1) tint))
                              (Sset _t'7
                                (Ecast
                                  (Ebinop Oeq (Etempvar _op tuchar)
                                    (Econst_int (Int.repr 68) tint) tint)
                                  tbool))))
                          (Sifthenelse (Etempvar _t'7 tint)
                            (Sset _t'8 (Econst_int (Int.repr 1) tint))
                            (Sset _t'8
                              (Ecast
                                (Ebinop Oeq (Etempvar _op tuchar)
                                  (Econst_int (Int.repr 76) tint) tint)
                                tbool))))
                        (Sifthenelse (Etempvar _t'8 tint)
                          (Sset _t'9 (Econst_int (Int.repr 1) tint))
                          (Sset _t'9
                            (Ecast
                              (Ebinop Oeq (Etempvar _op tuchar)
                                (Econst_int (Int.repr 84) tint) tint) tbool))))
                      (Sifthenelse (Etempvar _t'9 tint)
                        (Sset _t'10 (Econst_int (Int.repr 1) tint))
                        (Sset _t'10
                          (Ecast
                            (Ebinop Oeq (Etempvar _op tuchar)
                              (Econst_int (Int.repr 92) tint) tint) tbool))))
                    (Sifthenelse (Etempvar _t'10 tint)
                      (Sset _t'11 (Econst_int (Int.repr 1) tint))
                      (Sset _t'11
                        (Ecast
                          (Ebinop Oeq (Etempvar _op tuchar)
                            (Econst_int (Int.repr 108) tint) tint) tbool))))
                  (Sifthenelse (Etempvar _t'11 tint)
                    (Sset _t'12 (Econst_int (Int.repr 1) tint))
                    (Sset _t'12
                      (Ecast
                        (Ebinop Oeq (Etempvar _op tuchar)
                          (Econst_int (Int.repr 124) tint) tint) tbool))))
                (Sifthenelse (Etempvar _t'12 tint)
                  (Sset _t'13 (Econst_int (Int.repr 1) tint))
                  (Sset _t'13
                    (Ecast
                      (Ebinop Oeq (Etempvar _op tuchar)
                        (Econst_int (Int.repr 132) tint) tint) tbool))))
              (Sifthenelse (Etempvar _t'13 tint)
                (Sset _t'14 (Econst_int (Int.repr 1) tint))
                (Sset _t'14
                  (Ecast
                    (Ebinop Oeq (Etempvar _op tuchar)
                      (Econst_int (Int.repr 164) tint) tint) tbool))))
            (Sifthenelse (Etempvar _t'14 tint)
              (Sset _t'15 (Econst_int (Int.repr 1) tint))
              (Sset _t'15
                (Ecast
                  (Ebinop Oeq (Etempvar _op tuchar)
                    (Econst_int (Int.repr 172) tint) tint) tbool))))
          (Sifthenelse (Etempvar _t'15 tint)
            (Sset _t'16 (Econst_int (Int.repr 1) tint))
            (Sset _t'16
              (Ecast
                (Ebinop Oeq (Etempvar _op tuchar)
                  (Econst_int (Int.repr 180) tint) tint) tbool))))
        (Sifthenelse (Etempvar _t'16 tint)
          (Sset _t'17 (Econst_int (Int.repr 1) tint))
          (Sset _t'17
            (Ecast
              (Ebinop Oeq (Etempvar _op tuchar)
                (Econst_int (Int.repr 188) tint) tint) tbool))))
      (Sifthenelse (Etempvar _t'17 tint)
        (Sset _t'18 (Econst_int (Int.repr 1) tint))
        (Sset _t'18
          (Ecast
            (Ebinop Oeq (Etempvar _op tuchar)
              (Econst_int (Int.repr 204) tint) tint) tbool))))
    (Sreturn (Some (Etempvar _t'18 tint)))))
|}.

Definition f_ins_is_bpf_jump := {|
  fn_return := tbool;
  fn_callconv := cc_default;
  fn_params := ((_ins, tulong) :: nil);
  fn_vars := nil;
  fn_temps := ((_op, tuchar) :: (_t'22, tint) :: (_t'21, tint) ::
               (_t'20, tint) :: (_t'19, tint) :: (_t'18, tint) ::
               (_t'17, tint) :: (_t'16, tint) :: (_t'15, tint) ::
               (_t'14, tint) :: (_t'13, tint) :: (_t'12, tint) ::
               (_t'11, tint) :: (_t'10, tint) :: (_t'9, tint) ::
               (_t'8, tint) :: (_t'7, tint) :: (_t'6, tint) ::
               (_t'5, tint) :: (_t'4, tint) :: (_t'3, tint) ::
               (_t'2, tint) :: (_t'1, tint) :: nil);
  fn_body :=
(Ssequence
  (Sset _op
    (Ecast
      (Ecast
        (Ebinop Oand (Etempvar _ins tulong)
          (Econst_long (Int64.repr 255) tulong) tulong) tuchar) tuchar))
  (Ssequence
    (Ssequence
      (Ssequence
        (Ssequence
          (Ssequence
            (Ssequence
              (Ssequence
                (Ssequence
                  (Ssequence
                    (Ssequence
                      (Ssequence
                        (Ssequence
                          (Ssequence
                            (Ssequence
                              (Ssequence
                                (Ssequence
                                  (Ssequence
                                    (Ssequence
                                      (Ssequence
                                        (Ssequence
                                          (Ssequence
                                            (Ssequence
                                              (Sifthenelse (Ebinop Oeq
                                                             (Etempvar _op tuchar)
                                                             (Econst_int (Int.repr 5) tint)
                                                             tint)
                                                (Sset _t'1
                                                  (Econst_int (Int.repr 1) tint))
                                                (Sset _t'1
                                                  (Ecast
                                                    (Ebinop Oeq
                                                      (Etempvar _op tuchar)
                                                      (Econst_int (Int.repr 21) tint)
                                                      tint) tbool)))
                                              (Sifthenelse (Etempvar _t'1 tint)
                                                (Sset _t'2
                                                  (Econst_int (Int.repr 1) tint))
                                                (Sset _t'2
                                                  (Ecast
                                                    (Ebinop Oeq
                                                      (Etempvar _op tuchar)
                                                      (Econst_int (Int.repr 29) tint)
                                                      tint) tbool))))
                                            (Sifthenelse (Etempvar _t'2 tint)
                                              (Sset _t'3
                                                (Econst_int (Int.repr 1) tint))
                                              (Sset _t'3
                                                (Ecast
                                                  (Ebinop Oeq
                                                    (Etempvar _op tuchar)
                                                    (Econst_int (Int.repr 37) tint)
                                                    tint) tbool))))
                                          (Sifthenelse (Etempvar _t'3 tint)
                                            (Sset _t'4
                                              (Econst_int (Int.repr 1) tint))
                                            (Sset _t'4
                                              (Ecast
                                                (Ebinop Oeq
                                                  (Etempvar _op tuchar)
                                                  (Econst_int (Int.repr 45) tint)
                                                  tint) tbool))))
                                        (Sifthenelse (Etempvar _t'4 tint)
                                          (Sset _t'5
                                            (Econst_int (Int.repr 1) tint))
                                          (Sset _t'5
                                            (Ecast
                                              (Ebinop Oeq
                                                (Etempvar _op tuchar)
                                                (Econst_int (Int.repr 53) tint)
                                                tint) tbool))))
                                      (Sifthenelse (Etempvar _t'5 tint)
                                        (Sset _t'6
                                          (Econst_int (Int.repr 1) tint))
                                        (Sset _t'6
                                          (Ecast
                                            (Ebinop Oeq (Etempvar _op tuchar)
                                              (Econst_int (Int.repr 61) tint)
                                              tint) tbool))))
                                    (Sifthenelse (Etempvar _t'6 tint)
                                      (Sset _t'7
                                        (Econst_int (Int.repr 1) tint))
                                      (Sset _t'7
                                        (Ecast
                                          (Ebinop Oeq (Etempvar _op tuchar)
                                            (Econst_int (Int.repr 69) tint)
                                            tint) tbool))))
                                  (Sifthenelse (Etempvar _t'7 tint)
                                    (Sset _t'8
                                      (Econst_int (Int.repr 1) tint))
                                    (Sset _t'8
                                      (Ecast
                                        (Ebinop Oeq (Etempvar _op tuchar)
                                          (Econst_int (Int.repr 77) tint)
                                          tint) tbool))))
                                (Sifthenelse (Etempvar _t'8 tint)
                                  (Sset _t'9 (Econst_int (Int.repr 1) tint))
                                  (Sset _t'9
                                    (Ecast
                                      (Ebinop Oeq (Etempvar _op tuchar)
                                        (Econst_int (Int.repr 85) tint) tint)
                                      tbool))))
                              (Sifthenelse (Etempvar _t'9 tint)
                                (Sset _t'10 (Econst_int (Int.repr 1) tint))
                                (Sset _t'10
                                  (Ecast
                                    (Ebinop Oeq (Etempvar _op tuchar)
                                      (Econst_int (Int.repr 93) tint) tint)
                                    tbool))))
                            (Sifthenelse (Etempvar _t'10 tint)
                              (Sset _t'11 (Econst_int (Int.repr 1) tint))
                              (Sset _t'11
                                (Ecast
                                  (Ebinop Oeq (Etempvar _op tuchar)
                                    (Econst_int (Int.repr 101) tint) tint)
                                  tbool))))
                          (Sifthenelse (Etempvar _t'11 tint)
                            (Sset _t'12 (Econst_int (Int.repr 1) tint))
                            (Sset _t'12
                              (Ecast
                                (Ebinop Oeq (Etempvar _op tuchar)
                                  (Econst_int (Int.repr 109) tint) tint)
                                tbool))))
                        (Sifthenelse (Etempvar _t'12 tint)
                          (Sset _t'13 (Econst_int (Int.repr 1) tint))
                          (Sset _t'13
                            (Ecast
                              (Ebinop Oeq (Etempvar _op tuchar)
                                (Econst_int (Int.repr 117) tint) tint) tbool))))
                      (Sifthenelse (Etempvar _t'13 tint)
                        (Sset _t'14 (Econst_int (Int.repr 1) tint))
                        (Sset _t'14
                          (Ecast
                            (Ebinop Oeq (Etempvar _op tuchar)
                              (Econst_int (Int.repr 125) tint) tint) tbool))))
                    (Sifthenelse (Etempvar _t'14 tint)
                      (Sset _t'15 (Econst_int (Int.repr 1) tint))
                      (Sset _t'15
                        (Ecast
                          (Ebinop Oeq (Etempvar _op tuchar)
                            (Econst_int (Int.repr 165) tint) tint) tbool))))
                  (Sifthenelse (Etempvar _t'15 tint)
                    (Sset _t'16 (Econst_int (Int.repr 1) tint))
                    (Sset _t'16
                      (Ecast
                        (Ebinop Oeq (Etempvar _op tuchar)
                          (Econst_int (Int.repr 173) tint) tint) tbool))))
                (Sifthenelse (Etempvar _t'16 tint)
                  (Sset _t'17 (Econst_int (Int.repr 1) tint))
                  (Sset _t'17
                    (Ecast
                      (Ebinop Oeq (Etempvar _op tuchar)
                        (Econst_int (Int.repr 181) tint) tint) tbool))))
              (Sifthenelse (Etempvar _t'17 tint)
                (Sset _t'18 (Econst_int (Int.repr 1) tint))
                (Sset _t'18
                  (Ecast
                    (Ebinop Oeq (Etempvar _op tuchar)
                      (Econst_int (Int.repr 189) tint) tint) tbool))))
            (Sifthenelse (Etempvar _t'18 tint)
              (Sset _t'19 (Econst_int (Int.repr 1) tint))
              (Sset _t'19
                (Ecast
                  (Ebinop Oeq (Etempvar _op tuchar)
                    (Econst_int (Int.repr 197) tint) tint) tbool))))
          (Sifthenelse (Etempvar _t'19 tint)
            (Sset _t'20 (Econst_int (Int.repr 1) tint))
            (Sset _t'20
              (Ecast
                (Ebinop Oeq (Etempvar _op tuchar)
                  (Econst_int (Int.repr 205) tint) tint) tbool))))
        (Sifthenelse (Etempvar _t'20 tint)
          (Sset _t'21 (Econst_int (Int.repr 1) tint))
          (Sset _t'21
            (Ecast
              (Ebinop Oeq (Etempvar _op tuchar)
                (Econst_int (Int.repr 213) tint) tint) tbool))))
      (Sifthenelse (Etempvar _t'21 tint)
        (Sset _t'22 (Econst_int (Int.repr 1) tint))
        (Sset _t'22
          (Ecast
            (Ebinop Oeq (Etempvar _op tuchar)
              (Econst_int (Int.repr 221) tint) tint) tbool))))
    (Sreturn (Some (Etempvar _t'22 tint)))))
|}.

Definition f_reset_init_jittedthumb := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: nil);
  fn_vars := nil;
  fn_temps := ((_i, tint) :: nil);
  fn_body :=
(Ssequence
  (Sassign
    (Efield
      (Ederef (Etempvar _st (tptr (Tstruct _jit_state noattr)))
        (Tstruct _jit_state noattr)) _use_IR11 tbool)
    (Econst_int (Int.repr 0) tint))
  (Ssequence
    (Ssequence
      (Sset _i (Econst_int (Int.repr 0) tint))
      (Sloop
        (Ssequence
          (Sifthenelse (Ebinop Olt (Etempvar _i tint)
                         (Econst_int (Int.repr 11) tint) tint)
            Sskip
            Sbreak)
          (Sassign
            (Ederef
              (Ebinop Oadd
                (Efield
                  (Ederef (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                    (Tstruct _jit_state noattr)) _load_store_regs
                  (tptr tuint)) (Etempvar _i tint) (tptr tuint)) tuint)
            (Econst_int (Int.repr 0) tint)))
        (Sset _i
          (Ebinop Oadd (Etempvar _i tint) (Econst_int (Int.repr 1) tint)
            tint))))
    (Ssequence
      (Sassign
        (Efield
          (Ederef (Etempvar _st (tptr (Tstruct _jit_state noattr)))
            (Tstruct _jit_state noattr)) _offset tuint)
        (Econst_int (Int.repr 0) tuint))
      (Ssequence
        (Sassign
          (Efield
            (Ederef (Etempvar _st (tptr (Tstruct _jit_state noattr)))
              (Tstruct _jit_state noattr)) _thumb_len tuint)
          (Econst_int (Int.repr 0) tuint))
        (Sreturn None)))))
|}.

Definition f_eval_key_value2_arm_ofs := {|
  fn_return := tuint;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: (_key, tuint) ::
                nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sreturn (Some (Efield
                 (Ederef
                   (Ebinop Oadd
                     (Efield
                       (Ederef
                         (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                         (Tstruct _jit_state noattr)) _kv2
                       (tptr (Tstruct _key_value2 noattr)))
                     (Etempvar _key tuint)
                     (tptr (Tstruct _key_value2 noattr)))
                   (Tstruct _key_value2 noattr)) _arm_ofs tuint)))
|}.

Definition f_eval_key_value2_alu32_ofs := {|
  fn_return := tuint;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: (_key, tuint) ::
                nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sreturn (Some (Efield
                 (Ederef
                   (Ebinop Oadd
                     (Efield
                       (Ederef
                         (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                         (Tstruct _jit_state noattr)) _kv2
                       (tptr (Tstruct _key_value2 noattr)))
                     (Etempvar _key tuint)
                     (tptr (Tstruct _key_value2 noattr)))
                   (Tstruct _key_value2 noattr)) _alu32_ofs tuint)))
|}.

Definition f_add_key_value2 := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: (_pc, tuint) ::
                (_ofs0, tuint) :: (_ofs1, tuint) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Ssequence
  (Sassign
    (Efield
      (Ederef
        (Ebinop Oadd
          (Efield
            (Ederef (Etempvar _st (tptr (Tstruct _jit_state noattr)))
              (Tstruct _jit_state noattr)) _kv2
            (tptr (Tstruct _key_value2 noattr))) (Etempvar _pc tuint)
          (tptr (Tstruct _key_value2 noattr))) (Tstruct _key_value2 noattr))
      _arm_ofs tuint) (Etempvar _ofs0 tuint))
  (Ssequence
    (Sassign
      (Efield
        (Ederef
          (Ebinop Oadd
            (Efield
              (Ederef (Etempvar _st (tptr (Tstruct _jit_state noattr)))
                (Tstruct _jit_state noattr)) _kv2
              (tptr (Tstruct _key_value2 noattr))) (Etempvar _pc tuint)
            (tptr (Tstruct _key_value2 noattr)))
          (Tstruct _key_value2 noattr)) _alu32_ofs tuint)
      (Etempvar _ofs1 tuint))
    (Sreturn None)))
|}.

Definition f_construct_thumb_b := {|
  fn_return := tushort;
  fn_callconv := cc_default;
  fn_params := ((_cd, tushort) :: (_imm8, tushort) :: nil);
  fn_vars := nil;
  fn_temps := ((_ins_imm8, tuint) :: (_t'2, tuint) :: (_t'1, tuint) :: nil);
  fn_body :=
(Ssequence
  (Ssequence
    (Scall (Some _t'1)
      (Evar _encode_thumb (Tfunction
                            (Tcons tuint
                              (Tcons tuint (Tcons tuint (Tcons tuint Tnil))))
                            tuint cc_default))
      ((Etempvar _imm8 tushort) :: (Econst_int (Int.repr 53248) tint) ::
       (Econst_int (Int.repr 0) tuint) :: (Econst_int (Int.repr 8) tuint) ::
       nil))
    (Sset _ins_imm8 (Etempvar _t'1 tuint)))
  (Ssequence
    (Scall (Some _t'2)
      (Evar _encode_thumb (Tfunction
                            (Tcons tuint
                              (Tcons tuint (Tcons tuint (Tcons tuint Tnil))))
                            tuint cc_default))
      ((Etempvar _cd tushort) :: (Etempvar _ins_imm8 tuint) ::
       (Econst_int (Int.repr 8) tuint) :: (Econst_int (Int.repr 4) tuint) ::
       nil))
    (Sreturn (Some (Etempvar _t'2 tuint)))))
|}.

Definition f_construct_thumb2_shift_rd_rm := {|
  fn_return := tushort;
  fn_callconv := cc_default;
  fn_params := ((_rd, tushort) :: (_rm, tushort) :: nil);
  fn_vars := nil;
  fn_temps := ((_ins_rd, tuint) :: (_t'2, tuint) :: (_t'1, tuint) :: nil);
  fn_body :=
(Ssequence
  (Ssequence
    (Scall (Some _t'1)
      (Evar _encode_thumb (Tfunction
                            (Tcons tuint
                              (Tcons tuint (Tcons tuint (Tcons tuint Tnil))))
                            tuint cc_default))
      ((Etempvar _rd tushort) :: (Etempvar _rm tushort) ::
       (Econst_int (Int.repr 8) tuint) :: (Econst_int (Int.repr 4) tuint) ::
       nil))
    (Sset _ins_rd (Etempvar _t'1 tuint)))
  (Ssequence
    (Scall (Some _t'2)
      (Evar _encode_thumb (Tfunction
                            (Tcons tuint
                              (Tcons tuint (Tcons tuint (Tcons tuint Tnil))))
                            tuint cc_default))
      ((Econst_int (Int.repr 15) tint) :: (Etempvar _ins_rd tuint) ::
       (Econst_int (Int.repr 12) tuint) :: (Econst_int (Int.repr 4) tuint) ::
       nil))
    (Sreturn (Some (Etempvar _t'2 tuint)))))
|}.

Definition f_jit_alu32_thumb_store_template_ins := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) ::
                (_rt, tushort) :: (_rn, tushort) :: (_imm12, tushort) :: nil);
  fn_vars := nil;
  fn_temps := ((_str_low, tuint) :: (_str_high, tuint) :: (_t'2, tuint) ::
               (_t'1, tuint) :: nil);
  fn_body :=
(Ssequence
  (Ssequence
    (Scall (Some _t'1)
      (Evar _encode_thumb (Tfunction
                            (Tcons tuint
                              (Tcons tuint (Tcons tuint (Tcons tuint Tnil))))
                            tuint cc_default))
      ((Etempvar _rn tushort) :: (Econst_int (Int.repr 63680) tint) ::
       (Econst_int (Int.repr 0) tuint) :: (Econst_int (Int.repr 4) tuint) ::
       nil))
    (Sset _str_low (Etempvar _t'1 tuint)))
  (Ssequence
    (Ssequence
      (Scall (Some _t'2)
        (Evar _encode_thumb (Tfunction
                              (Tcons tuint
                                (Tcons tuint
                                  (Tcons tuint (Tcons tuint Tnil)))) tuint
                              cc_default))
        ((Etempvar _rt tushort) :: (Etempvar _imm12 tushort) ::
         (Econst_int (Int.repr 12) tuint) ::
         (Econst_int (Int.repr 4) tuint) :: nil))
      (Sset _str_high (Etempvar _t'2 tuint)))
    (Ssequence
      (Scall None
        (Evar _add_ins_jittedthumb (Tfunction
                                     (Tcons
                                       (tptr (Tstruct _jit_state noattr))
                                       (Tcons tuint Tnil)) tvoid cc_default))
        ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
         (Etempvar _str_low tuint) :: nil))
      (Ssequence
        (Scall None
          (Evar _add_ins_jittedthumb (Tfunction
                                       (Tcons
                                         (tptr (Tstruct _jit_state noattr))
                                         (Tcons tuint Tnil)) tvoid
                                       cc_default))
          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
           (Etempvar _str_high tuint) :: nil))
        (Sreturn None)))))
|}.

Definition f_jit_alu32_thumb_load_template_ins := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) ::
                (_rt, tushort) :: (_rn, tushort) :: (_imm12, tushort) :: nil);
  fn_vars := nil;
  fn_temps := ((_str_low, tuint) :: (_str_high, tuint) :: (_t'2, tuint) ::
               (_t'1, tuint) :: nil);
  fn_body :=
(Ssequence
  (Ssequence
    (Scall (Some _t'1)
      (Evar _encode_thumb (Tfunction
                            (Tcons tuint
                              (Tcons tuint (Tcons tuint (Tcons tuint Tnil))))
                            tuint cc_default))
      ((Etempvar _rn tushort) :: (Econst_int (Int.repr 63696) tint) ::
       (Econst_int (Int.repr 0) tuint) :: (Econst_int (Int.repr 4) tuint) ::
       nil))
    (Sset _str_low (Etempvar _t'1 tuint)))
  (Ssequence
    (Ssequence
      (Scall (Some _t'2)
        (Evar _encode_thumb (Tfunction
                              (Tcons tuint
                                (Tcons tuint
                                  (Tcons tuint (Tcons tuint Tnil)))) tuint
                              cc_default))
        ((Etempvar _rt tushort) :: (Etempvar _imm12 tushort) ::
         (Econst_int (Int.repr 12) tuint) ::
         (Econst_int (Int.repr 4) tuint) :: nil))
      (Sset _str_high (Etempvar _t'2 tuint)))
    (Ssequence
      (Scall None
        (Evar _add_ins_jittedthumb (Tfunction
                                     (Tcons
                                       (tptr (Tstruct _jit_state noattr))
                                       (Tcons tuint Tnil)) tvoid cc_default))
        ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
         (Etempvar _str_low tuint) :: nil))
      (Ssequence
        (Scall None
          (Evar _add_ins_jittedthumb (Tfunction
                                       (Tcons
                                         (tptr (Tstruct _jit_state noattr))
                                         (Tcons tuint Tnil)) tvoid
                                       cc_default))
          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
           (Etempvar _str_high tuint) :: nil))
        (Sreturn None)))))
|}.

Definition f_jit_alu32_thumb_store_template_jit := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) ::
                (_rt, tushort) :: (_rn, tushort) :: (_imm12, tushort) :: nil);
  fn_vars := nil;
  fn_temps := ((_str_low, tuint) :: (_str_high, tuint) :: (_t'2, tuint) ::
               (_t'1, tuint) :: nil);
  fn_body :=
(Ssequence
  (Ssequence
    (Scall (Some _t'1)
      (Evar _encode_thumb (Tfunction
                            (Tcons tuint
                              (Tcons tuint (Tcons tuint (Tcons tuint Tnil))))
                            tuint cc_default))
      ((Etempvar _rn tushort) :: (Econst_int (Int.repr 63680) tint) ::
       (Econst_int (Int.repr 0) tuint) :: (Econst_int (Int.repr 4) tuint) ::
       nil))
    (Sset _str_low (Etempvar _t'1 tuint)))
  (Ssequence
    (Ssequence
      (Scall (Some _t'2)
        (Evar _encode_thumb (Tfunction
                              (Tcons tuint
                                (Tcons tuint
                                  (Tcons tuint (Tcons tuint Tnil)))) tuint
                              cc_default))
        ((Etempvar _rt tushort) :: (Etempvar _imm12 tushort) ::
         (Econst_int (Int.repr 12) tuint) ::
         (Econst_int (Int.repr 4) tuint) :: nil))
      (Sset _str_high (Etempvar _t'2 tuint)))
    (Ssequence
      (Scall None
        (Evar _upd_jitted_list (Tfunction
                                 (Tcons (tptr (Tstruct _jit_state noattr))
                                   (Tcons tuint Tnil)) tvoid cc_default))
        ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
         (Etempvar _str_low tuint) :: nil))
      (Ssequence
        (Scall None
          (Evar _upd_jitted_list (Tfunction
                                   (Tcons (tptr (Tstruct _jit_state noattr))
                                     (Tcons tuint Tnil)) tvoid cc_default))
          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
           (Etempvar _str_high tuint) :: nil))
        (Sreturn None)))))
|}.

Definition f_jit_alu32_thumb_load_template_jit := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) ::
                (_rt, tushort) :: (_rn, tushort) :: (_imm12, tushort) :: nil);
  fn_vars := nil;
  fn_temps := ((_str_low, tuint) :: (_str_high, tuint) :: (_t'2, tuint) ::
               (_t'1, tuint) :: nil);
  fn_body :=
(Ssequence
  (Ssequence
    (Scall (Some _t'1)
      (Evar _encode_thumb (Tfunction
                            (Tcons tuint
                              (Tcons tuint (Tcons tuint (Tcons tuint Tnil))))
                            tuint cc_default))
      ((Etempvar _rn tushort) :: (Econst_int (Int.repr 63696) tint) ::
       (Econst_int (Int.repr 0) tuint) :: (Econst_int (Int.repr 4) tuint) ::
       nil))
    (Sset _str_low (Etempvar _t'1 tuint)))
  (Ssequence
    (Ssequence
      (Scall (Some _t'2)
        (Evar _encode_thumb (Tfunction
                              (Tcons tuint
                                (Tcons tuint
                                  (Tcons tuint (Tcons tuint Tnil)))) tuint
                              cc_default))
        ((Etempvar _rt tushort) :: (Etempvar _imm12 tushort) ::
         (Econst_int (Int.repr 12) tuint) ::
         (Econst_int (Int.repr 4) tuint) :: nil))
      (Sset _str_high (Etempvar _t'2 tuint)))
    (Ssequence
      (Scall None
        (Evar _upd_jitted_list (Tfunction
                                 (Tcons (tptr (Tstruct _jit_state noattr))
                                   (Tcons tuint Tnil)) tvoid cc_default))
        ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
         (Etempvar _str_low tuint) :: nil))
      (Ssequence
        (Scall None
          (Evar _upd_jitted_list (Tfunction
                                   (Tcons (tptr (Tstruct _jit_state noattr))
                                     (Tcons tuint Tnil)) tvoid cc_default))
          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
           (Etempvar _str_high tuint) :: nil))
        (Sreturn None)))))
|}.

Definition f_jit_alu32_store_flag := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: (_f, tuint) ::
                nil);
  fn_vars := nil;
  fn_temps := ((_movw_hi, tuint) :: (_b, tbool) :: (_t'2, tbool) ::
               (_t'1, tuint) :: nil);
  fn_body :=
(Ssequence
  (Ssequence
    (Scall (Some _t'1)
      (Evar _encode_thumb (Tfunction
                            (Tcons tuint
                              (Tcons tuint (Tcons tuint (Tcons tuint Tnil))))
                            tuint cc_default))
      ((Econst_int (Int.repr 11) tint) :: (Etempvar _f tuint) ::
       (Econst_int (Int.repr 8) tuint) :: (Econst_int (Int.repr 4) tuint) ::
       nil))
    (Sset _movw_hi (Etempvar _t'1 tuint)))
  (Ssequence
    (Scall None
      (Evar _add_ins_jittedthumb (Tfunction
                                   (Tcons (tptr (Tstruct _jit_state noattr))
                                     (Tcons tuint Tnil)) tvoid cc_default))
      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
       (Econst_int (Int.repr 62016) tint) :: nil))
    (Ssequence
      (Scall None
        (Evar _add_ins_jittedthumb (Tfunction
                                     (Tcons
                                       (tptr (Tstruct _jit_state noattr))
                                       (Tcons tuint Tnil)) tvoid cc_default))
        ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
         (Etempvar _movw_hi tuint) :: nil))
      (Ssequence
        (Ssequence
          (Scall (Some _t'2)
            (Evar _is_non_reg (Tfunction
                                (Tcons (tptr (Tstruct _jit_state noattr))
                                  (Tcons tuint Tnil)) tbool cc_default))
            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
             (Econst_int (Int.repr 1) tuint) :: nil))
          (Sset _b (Ecast (Etempvar _t'2 tbool) tbool)))
        (Ssequence
          (Sifthenelse (Etempvar _b tbool)
            Sskip
            (Scall None
              (Evar _jit_alu32_thumb_store_template_ins (Tfunction
                                                          (Tcons
                                                            (tptr (Tstruct _jit_state noattr))
                                                            (Tcons tushort
                                                              (Tcons tushort
                                                                (Tcons
                                                                  tushort
                                                                  Tnil))))
                                                          tvoid cc_default))
              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
               (Econst_int (Int.repr 1) tint) ::
               (Econst_int (Int.repr 13) tint) ::
               (Econst_int (Int.repr 4) tint) :: nil)))
          (Ssequence
            (Scall None
              (Evar _jit_alu32_thumb_load_template_ins (Tfunction
                                                         (Tcons
                                                           (tptr (Tstruct _jit_state noattr))
                                                           (Tcons tushort
                                                             (Tcons tushort
                                                               (Tcons tushort
                                                                 Tnil))))
                                                         tvoid cc_default))
              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
               (Econst_int (Int.repr 1) tint) ::
               (Econst_int (Int.repr 12) tint) ::
               (Econst_int (Int.repr 4) tint) :: nil))
            (Ssequence
              (Scall None
                (Evar _jit_alu32_thumb_store_template_ins (Tfunction
                                                            (Tcons
                                                              (tptr (Tstruct _jit_state noattr))
                                                              (Tcons tushort
                                                                (Tcons
                                                                  tushort
                                                                  (Tcons
                                                                    tushort
                                                                    Tnil))))
                                                            tvoid cc_default))
                ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                 (Econst_int (Int.repr 11) tint) ::
                 (Econst_int (Int.repr 1) tint) ::
                 (Econst_int (Int.repr 0) tint) :: nil))
              (Sifthenelse (Etempvar _b tbool)
                (Sreturn None)
                (Ssequence
                  (Scall None
                    (Evar _jit_alu32_thumb_load_template_ins (Tfunction
                                                               (Tcons
                                                                 (tptr (Tstruct _jit_state noattr))
                                                                 (Tcons
                                                                   tushort
                                                                   (Tcons
                                                                    tushort
                                                                    (Tcons
                                                                    tushort
                                                                    Tnil))))
                                                               tvoid
                                                               cc_default))
                    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                     (Econst_int (Int.repr 1) tint) ::
                     (Econst_int (Int.repr 13) tint) ::
                     (Econst_int (Int.repr 4) tint) :: nil))
                  (Sreturn None))))))))))
|}.

Definition f_get_offset := {|
  fn_return := tint;
  fn_callconv := cc_default;
  fn_params := ((_ins, tulong) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sreturn (Some (Ecast
                 (Ecast
                   (Ebinop Oshr
                     (Ebinop Oshl (Etempvar _ins tulong)
                       (Econst_long (Int64.repr 32) tulong) tulong)
                     (Econst_long (Int64.repr 48) tulong) tulong) tshort)
                 tint)))
|}.

Definition f_jit_alu32_pre := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: nil);
  fn_vars := nil;
  fn_temps := ((_ins_rdn, tuint) :: (_ins_rm, tuint) :: (_ins_mov, tuint) ::
               (_t'3, tuint) :: (_t'2, tuint) :: (_t'1, tuint) :: nil);
  fn_body :=
(Ssequence
  (Ssequence
    (Scall (Some _t'1)
      (Evar _encode_thumb (Tfunction
                            (Tcons tuint
                              (Tcons tuint (Tcons tuint (Tcons tuint Tnil))))
                            tuint cc_default))
      ((Econst_int (Int.repr 4) tint) ::
       (Econst_int (Int.repr 17920) tint) ::
       (Econst_int (Int.repr 0) tuint) :: (Econst_int (Int.repr 3) tuint) ::
       nil))
    (Sset _ins_rdn (Etempvar _t'1 tuint)))
  (Ssequence
    (Ssequence
      (Scall (Some _t'2)
        (Evar _encode_thumb (Tfunction
                              (Tcons tuint
                                (Tcons tuint
                                  (Tcons tuint (Tcons tuint Tnil)))) tuint
                              cc_default))
        ((Econst_int (Int.repr 1) tint) :: (Etempvar _ins_rdn tuint) ::
         (Econst_int (Int.repr 3) tuint) ::
         (Econst_int (Int.repr 4) tuint) :: nil))
      (Sset _ins_rm (Etempvar _t'2 tuint)))
    (Ssequence
      (Ssequence
        (Scall (Some _t'3)
          (Evar _encode_thumb (Tfunction
                                (Tcons tuint
                                  (Tcons tuint
                                    (Tcons tuint (Tcons tuint Tnil)))) tuint
                                cc_default))
          ((Econst_int (Int.repr 1) tint) :: (Etempvar _ins_rm tuint) ::
           (Econst_int (Int.repr 7) tuint) ::
           (Econst_int (Int.repr 1) tuint) :: nil))
        (Sset _ins_mov (Etempvar _t'3 tuint)))
      (Ssequence
        (Scall None
          (Evar _upd_jitted_list (Tfunction
                                   (Tcons (tptr (Tstruct _jit_state noattr))
                                     (Tcons tuint Tnil)) tvoid cc_default))
          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
           (Etempvar _ins_mov tuint) :: nil))
        (Sreturn None)))))
|}.

Definition f_jit_alu32_thumb_upd_save := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: (_r, tuint) ::
                nil);
  fn_vars := nil;
  fn_temps := ((_b, tbool) :: (_ir, tuint) :: (_t'1, tbool) :: nil);
  fn_body :=
(Ssequence
  (Ssequence
    (Scall (Some _t'1)
      (Evar _is_non_reg (Tfunction
                          (Tcons (tptr (Tstruct _jit_state noattr))
                            (Tcons tuint Tnil)) tbool cc_default))
      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
       (Etempvar _r tuint) :: nil))
    (Sset _b (Ecast (Etempvar _t'1 tbool) tbool)))
  (Sifthenelse (Etempvar _b tbool)
    (Sreturn None)
    (Ssequence
      (Sset _ir (Etempvar _r tuint))
      (Ssequence
        (Scall None
          (Evar _jit_alu32_thumb_store_template_jit (Tfunction
                                                      (Tcons
                                                        (tptr (Tstruct _jit_state noattr))
                                                        (Tcons tushort
                                                          (Tcons tushort
                                                            (Tcons tushort
                                                              Tnil)))) tvoid
                                                      cc_default))
          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
           (Etempvar _ir tuint) :: (Econst_int (Int.repr 13) tuint) ::
           (Ebinop Omul (Etempvar _ir tuint) (Econst_int (Int.repr 4) tint)
             tuint) :: nil))
        (Sreturn None)))))
|}.

Definition f_jit_alu32_thumb_save := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: nil);
  fn_vars := nil;
  fn_temps := ((_b, tbool) :: (_t'1, tbool) :: nil);
  fn_body :=
(Ssequence
  (Scall None
    (Evar _jit_alu32_thumb_upd_save (Tfunction
                                      (Tcons
                                        (tptr (Tstruct _jit_state noattr))
                                        (Tcons tuint Tnil)) tvoid cc_default))
    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
     (Econst_int (Int.repr 4) tuint) :: nil))
  (Ssequence
    (Scall None
      (Evar _jit_alu32_thumb_upd_save (Tfunction
                                        (Tcons
                                          (tptr (Tstruct _jit_state noattr))
                                          (Tcons tuint Tnil)) tvoid
                                        cc_default))
      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
       (Econst_int (Int.repr 5) tuint) :: nil))
    (Ssequence
      (Scall None
        (Evar _jit_alu32_thumb_upd_save (Tfunction
                                          (Tcons
                                            (tptr (Tstruct _jit_state noattr))
                                            (Tcons tuint Tnil)) tvoid
                                          cc_default))
        ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
         (Econst_int (Int.repr 6) tuint) :: nil))
      (Ssequence
        (Scall None
          (Evar _jit_alu32_thumb_upd_save (Tfunction
                                            (Tcons
                                              (tptr (Tstruct _jit_state noattr))
                                              (Tcons tuint Tnil)) tvoid
                                            cc_default))
          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
           (Econst_int (Int.repr 7) tuint) :: nil))
        (Ssequence
          (Scall None
            (Evar _jit_alu32_thumb_upd_save (Tfunction
                                              (Tcons
                                                (tptr (Tstruct _jit_state noattr))
                                                (Tcons tuint Tnil)) tvoid
                                              cc_default))
            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
             (Econst_int (Int.repr 8) tuint) :: nil))
          (Ssequence
            (Scall None
              (Evar _jit_alu32_thumb_upd_save (Tfunction
                                                (Tcons
                                                  (tptr (Tstruct _jit_state noattr))
                                                  (Tcons tuint Tnil)) tvoid
                                                cc_default))
              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
               (Econst_int (Int.repr 9) tuint) :: nil))
            (Ssequence
              (Scall None
                (Evar _jit_alu32_thumb_upd_save (Tfunction
                                                  (Tcons
                                                    (tptr (Tstruct _jit_state noattr))
                                                    (Tcons tuint Tnil)) tvoid
                                                  cc_default))
                ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                 (Econst_int (Int.repr 10) tuint) :: nil))
              (Ssequence
                (Ssequence
                  (Scall (Some _t'1)
                    (Evar _eval_use_IR11 (Tfunction
                                           (Tcons
                                             (tptr (Tstruct _jit_state noattr))
                                             Tnil) tbool cc_default))
                    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                     nil))
                  (Sset _b (Ecast (Etempvar _t'1 tbool) tbool)))
                (Sifthenelse (Etempvar _b tbool)
                  (Ssequence
                    (Scall None
                      (Evar _jit_alu32_thumb_store_template_jit (Tfunction
                                                                  (Tcons
                                                                    (tptr (Tstruct _jit_state noattr))
                                                                    (Tcons
                                                                    tushort
                                                                    (Tcons
                                                                    tushort
                                                                    (Tcons
                                                                    tushort
                                                                    Tnil))))
                                                                  tvoid
                                                                  cc_default))
                      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                       (Econst_int (Int.repr 11) tint) ::
                       (Econst_int (Int.repr 13) tuint) ::
                       (Econst_int (Int.repr 44) tint) :: nil))
                    (Sreturn None))
                  (Sreturn None))))))))))
|}.

Definition f_jit_alu32_thumb_upd_load := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: (_r, tuint) ::
                nil);
  fn_vars := nil;
  fn_temps := ((_b, tbool) :: (_int_r, tuint) :: (_t'1, tbool) :: nil);
  fn_body :=
(Ssequence
  (Ssequence
    (Scall (Some _t'1)
      (Evar _is_load_reg (Tfunction
                           (Tcons (tptr (Tstruct _jit_state noattr))
                             (Tcons tuint Tnil)) tbool cc_default))
      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
       (Etempvar _r tuint) :: nil))
    (Sset _b (Ecast (Etempvar _t'1 tbool) tbool)))
  (Sifthenelse (Etempvar _b tbool)
    (Ssequence
      (Sset _int_r (Etempvar _r tuint))
      (Ssequence
        (Scall None
          (Evar _jit_alu32_thumb_load_template_jit (Tfunction
                                                     (Tcons
                                                       (tptr (Tstruct _jit_state noattr))
                                                       (Tcons tushort
                                                         (Tcons tushort
                                                           (Tcons tushort
                                                             Tnil)))) tvoid
                                                     cc_default))
          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
           (Etempvar _int_r tuint) :: (Econst_int (Int.repr 0) tint) ::
           (Ebinop Omul (Etempvar _int_r tuint)
             (Econst_int (Int.repr 8) tint) tuint) :: nil))
        (Sreturn None)))
    (Sreturn None)))
|}.

Definition f_no_reg_load := {|
  fn_return := tbool;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: nil);
  fn_vars := nil;
  fn_temps := ((_b0, tbool) :: (_b1, tbool) :: (_b2, tbool) ::
               (_b3, tbool) :: (_b4, tbool) :: (_b5, tbool) ::
               (_b6, tbool) :: (_b7, tbool) :: (_b8, tbool) ::
               (_b9, tbool) :: (_b10, tbool) :: (_t'11, tbool) ::
               (_t'10, tbool) :: (_t'9, tbool) :: (_t'8, tbool) ::
               (_t'7, tbool) :: (_t'6, tbool) :: (_t'5, tbool) ::
               (_t'4, tbool) :: (_t'3, tbool) :: (_t'2, tbool) ::
               (_t'1, tbool) :: nil);
  fn_body :=
(Ssequence
  (Ssequence
    (Scall (Some _t'1)
      (Evar _is_load_reg (Tfunction
                           (Tcons (tptr (Tstruct _jit_state noattr))
                             (Tcons tuint Tnil)) tbool cc_default))
      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
       (Econst_int (Int.repr 0) tuint) :: nil))
    (Sset _b0 (Ecast (Etempvar _t'1 tbool) tbool)))
  (Sifthenelse (Etempvar _b0 tbool)
    (Sreturn (Some (Econst_int (Int.repr 0) tint)))
    (Ssequence
      (Ssequence
        (Scall (Some _t'2)
          (Evar _is_load_reg (Tfunction
                               (Tcons (tptr (Tstruct _jit_state noattr))
                                 (Tcons tuint Tnil)) tbool cc_default))
          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
           (Econst_int (Int.repr 1) tuint) :: nil))
        (Sset _b1 (Ecast (Etempvar _t'2 tbool) tbool)))
      (Sifthenelse (Etempvar _b1 tbool)
        (Sreturn (Some (Econst_int (Int.repr 0) tint)))
        (Ssequence
          (Ssequence
            (Scall (Some _t'3)
              (Evar _is_load_reg (Tfunction
                                   (Tcons (tptr (Tstruct _jit_state noattr))
                                     (Tcons tuint Tnil)) tbool cc_default))
              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
               (Econst_int (Int.repr 2) tuint) :: nil))
            (Sset _b2 (Ecast (Etempvar _t'3 tbool) tbool)))
          (Sifthenelse (Etempvar _b2 tbool)
            (Sreturn (Some (Econst_int (Int.repr 0) tint)))
            (Ssequence
              (Ssequence
                (Scall (Some _t'4)
                  (Evar _is_load_reg (Tfunction
                                       (Tcons
                                         (tptr (Tstruct _jit_state noattr))
                                         (Tcons tuint Tnil)) tbool
                                       cc_default))
                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                   (Econst_int (Int.repr 3) tuint) :: nil))
                (Sset _b3 (Ecast (Etempvar _t'4 tbool) tbool)))
              (Sifthenelse (Etempvar _b3 tbool)
                (Sreturn (Some (Econst_int (Int.repr 0) tint)))
                (Ssequence
                  (Ssequence
                    (Scall (Some _t'5)
                      (Evar _is_load_reg (Tfunction
                                           (Tcons
                                             (tptr (Tstruct _jit_state noattr))
                                             (Tcons tuint Tnil)) tbool
                                           cc_default))
                      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                       (Econst_int (Int.repr 4) tuint) :: nil))
                    (Sset _b4 (Ecast (Etempvar _t'5 tbool) tbool)))
                  (Sifthenelse (Etempvar _b4 tbool)
                    (Sreturn (Some (Econst_int (Int.repr 0) tint)))
                    (Ssequence
                      (Ssequence
                        (Scall (Some _t'6)
                          (Evar _is_load_reg (Tfunction
                                               (Tcons
                                                 (tptr (Tstruct _jit_state noattr))
                                                 (Tcons tuint Tnil)) tbool
                                               cc_default))
                          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                           (Econst_int (Int.repr 5) tuint) :: nil))
                        (Sset _b5 (Ecast (Etempvar _t'6 tbool) tbool)))
                      (Sifthenelse (Etempvar _b5 tbool)
                        (Sreturn (Some (Econst_int (Int.repr 0) tint)))
                        (Ssequence
                          (Ssequence
                            (Scall (Some _t'7)
                              (Evar _is_load_reg (Tfunction
                                                   (Tcons
                                                     (tptr (Tstruct _jit_state noattr))
                                                     (Tcons tuint Tnil))
                                                   tbool cc_default))
                              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                               (Econst_int (Int.repr 6) tuint) :: nil))
                            (Sset _b6 (Ecast (Etempvar _t'7 tbool) tbool)))
                          (Sifthenelse (Etempvar _b6 tbool)
                            (Sreturn (Some (Econst_int (Int.repr 0) tint)))
                            (Ssequence
                              (Ssequence
                                (Scall (Some _t'8)
                                  (Evar _is_load_reg (Tfunction
                                                       (Tcons
                                                         (tptr (Tstruct _jit_state noattr))
                                                         (Tcons tuint Tnil))
                                                       tbool cc_default))
                                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                   (Econst_int (Int.repr 7) tuint) :: nil))
                                (Sset _b7
                                  (Ecast (Etempvar _t'8 tbool) tbool)))
                              (Sifthenelse (Etempvar _b7 tbool)
                                (Sreturn (Some (Econst_int (Int.repr 0) tint)))
                                (Ssequence
                                  (Ssequence
                                    (Scall (Some _t'9)
                                      (Evar _is_load_reg (Tfunction
                                                           (Tcons
                                                             (tptr (Tstruct _jit_state noattr))
                                                             (Tcons tuint
                                                               Tnil)) tbool
                                                           cc_default))
                                      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                       (Econst_int (Int.repr 8) tuint) ::
                                       nil))
                                    (Sset _b8
                                      (Ecast (Etempvar _t'9 tbool) tbool)))
                                  (Sifthenelse (Etempvar _b8 tbool)
                                    (Sreturn (Some (Econst_int (Int.repr 0) tint)))
                                    (Ssequence
                                      (Ssequence
                                        (Scall (Some _t'10)
                                          (Evar _is_load_reg (Tfunction
                                                               (Tcons
                                                                 (tptr (Tstruct _jit_state noattr))
                                                                 (Tcons tuint
                                                                   Tnil))
                                                               tbool
                                                               cc_default))
                                          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                           (Econst_int (Int.repr 9) tuint) ::
                                           nil))
                                        (Sset _b9
                                          (Ecast (Etempvar _t'10 tbool)
                                            tbool)))
                                      (Sifthenelse (Etempvar _b9 tbool)
                                        (Sreturn (Some (Econst_int (Int.repr 0) tint)))
                                        (Ssequence
                                          (Ssequence
                                            (Scall (Some _t'11)
                                              (Evar _is_load_reg (Tfunction
                                                                   (Tcons
                                                                    (tptr (Tstruct _jit_state noattr))
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil))
                                                                   tbool
                                                                   cc_default))
                                              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                               (Econst_int (Int.repr 10) tuint) ::
                                               nil))
                                            (Sset _b10
                                              (Ecast (Etempvar _t'11 tbool)
                                                tbool)))
                                          (Sifthenelse (Etempvar _b10 tbool)
                                            (Sreturn (Some (Econst_int (Int.repr 0) tint)))
                                            (Sreturn (Some (Econst_int (Int.repr 1) tint)))))))))))))))))))))))))
|}.

Definition f_jit_alu32_thumb_load := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: nil);
  fn_vars := nil;
  fn_temps := ((_b, tbool) :: (_t'1, tbool) :: nil);
  fn_body :=
(Ssequence
  (Ssequence
    (Scall (Some _t'1)
      (Evar _no_reg_load (Tfunction
                           (Tcons (tptr (Tstruct _jit_state noattr)) Tnil)
                           tbool cc_default))
      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) :: nil))
    (Sset _b (Ecast (Etempvar _t'1 tbool) tbool)))
  (Sifthenelse (Etempvar _b tbool)
    (Sreturn None)
    (Ssequence
      (Scall None
        (Evar _jit_alu32_thumb_load_template_jit (Tfunction
                                                   (Tcons
                                                     (tptr (Tstruct _jit_state noattr))
                                                     (Tcons tushort
                                                       (Tcons tushort
                                                         (Tcons tushort Tnil))))
                                                   tvoid cc_default))
        ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
         (Econst_int (Int.repr 0) tint) :: (Econst_int (Int.repr 12) tint) ::
         (Econst_int (Int.repr 8) tint) :: nil))
      (Ssequence
        (Scall None
          (Evar _jit_alu32_thumb_upd_load (Tfunction
                                            (Tcons
                                              (tptr (Tstruct _jit_state noattr))
                                              (Tcons tuint Tnil)) tvoid
                                            cc_default))
          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
           (Econst_int (Int.repr 10) tuint) :: nil))
        (Ssequence
          (Scall None
            (Evar _jit_alu32_thumb_upd_load (Tfunction
                                              (Tcons
                                                (tptr (Tstruct _jit_state noattr))
                                                (Tcons tuint Tnil)) tvoid
                                              cc_default))
            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
             (Econst_int (Int.repr 9) tuint) :: nil))
          (Ssequence
            (Scall None
              (Evar _jit_alu32_thumb_upd_load (Tfunction
                                                (Tcons
                                                  (tptr (Tstruct _jit_state noattr))
                                                  (Tcons tuint Tnil)) tvoid
                                                cc_default))
              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
               (Econst_int (Int.repr 8) tuint) :: nil))
            (Ssequence
              (Scall None
                (Evar _jit_alu32_thumb_upd_load (Tfunction
                                                  (Tcons
                                                    (tptr (Tstruct _jit_state noattr))
                                                    (Tcons tuint Tnil)) tvoid
                                                  cc_default))
                ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                 (Econst_int (Int.repr 7) tuint) :: nil))
              (Ssequence
                (Scall None
                  (Evar _jit_alu32_thumb_upd_load (Tfunction
                                                    (Tcons
                                                      (tptr (Tstruct _jit_state noattr))
                                                      (Tcons tuint Tnil))
                                                    tvoid cc_default))
                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                   (Econst_int (Int.repr 6) tuint) :: nil))
                (Ssequence
                  (Scall None
                    (Evar _jit_alu32_thumb_upd_load (Tfunction
                                                      (Tcons
                                                        (tptr (Tstruct _jit_state noattr))
                                                        (Tcons tuint Tnil))
                                                      tvoid cc_default))
                    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                     (Econst_int (Int.repr 5) tuint) :: nil))
                  (Ssequence
                    (Scall None
                      (Evar _jit_alu32_thumb_upd_load (Tfunction
                                                        (Tcons
                                                          (tptr (Tstruct _jit_state noattr))
                                                          (Tcons tuint Tnil))
                                                        tvoid cc_default))
                      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                       (Econst_int (Int.repr 4) tuint) :: nil))
                    (Ssequence
                      (Scall None
                        (Evar _jit_alu32_thumb_upd_load (Tfunction
                                                          (Tcons
                                                            (tptr (Tstruct _jit_state noattr))
                                                            (Tcons tuint
                                                              Tnil)) tvoid
                                                          cc_default))
                        ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                         (Econst_int (Int.repr 3) tuint) :: nil))
                      (Ssequence
                        (Scall None
                          (Evar _jit_alu32_thumb_upd_load (Tfunction
                                                            (Tcons
                                                              (tptr (Tstruct _jit_state noattr))
                                                              (Tcons tuint
                                                                Tnil)) tvoid
                                                            cc_default))
                          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                           (Econst_int (Int.repr 2) tuint) :: nil))
                        (Ssequence
                          (Scall None
                            (Evar _jit_alu32_thumb_upd_load (Tfunction
                                                              (Tcons
                                                                (tptr (Tstruct _jit_state noattr))
                                                                (Tcons tuint
                                                                  Tnil))
                                                              tvoid
                                                              cc_default))
                            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                             (Econst_int (Int.repr 1) tuint) :: nil))
                          (Ssequence
                            (Scall None
                              (Evar _jit_alu32_thumb_upd_load (Tfunction
                                                                (Tcons
                                                                  (tptr (Tstruct _jit_state noattr))
                                                                  (Tcons
                                                                    tuint
                                                                    Tnil))
                                                                tvoid
                                                                cc_default))
                              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                               (Econst_int (Int.repr 0) tuint) :: nil))
                            (Sreturn None)))))))))))))))
|}.

Definition f_bpf_alu32_to_thumb_reg := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: (_op, tuchar) ::
                (_dst, tuint) :: (_src, tuint) :: nil);
  fn_vars := nil;
  fn_temps := ((_d, tuint) :: (_rdn, tuint) :: (_ins_rdn, tuint) ::
               (_ins_rm, tuint) :: (_ins, tuint) :: (_r, tuint) ::
               (_ins_lo, tuint) :: (_ins_hi, tuint) :: (_ins_hi0, tuint) ::
               (_cmp_lo, tuint) :: (_b_r1, tbool) :: (_b_ne, tushort) ::
               (_b_lt, tushort) :: (_lsl_lo, tuint) :: (_lsl_hi, tushort) ::
               (_lsr_lo, tuint) :: (_lsr_hi, tushort) :: (_asr_lo, tuint) ::
               (_asr_hi, tushort) :: (_t'51, tuint) :: (_t'50, tushort) ::
               (_t'49, tuint) :: (_t'48, tushort) :: (_t'47, tushort) ::
               (_t'46, tbool) :: (_t'45, tuint) :: (_t'44, tuint) ::
               (_t'43, tuint) :: (_t'42, tuint) :: (_t'41, tuint) ::
               (_t'40, tuint) :: (_t'39, tuint) :: (_t'38, tuint) ::
               (_t'37, tuint) :: (_t'36, tushort) :: (_t'35, tuint) ::
               (_t'34, tushort) :: (_t'33, tushort) :: (_t'32, tbool) ::
               (_t'31, tuint) :: (_t'30, tuint) :: (_t'29, tushort) ::
               (_t'28, tuint) :: (_t'27, tushort) :: (_t'26, tushort) ::
               (_t'25, tbool) :: (_t'24, tuint) :: (_t'23, tuint) ::
               (_t'22, tuint) :: (_t'21, tuint) :: (_t'20, tuint) ::
               (_t'19, tuint) :: (_t'18, tuint) :: (_t'17, tint) ::
               (_t'16, tuint) :: (_t'15, tushort) :: (_t'14, tushort) ::
               (_t'13, tbool) :: (_t'12, tuint) :: (_t'11, tuint) ::
               (_t'10, tuint) :: (_t'9, tuint) :: (_t'8, tuint) ::
               (_t'7, tuint) :: (_t'6, tuint) :: (_t'5, tuint) ::
               (_t'4, tuint) :: (_t'3, tuint) :: (_t'2, tuint) ::
               (_t'1, tuint) :: nil);
  fn_body :=
(Sswitch (Etempvar _op tuchar)
  (LScons (Some 12)
    (Ssequence
      (Sifthenelse (Ebinop Olt (Etempvar _dst tuint)
                     (Econst_int (Int.repr 8) tint) tint)
        (Sset _d (Econst_int (Int.repr 0) tint))
        (Sset _d (Econst_int (Int.repr 1) tint)))
      (Ssequence
        (Sifthenelse (Ebinop Olt (Etempvar _dst tuint)
                       (Econst_int (Int.repr 8) tint) tint)
          (Sset _rdn (Etempvar _dst tuint))
          (Sset _rdn
            (Ebinop Osub (Etempvar _dst tuint) (Econst_int (Int.repr 8) tint)
              tuint)))
        (Ssequence
          (Ssequence
            (Scall (Some _t'1)
              (Evar _encode_thumb (Tfunction
                                    (Tcons tuint
                                      (Tcons tuint
                                        (Tcons tuint (Tcons tuint Tnil))))
                                    tuint cc_default))
              ((Etempvar _rdn tuint) :: (Econst_int (Int.repr 17408) tint) ::
               (Econst_int (Int.repr 0) tuint) ::
               (Econst_int (Int.repr 3) tuint) :: nil))
            (Sset _ins_rdn (Etempvar _t'1 tuint)))
          (Ssequence
            (Ssequence
              (Scall (Some _t'2)
                (Evar _encode_thumb (Tfunction
                                      (Tcons tuint
                                        (Tcons tuint
                                          (Tcons tuint (Tcons tuint Tnil))))
                                      tuint cc_default))
                ((Etempvar _src tuint) :: (Etempvar _ins_rdn tuint) ::
                 (Econst_int (Int.repr 3) tuint) ::
                 (Econst_int (Int.repr 4) tuint) :: nil))
              (Sset _ins_rm (Etempvar _t'2 tuint)))
            (Ssequence
              (Ssequence
                (Scall (Some _t'3)
                  (Evar _encode_thumb (Tfunction
                                        (Tcons tuint
                                          (Tcons tuint
                                            (Tcons tuint (Tcons tuint Tnil))))
                                        tuint cc_default))
                  ((Etempvar _d tuint) :: (Etempvar _ins_rm tuint) ::
                   (Econst_int (Int.repr 7) tuint) ::
                   (Econst_int (Int.repr 1) tuint) :: nil))
                (Sset _ins (Etempvar _t'3 tuint)))
              (Ssequence
                (Scall None
                  (Evar _add_ins_jittedthumb (Tfunction
                                               (Tcons
                                                 (tptr (Tstruct _jit_state noattr))
                                                 (Tcons tuint Tnil)) tvoid
                                               cc_default))
                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                   (Etempvar _ins tuint) :: nil))
                (Ssequence
                  (Scall None
                    (Evar _upd_load_store_regs_jittedthumb (Tfunction
                                                             (Tcons
                                                               (tptr (Tstruct _jit_state noattr))
                                                               (Tcons tuint
                                                                 (Tcons tuint
                                                                   Tnil)))
                                                             tvoid
                                                             cc_default))
                    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                     (Etempvar _dst tuint) ::
                     (Econst_int (Int.repr 3) tuint) :: nil))
                  (Sifthenelse (Ebinop Oeq (Etempvar _src tuint)
                                 (Econst_int (Int.repr 11) tuint) tint)
                    (Sreturn None)
                    (Ssequence
                      (Ssequence
                        (Scall (Some _t'4)
                          (Evar _reg_of_ireg (Tfunction (Tcons tuint Tnil)
                                               tuint cc_default))
                          ((Etempvar _src tuint) :: nil))
                        (Sset _r (Etempvar _t'4 tuint)))
                      (Ssequence
                        (Scall None
                          (Evar _upd_load_store_regs_jittedthumb (Tfunction
                                                                   (Tcons
                                                                    (tptr (Tstruct _jit_state noattr))
                                                                    (Tcons
                                                                    tuint
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)))
                                                                   tvoid
                                                                   cc_default))
                          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                           (Etempvar _r tuint) ::
                           (Econst_int (Int.repr 1) tuint) :: nil))
                        (Sreturn None)))))))))))
    (LScons (Some 28)
      (Ssequence
        (Ssequence
          (Scall (Some _t'5)
            (Evar _encode_thumb (Tfunction
                                  (Tcons tuint
                                    (Tcons tuint
                                      (Tcons tuint (Tcons tuint Tnil))))
                                  tuint cc_default))
            ((Etempvar _dst tuint) :: (Econst_int (Int.repr 60320) tint) ::
             (Econst_int (Int.repr 0) tuint) ::
             (Econst_int (Int.repr 4) tuint) :: nil))
          (Sset _ins_lo (Etempvar _t'5 tuint)))
        (Ssequence
          (Ssequence
            (Scall (Some _t'6)
              (Evar _encode_thumb (Tfunction
                                    (Tcons tuint
                                      (Tcons tuint
                                        (Tcons tuint (Tcons tuint Tnil))))
                                    tuint cc_default))
              ((Etempvar _dst tuint) :: (Etempvar _src tuint) ::
               (Econst_int (Int.repr 8) tuint) ::
               (Econst_int (Int.repr 4) tuint) :: nil))
            (Sset _ins_hi (Etempvar _t'6 tuint)))
          (Ssequence
            (Scall None
              (Evar _add_ins_jittedthumb (Tfunction
                                           (Tcons
                                             (tptr (Tstruct _jit_state noattr))
                                             (Tcons tuint Tnil)) tvoid
                                           cc_default))
              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
               (Etempvar _ins_lo tuint) :: nil))
            (Ssequence
              (Scall None
                (Evar _add_ins_jittedthumb (Tfunction
                                             (Tcons
                                               (tptr (Tstruct _jit_state noattr))
                                               (Tcons tuint Tnil)) tvoid
                                             cc_default))
                ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                 (Etempvar _ins_hi tuint) :: nil))
              (Ssequence
                (Scall None
                  (Evar _upd_load_store_regs_jittedthumb (Tfunction
                                                           (Tcons
                                                             (tptr (Tstruct _jit_state noattr))
                                                             (Tcons tuint
                                                               (Tcons tuint
                                                                 Tnil)))
                                                           tvoid cc_default))
                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                   (Etempvar _dst tuint) ::
                   (Econst_int (Int.repr 3) tuint) :: nil))
                (Sifthenelse (Ebinop Oeq (Etempvar _src tuint)
                               (Econst_int (Int.repr 11) tuint) tint)
                  (Sreturn None)
                  (Ssequence
                    (Ssequence
                      (Scall (Some _t'7)
                        (Evar _reg_of_ireg (Tfunction (Tcons tuint Tnil)
                                             tuint cc_default))
                        ((Etempvar _src tuint) :: nil))
                      (Sset _r (Etempvar _t'7 tuint)))
                    (Ssequence
                      (Scall None
                        (Evar _upd_load_store_regs_jittedthumb (Tfunction
                                                                 (Tcons
                                                                   (tptr (Tstruct _jit_state noattr))
                                                                   (Tcons
                                                                    tuint
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)))
                                                                 tvoid
                                                                 cc_default))
                        ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                         (Etempvar _r tuint) ::
                         (Econst_int (Int.repr 1) tuint) :: nil))
                      (Sreturn None)))))))))
      (LScons (Some 44)
        (Ssequence
          (Ssequence
            (Scall (Some _t'8)
              (Evar _encode_thumb (Tfunction
                                    (Tcons tuint
                                      (Tcons tuint
                                        (Tcons tuint (Tcons tuint Tnil))))
                                    tuint cc_default))
              ((Etempvar _dst tuint) :: (Econst_int (Int.repr 64256) tint) ::
               (Econst_int (Int.repr 0) tuint) ::
               (Econst_int (Int.repr 4) tuint) :: nil))
            (Sset _ins_lo (Etempvar _t'8 tuint)))
          (Ssequence
            (Ssequence
              (Scall (Some _t'9)
                (Evar _encode_thumb (Tfunction
                                      (Tcons tuint
                                        (Tcons tuint
                                          (Tcons tuint (Tcons tuint Tnil))))
                                      tuint cc_default))
                ((Etempvar _dst tuint) :: (Etempvar _src tuint) ::
                 (Econst_int (Int.repr 8) tuint) ::
                 (Econst_int (Int.repr 4) tuint) :: nil))
              (Sset _ins_hi0 (Etempvar _t'9 tuint)))
            (Ssequence
              (Ssequence
                (Scall (Some _t'10)
                  (Evar _encode_thumb (Tfunction
                                        (Tcons tuint
                                          (Tcons tuint
                                            (Tcons tuint (Tcons tuint Tnil))))
                                        tuint cc_default))
                  ((Econst_int (Int.repr 15) tint) ::
                   (Etempvar _ins_hi0 tuint) ::
                   (Econst_int (Int.repr 12) tuint) ::
                   (Econst_int (Int.repr 4) tuint) :: nil))
                (Sset _ins_hi (Etempvar _t'10 tuint)))
              (Ssequence
                (Scall None
                  (Evar _add_ins_jittedthumb (Tfunction
                                               (Tcons
                                                 (tptr (Tstruct _jit_state noattr))
                                                 (Tcons tuint Tnil)) tvoid
                                               cc_default))
                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                   (Etempvar _ins_lo tuint) :: nil))
                (Ssequence
                  (Scall None
                    (Evar _add_ins_jittedthumb (Tfunction
                                                 (Tcons
                                                   (tptr (Tstruct _jit_state noattr))
                                                   (Tcons tuint Tnil)) tvoid
                                                 cc_default))
                    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                     (Etempvar _ins_hi tuint) :: nil))
                  (Ssequence
                    (Scall None
                      (Evar _upd_load_store_regs_jittedthumb (Tfunction
                                                               (Tcons
                                                                 (tptr (Tstruct _jit_state noattr))
                                                                 (Tcons tuint
                                                                   (Tcons
                                                                    tuint
                                                                    Tnil)))
                                                               tvoid
                                                               cc_default))
                      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                       (Etempvar _dst tuint) ::
                       (Econst_int (Int.repr 3) tuint) :: nil))
                    (Sifthenelse (Ebinop Oeq (Etempvar _src tuint)
                                   (Econst_int (Int.repr 11) tuint) tint)
                      (Sreturn None)
                      (Ssequence
                        (Ssequence
                          (Scall (Some _t'11)
                            (Evar _reg_of_ireg (Tfunction (Tcons tuint Tnil)
                                                 tuint cc_default))
                            ((Etempvar _src tuint) :: nil))
                          (Sset _r (Etempvar _t'11 tuint)))
                        (Ssequence
                          (Scall None
                            (Evar _upd_load_store_regs_jittedthumb (Tfunction
                                                                    (Tcons
                                                                    (tptr (Tstruct _jit_state noattr))
                                                                    (Tcons
                                                                    tuint
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)))
                                                                    tvoid
                                                                    cc_default))
                            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                             (Etempvar _r tuint) ::
                             (Econst_int (Int.repr 1) tuint) :: nil))
                          (Sreturn None))))))))))
        (LScons (Some 60)
          (Ssequence
            (Sifthenelse (Ebinop Oeq (Etempvar _dst tuint)
                           (Econst_int (Int.repr 0) tuint) tint)
              (Sset _t'17
                (Ecast
                  (Ebinop Oeq (Etempvar _src tuint)
                    (Econst_int (Int.repr 1) tuint) tint) tbool))
              (Sset _t'17 (Econst_int (Int.repr 0) tint)))
            (Sifthenelse (Etempvar _t'17 tint)
              (Ssequence
                (Scall None
                  (Evar _upd_IR11_jittedthumb (Tfunction
                                                (Tcons
                                                  (tptr (Tstruct _jit_state noattr))
                                                  (Tcons tbool Tnil)) tvoid
                                                cc_default))
                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                   (Econst_int (Int.repr 1) tint) :: nil))
                (Ssequence
                  (Ssequence
                    (Scall (Some _t'12)
                      (Evar _encode_thumb (Tfunction
                                            (Tcons tuint
                                              (Tcons tuint
                                                (Tcons tuint
                                                  (Tcons tuint Tnil)))) tuint
                                            cc_default))
                      ((Etempvar _src tuint) ::
                       (Econst_int (Int.repr 61872) tint) ::
                       (Econst_int (Int.repr 0) tuint) ::
                       (Econst_int (Int.repr 4) tuint) :: nil))
                    (Sset _cmp_lo (Etempvar _t'12 tuint)))
                  (Ssequence
                    (Scall None
                      (Evar _add_ins_jittedthumb (Tfunction
                                                   (Tcons
                                                     (tptr (Tstruct _jit_state noattr))
                                                     (Tcons tuint Tnil))
                                                   tvoid cc_default))
                      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                       (Etempvar _cmp_lo tuint) :: nil))
                    (Ssequence
                      (Scall None
                        (Evar _add_ins_jittedthumb (Tfunction
                                                     (Tcons
                                                       (tptr (Tstruct _jit_state noattr))
                                                       (Tcons tuint Tnil))
                                                     tvoid cc_default))
                        ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                         (Econst_int (Int.repr 3840) tint) :: nil))
                      (Ssequence
                        (Ssequence
                          (Scall (Some _t'13)
                            (Evar _is_non_reg (Tfunction
                                                (Tcons
                                                  (tptr (Tstruct _jit_state noattr))
                                                  (Tcons tuint Tnil)) tbool
                                                cc_default))
                            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                             (Econst_int (Int.repr 1) tuint) :: nil))
                          (Sset _b_r1 (Ecast (Etempvar _t'13 tbool) tbool)))
                        (Ssequence
                          (Sifthenelse (Etempvar _b_r1 tbool)
                            (Ssequence
                              (Scall (Some _t'14)
                                (Evar _construct_thumb_b (Tfunction
                                                           (Tcons tushort
                                                             (Tcons tushort
                                                               Tnil)) tushort
                                                           cc_default))
                                ((Econst_int (Int.repr 1) tint) ::
                                 (Econst_int (Int.repr 6) tint) :: nil))
                              (Sset _b_ne
                                (Ecast (Etempvar _t'14 tushort) tushort)))
                            (Ssequence
                              (Scall (Some _t'15)
                                (Evar _construct_thumb_b (Tfunction
                                                           (Tcons tushort
                                                             (Tcons tushort
                                                               Tnil)) tushort
                                                           cc_default))
                                ((Econst_int (Int.repr 1) tint) ::
                                 (Econst_int (Int.repr 10) tint) :: nil))
                              (Sset _b_ne
                                (Ecast (Etempvar _t'15 tushort) tushort))))
                          (Ssequence
                            (Scall None
                              (Evar _add_ins_jittedthumb (Tfunction
                                                           (Tcons
                                                             (tptr (Tstruct _jit_state noattr))
                                                             (Tcons tuint
                                                               Tnil)) tvoid
                                                           cc_default))
                              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                               (Etempvar _b_ne tushort) :: nil))
                            (Ssequence
                              (Scall None
                                (Evar _jit_alu32_store_flag (Tfunction
                                                              (Tcons
                                                                (tptr (Tstruct _jit_state noattr))
                                                                (Tcons tuint
                                                                  Tnil))
                                                              tvoid
                                                              cc_default))
                                ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                 (Econst_int (Int.repr 10) tuint) :: nil))
                              (Ssequence
                                (Scall None
                                  (Evar _add_ins_jittedthumb (Tfunction
                                                               (Tcons
                                                                 (tptr (Tstruct _jit_state noattr))
                                                                 (Tcons tuint
                                                                   Tnil))
                                                               tvoid
                                                               cc_default))
                                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                   (Econst_int (Int.repr 53504) tint) :: nil))
                                (Ssequence
                                  (Scall None
                                    (Evar _add_ins_jittedthumb (Tfunction
                                                                 (Tcons
                                                                   (tptr (Tstruct _jit_state noattr))
                                                                   (Tcons
                                                                    tuint
                                                                    Tnil))
                                                                 tvoid
                                                                 cc_default))
                                    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                     (Econst_int (Int.repr 64432) tint) ::
                                     nil))
                                  (Ssequence
                                    (Scall None
                                      (Evar _add_ins_jittedthumb (Tfunction
                                                                   (Tcons
                                                                    (tptr (Tstruct _jit_state noattr))
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil))
                                                                   tvoid
                                                                   cc_default))
                                      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                       (Econst_int (Int.repr 61681) tint) ::
                                       nil))
                                    (Ssequence
                                      (Scall None
                                        (Evar _upd_load_store_regs_jittedthumb 
                                        (Tfunction
                                          (Tcons
                                            (tptr (Tstruct _jit_state noattr))
                                            (Tcons tuint (Tcons tuint Tnil)))
                                          tvoid cc_default))
                                        ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                         (Etempvar _dst tuint) ::
                                         (Econst_int (Int.repr 3) tuint) ::
                                         nil))
                                      (Sifthenelse (Ebinop Oeq
                                                     (Etempvar _src tuint)
                                                     (Econst_int (Int.repr 11) tuint)
                                                     tint)
                                        (Sreturn None)
                                        (Ssequence
                                          (Ssequence
                                            (Scall (Some _t'16)
                                              (Evar _reg_of_ireg (Tfunction
                                                                   (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                   tuint
                                                                   cc_default))
                                              ((Etempvar _src tuint) :: nil))
                                            (Sset _r (Etempvar _t'16 tuint)))
                                          (Ssequence
                                            (Scall None
                                              (Evar _upd_load_store_regs_jittedthumb 
                                              (Tfunction
                                                (Tcons
                                                  (tptr (Tstruct _jit_state noattr))
                                                  (Tcons tuint
                                                    (Tcons tuint Tnil)))
                                                tvoid cc_default))
                                              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                               (Etempvar _r tuint) ::
                                               (Econst_int (Int.repr 1) tuint) ::
                                               nil))
                                            (Sreturn None))))))))))))))))
              (Ssequence
                (Scall None
                  (Evar _upd_flag (Tfunction
                                    (Tcons (tptr (Tstruct _jit_state noattr))
                                      (Tcons tuint Tnil)) tvoid cc_default))
                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                   (Econst_int (Int.repr 10) tuint) :: nil))
                (Sreturn None))))
          (LScons (Some 76)
            (Ssequence
              (Ssequence
                (Scall (Some _t'18)
                  (Evar _encode_thumb (Tfunction
                                        (Tcons tuint
                                          (Tcons tuint
                                            (Tcons tuint (Tcons tuint Tnil))))
                                        tuint cc_default))
                  ((Etempvar _dst tuint) ::
                   (Econst_int (Int.repr 59968) tint) ::
                   (Econst_int (Int.repr 0) tuint) ::
                   (Econst_int (Int.repr 4) tuint) :: nil))
                (Sset _ins_lo (Etempvar _t'18 tuint)))
              (Ssequence
                (Ssequence
                  (Scall (Some _t'19)
                    (Evar _encode_thumb (Tfunction
                                          (Tcons tuint
                                            (Tcons tuint
                                              (Tcons tuint
                                                (Tcons tuint Tnil)))) tuint
                                          cc_default))
                    ((Etempvar _dst tuint) :: (Etempvar _src tuint) ::
                     (Econst_int (Int.repr 8) tuint) ::
                     (Econst_int (Int.repr 4) tuint) :: nil))
                  (Sset _ins_hi (Etempvar _t'19 tuint)))
                (Ssequence
                  (Scall None
                    (Evar _add_ins_jittedthumb (Tfunction
                                                 (Tcons
                                                   (tptr (Tstruct _jit_state noattr))
                                                   (Tcons tuint Tnil)) tvoid
                                                 cc_default))
                    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                     (Etempvar _ins_lo tuint) :: nil))
                  (Ssequence
                    (Scall None
                      (Evar _add_ins_jittedthumb (Tfunction
                                                   (Tcons
                                                     (tptr (Tstruct _jit_state noattr))
                                                     (Tcons tuint Tnil))
                                                   tvoid cc_default))
                      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                       (Etempvar _ins_hi tuint) :: nil))
                    (Ssequence
                      (Scall None
                        (Evar _upd_load_store_regs_jittedthumb (Tfunction
                                                                 (Tcons
                                                                   (tptr (Tstruct _jit_state noattr))
                                                                   (Tcons
                                                                    tuint
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)))
                                                                 tvoid
                                                                 cc_default))
                        ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                         (Etempvar _dst tuint) ::
                         (Econst_int (Int.repr 3) tuint) :: nil))
                      (Sifthenelse (Ebinop Oeq (Etempvar _src tuint)
                                     (Econst_int (Int.repr 11) tuint) tint)
                        (Sreturn None)
                        (Ssequence
                          (Ssequence
                            (Scall (Some _t'20)
                              (Evar _reg_of_ireg (Tfunction
                                                   (Tcons tuint Tnil) tuint
                                                   cc_default))
                              ((Etempvar _src tuint) :: nil))
                            (Sset _r (Etempvar _t'20 tuint)))
                          (Ssequence
                            (Scall None
                              (Evar _upd_load_store_regs_jittedthumb 
                              (Tfunction
                                (Tcons (tptr (Tstruct _jit_state noattr))
                                  (Tcons tuint (Tcons tuint Tnil))) tvoid
                                cc_default))
                              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                               (Etempvar _r tuint) ::
                               (Econst_int (Int.repr 1) tuint) :: nil))
                            (Sreturn None)))))))))
            (LScons (Some 92)
              (Ssequence
                (Ssequence
                  (Scall (Some _t'21)
                    (Evar _encode_thumb (Tfunction
                                          (Tcons tuint
                                            (Tcons tuint
                                              (Tcons tuint
                                                (Tcons tuint Tnil)))) tuint
                                          cc_default))
                    ((Etempvar _dst tuint) ::
                     (Econst_int (Int.repr 59904) tint) ::
                     (Econst_int (Int.repr 0) tuint) ::
                     (Econst_int (Int.repr 4) tuint) :: nil))
                  (Sset _ins_lo (Etempvar _t'21 tuint)))
                (Ssequence
                  (Ssequence
                    (Scall (Some _t'22)
                      (Evar _encode_thumb (Tfunction
                                            (Tcons tuint
                                              (Tcons tuint
                                                (Tcons tuint
                                                  (Tcons tuint Tnil)))) tuint
                                            cc_default))
                      ((Etempvar _dst tuint) :: (Etempvar _src tuint) ::
                       (Econst_int (Int.repr 8) tuint) ::
                       (Econst_int (Int.repr 4) tuint) :: nil))
                    (Sset _ins_hi (Etempvar _t'22 tuint)))
                  (Ssequence
                    (Scall None
                      (Evar _add_ins_jittedthumb (Tfunction
                                                   (Tcons
                                                     (tptr (Tstruct _jit_state noattr))
                                                     (Tcons tuint Tnil))
                                                   tvoid cc_default))
                      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                       (Etempvar _ins_lo tuint) :: nil))
                    (Ssequence
                      (Scall None
                        (Evar _add_ins_jittedthumb (Tfunction
                                                     (Tcons
                                                       (tptr (Tstruct _jit_state noattr))
                                                       (Tcons tuint Tnil))
                                                     tvoid cc_default))
                        ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                         (Etempvar _ins_hi tuint) :: nil))
                      (Ssequence
                        (Scall None
                          (Evar _upd_load_store_regs_jittedthumb (Tfunction
                                                                   (Tcons
                                                                    (tptr (Tstruct _jit_state noattr))
                                                                    (Tcons
                                                                    tuint
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)))
                                                                   tvoid
                                                                   cc_default))
                          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                           (Etempvar _dst tuint) ::
                           (Econst_int (Int.repr 3) tuint) :: nil))
                        (Sifthenelse (Ebinop Oeq (Etempvar _src tuint)
                                       (Econst_int (Int.repr 11) tuint) tint)
                          (Sreturn None)
                          (Ssequence
                            (Ssequence
                              (Scall (Some _t'23)
                                (Evar _reg_of_ireg (Tfunction
                                                     (Tcons tuint Tnil) tuint
                                                     cc_default))
                                ((Etempvar _src tuint) :: nil))
                              (Sset _r (Etempvar _t'23 tuint)))
                            (Ssequence
                              (Scall None
                                (Evar _upd_load_store_regs_jittedthumb 
                                (Tfunction
                                  (Tcons (tptr (Tstruct _jit_state noattr))
                                    (Tcons tuint (Tcons tuint Tnil))) tvoid
                                  cc_default))
                                ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                 (Etempvar _r tuint) ::
                                 (Econst_int (Int.repr 1) tuint) :: nil))
                              (Sreturn None)))))))))
              (LScons (Some 108)
                (Ssequence
                  (Scall None
                    (Evar _upd_IR11_jittedthumb (Tfunction
                                                  (Tcons
                                                    (tptr (Tstruct _jit_state noattr))
                                                    (Tcons tbool Tnil)) tvoid
                                                  cc_default))
                    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                     (Econst_int (Int.repr 1) tint) :: nil))
                  (Ssequence
                    (Ssequence
                      (Scall (Some _t'24)
                        (Evar _encode_thumb (Tfunction
                                              (Tcons tuint
                                                (Tcons tuint
                                                  (Tcons tuint
                                                    (Tcons tuint Tnil))))
                                              tuint cc_default))
                        ((Etempvar _src tuint) ::
                         (Econst_int (Int.repr 61872) tint) ::
                         (Econst_int (Int.repr 0) tuint) ::
                         (Econst_int (Int.repr 4) tuint) :: nil))
                      (Sset _cmp_lo (Etempvar _t'24 tuint)))
                    (Ssequence
                      (Scall None
                        (Evar _add_ins_jittedthumb (Tfunction
                                                     (Tcons
                                                       (tptr (Tstruct _jit_state noattr))
                                                       (Tcons tuint Tnil))
                                                     tvoid cc_default))
                        ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                         (Etempvar _cmp_lo tuint) :: nil))
                      (Ssequence
                        (Scall None
                          (Evar _add_ins_jittedthumb (Tfunction
                                                       (Tcons
                                                         (tptr (Tstruct _jit_state noattr))
                                                         (Tcons tuint Tnil))
                                                       tvoid cc_default))
                          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                           (Econst_int (Int.repr 3872) tint) :: nil))
                        (Ssequence
                          (Ssequence
                            (Scall (Some _t'25)
                              (Evar _is_non_reg (Tfunction
                                                  (Tcons
                                                    (tptr (Tstruct _jit_state noattr))
                                                    (Tcons tuint Tnil)) tbool
                                                  cc_default))
                              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                               (Econst_int (Int.repr 1) tuint) :: nil))
                            (Sset _b_r1 (Ecast (Etempvar _t'25 tbool) tbool)))
                          (Ssequence
                            (Sifthenelse (Etempvar _b_r1 tbool)
                              (Ssequence
                                (Scall (Some _t'26)
                                  (Evar _construct_thumb_b (Tfunction
                                                             (Tcons tushort
                                                               (Tcons tushort
                                                                 Tnil))
                                                             tushort
                                                             cc_default))
                                  ((Econst_int (Int.repr 11) tint) ::
                                   (Econst_int (Int.repr 6) tint) :: nil))
                                (Sset _b_lt
                                  (Ecast (Etempvar _t'26 tushort) tushort)))
                              (Ssequence
                                (Scall (Some _t'27)
                                  (Evar _construct_thumb_b (Tfunction
                                                             (Tcons tushort
                                                               (Tcons tushort
                                                                 Tnil))
                                                             tushort
                                                             cc_default))
                                  ((Econst_int (Int.repr 11) tint) ::
                                   (Econst_int (Int.repr 10) tint) :: nil))
                                (Sset _b_lt
                                  (Ecast (Etempvar _t'27 tushort) tushort))))
                            (Ssequence
                              (Scall None
                                (Evar _add_ins_jittedthumb (Tfunction
                                                             (Tcons
                                                               (tptr (Tstruct _jit_state noattr))
                                                               (Tcons tuint
                                                                 Tnil)) tvoid
                                                             cc_default))
                                ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                 (Etempvar _b_lt tushort) :: nil))
                              (Ssequence
                                (Scall None
                                  (Evar _jit_alu32_store_flag (Tfunction
                                                                (Tcons
                                                                  (tptr (Tstruct _jit_state noattr))
                                                                  (Tcons
                                                                    tuint
                                                                    Tnil))
                                                                tvoid
                                                                cc_default))
                                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                   (Econst_int (Int.repr 11) tuint) :: nil))
                                (Ssequence
                                  (Scall None
                                    (Evar _add_ins_jittedthumb (Tfunction
                                                                 (Tcons
                                                                   (tptr (Tstruct _jit_state noattr))
                                                                   (Tcons
                                                                    tuint
                                                                    Tnil))
                                                                 tvoid
                                                                 cc_default))
                                    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                     (Econst_int (Int.repr 56064) tint) ::
                                     nil))
                                  (Ssequence
                                    (Ssequence
                                      (Scall (Some _t'28)
                                        (Evar _encode_thumb (Tfunction
                                                              (Tcons tuint
                                                                (Tcons tuint
                                                                  (Tcons
                                                                    tuint
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil))))
                                                              tuint
                                                              cc_default))
                                        ((Etempvar _dst tuint) ::
                                         (Econst_int (Int.repr 64000) tint) ::
                                         (Econst_int (Int.repr 0) tuint) ::
                                         (Econst_int (Int.repr 4) tuint) ::
                                         nil))
                                      (Sset _lsl_lo (Etempvar _t'28 tuint)))
                                    (Ssequence
                                      (Ssequence
                                        (Scall (Some _t'29)
                                          (Evar _construct_thumb2_shift_rd_rm 
                                          (Tfunction
                                            (Tcons tushort
                                              (Tcons tushort Tnil)) tushort
                                            cc_default))
                                          ((Etempvar _dst tuint) ::
                                           (Etempvar _src tuint) :: nil))
                                        (Sset _lsl_hi
                                          (Ecast (Etempvar _t'29 tushort)
                                            tushort)))
                                      (Ssequence
                                        (Scall None
                                          (Evar _add_ins_jittedthumb 
                                          (Tfunction
                                            (Tcons
                                              (tptr (Tstruct _jit_state noattr))
                                              (Tcons tuint Tnil)) tvoid
                                            cc_default))
                                          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                           (Etempvar _lsl_lo tuint) :: nil))
                                        (Ssequence
                                          (Scall None
                                            (Evar _add_ins_jittedthumb 
                                            (Tfunction
                                              (Tcons
                                                (tptr (Tstruct _jit_state noattr))
                                                (Tcons tuint Tnil)) tvoid
                                              cc_default))
                                            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                             (Etempvar _lsl_hi tushort) ::
                                             nil))
                                          (Ssequence
                                            (Scall None
                                              (Evar _upd_load_store_regs_jittedthumb 
                                              (Tfunction
                                                (Tcons
                                                  (tptr (Tstruct _jit_state noattr))
                                                  (Tcons tuint
                                                    (Tcons tuint Tnil)))
                                                tvoid cc_default))
                                              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                               (Etempvar _dst tuint) ::
                                               (Econst_int (Int.repr 3) tuint) ::
                                               nil))
                                            (Sifthenelse (Ebinop Oeq
                                                           (Etempvar _src tuint)
                                                           (Econst_int (Int.repr 11) tuint)
                                                           tint)
                                              (Sreturn None)
                                              (Ssequence
                                                (Ssequence
                                                  (Scall (Some _t'30)
                                                    (Evar _reg_of_ireg 
                                                    (Tfunction
                                                      (Tcons tuint Tnil)
                                                      tuint cc_default))
                                                    ((Etempvar _src tuint) ::
                                                     nil))
                                                  (Sset _r
                                                    (Etempvar _t'30 tuint)))
                                                (Ssequence
                                                  (Scall None
                                                    (Evar _upd_load_store_regs_jittedthumb 
                                                    (Tfunction
                                                      (Tcons
                                                        (tptr (Tstruct _jit_state noattr))
                                                        (Tcons tuint
                                                          (Tcons tuint Tnil)))
                                                      tvoid cc_default))
                                                    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                                     (Etempvar _r tuint) ::
                                                     (Econst_int (Int.repr 1) tuint) ::
                                                     nil))
                                                  (Sreturn None))))))))))))))))))
                (LScons (Some 124)
                  (Ssequence
                    (Scall None
                      (Evar _upd_IR11_jittedthumb (Tfunction
                                                    (Tcons
                                                      (tptr (Tstruct _jit_state noattr))
                                                      (Tcons tbool Tnil))
                                                    tvoid cc_default))
                      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                       (Econst_int (Int.repr 1) tint) :: nil))
                    (Ssequence
                      (Ssequence
                        (Scall (Some _t'31)
                          (Evar _encode_thumb (Tfunction
                                                (Tcons tuint
                                                  (Tcons tuint
                                                    (Tcons tuint
                                                      (Tcons tuint Tnil))))
                                                tuint cc_default))
                          ((Etempvar _src tuint) ::
                           (Econst_int (Int.repr 61872) tint) ::
                           (Econst_int (Int.repr 0) tuint) ::
                           (Econst_int (Int.repr 4) tuint) :: nil))
                        (Sset _cmp_lo (Etempvar _t'31 tuint)))
                      (Ssequence
                        (Scall None
                          (Evar _add_ins_jittedthumb (Tfunction
                                                       (Tcons
                                                         (tptr (Tstruct _jit_state noattr))
                                                         (Tcons tuint Tnil))
                                                       tvoid cc_default))
                          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                           (Etempvar _cmp_lo tuint) :: nil))
                        (Ssequence
                          (Scall None
                            (Evar _add_ins_jittedthumb (Tfunction
                                                         (Tcons
                                                           (tptr (Tstruct _jit_state noattr))
                                                           (Tcons tuint Tnil))
                                                         tvoid cc_default))
                            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                             (Econst_int (Int.repr 3872) tint) :: nil))
                          (Ssequence
                            (Ssequence
                              (Scall (Some _t'32)
                                (Evar _is_non_reg (Tfunction
                                                    (Tcons
                                                      (tptr (Tstruct _jit_state noattr))
                                                      (Tcons tuint Tnil))
                                                    tbool cc_default))
                                ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                 (Econst_int (Int.repr 1) tuint) :: nil))
                              (Sset _b_r1
                                (Ecast (Etempvar _t'32 tbool) tbool)))
                            (Ssequence
                              (Sifthenelse (Etempvar _b_r1 tbool)
                                (Ssequence
                                  (Scall (Some _t'33)
                                    (Evar _construct_thumb_b (Tfunction
                                                               (Tcons tushort
                                                                 (Tcons
                                                                   tushort
                                                                   Tnil))
                                                               tushort
                                                               cc_default))
                                    ((Econst_int (Int.repr 11) tint) ::
                                     (Econst_int (Int.repr 6) tint) :: nil))
                                  (Sset _b_lt
                                    (Ecast (Etempvar _t'33 tushort) tushort)))
                                (Ssequence
                                  (Scall (Some _t'34)
                                    (Evar _construct_thumb_b (Tfunction
                                                               (Tcons tushort
                                                                 (Tcons
                                                                   tushort
                                                                   Tnil))
                                                               tushort
                                                               cc_default))
                                    ((Econst_int (Int.repr 11) tint) ::
                                     (Econst_int (Int.repr 10) tint) :: nil))
                                  (Sset _b_lt
                                    (Ecast (Etempvar _t'34 tushort) tushort))))
                              (Ssequence
                                (Scall None
                                  (Evar _add_ins_jittedthumb (Tfunction
                                                               (Tcons
                                                                 (tptr (Tstruct _jit_state noattr))
                                                                 (Tcons tuint
                                                                   Tnil))
                                                               tvoid
                                                               cc_default))
                                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                   (Etempvar _b_lt tushort) :: nil))
                                (Ssequence
                                  (Scall None
                                    (Evar _jit_alu32_store_flag (Tfunction
                                                                  (Tcons
                                                                    (tptr (Tstruct _jit_state noattr))
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil))
                                                                  tvoid
                                                                  cc_default))
                                    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                     (Econst_int (Int.repr 11) tuint) :: nil))
                                  (Ssequence
                                    (Scall None
                                      (Evar _add_ins_jittedthumb (Tfunction
                                                                   (Tcons
                                                                    (tptr (Tstruct _jit_state noattr))
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil))
                                                                   tvoid
                                                                   cc_default))
                                      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                       (Econst_int (Int.repr 56064) tint) ::
                                       nil))
                                    (Ssequence
                                      (Ssequence
                                        (Scall (Some _t'35)
                                          (Evar _encode_thumb (Tfunction
                                                                (Tcons tuint
                                                                  (Tcons
                                                                    tuint
                                                                    (Tcons
                                                                    tuint
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil))))
                                                                tuint
                                                                cc_default))
                                          ((Etempvar _dst tuint) ::
                                           (Econst_int (Int.repr 64032) tint) ::
                                           (Econst_int (Int.repr 0) tuint) ::
                                           (Econst_int (Int.repr 4) tuint) ::
                                           nil))
                                        (Sset _lsr_lo (Etempvar _t'35 tuint)))
                                      (Ssequence
                                        (Ssequence
                                          (Scall (Some _t'36)
                                            (Evar _construct_thumb2_shift_rd_rm 
                                            (Tfunction
                                              (Tcons tushort
                                                (Tcons tushort Tnil)) tushort
                                              cc_default))
                                            ((Etempvar _dst tuint) ::
                                             (Etempvar _src tuint) :: nil))
                                          (Sset _lsr_hi
                                            (Ecast (Etempvar _t'36 tushort)
                                              tushort)))
                                        (Ssequence
                                          (Scall None
                                            (Evar _add_ins_jittedthumb 
                                            (Tfunction
                                              (Tcons
                                                (tptr (Tstruct _jit_state noattr))
                                                (Tcons tuint Tnil)) tvoid
                                              cc_default))
                                            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                             (Etempvar _lsr_lo tuint) :: nil))
                                          (Ssequence
                                            (Scall None
                                              (Evar _add_ins_jittedthumb 
                                              (Tfunction
                                                (Tcons
                                                  (tptr (Tstruct _jit_state noattr))
                                                  (Tcons tuint Tnil)) tvoid
                                                cc_default))
                                              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                               (Etempvar _lsr_hi tushort) ::
                                               nil))
                                            (Ssequence
                                              (Scall None
                                                (Evar _upd_load_store_regs_jittedthumb 
                                                (Tfunction
                                                  (Tcons
                                                    (tptr (Tstruct _jit_state noattr))
                                                    (Tcons tuint
                                                      (Tcons tuint Tnil)))
                                                  tvoid cc_default))
                                                ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                                 (Etempvar _dst tuint) ::
                                                 (Econst_int (Int.repr 3) tuint) ::
                                                 nil))
                                              (Sifthenelse (Ebinop Oeq
                                                             (Etempvar _src tuint)
                                                             (Econst_int (Int.repr 11) tuint)
                                                             tint)
                                                (Sreturn None)
                                                (Ssequence
                                                  (Ssequence
                                                    (Scall (Some _t'37)
                                                      (Evar _reg_of_ireg 
                                                      (Tfunction
                                                        (Tcons tuint Tnil)
                                                        tuint cc_default))
                                                      ((Etempvar _src tuint) ::
                                                       nil))
                                                    (Sset _r
                                                      (Etempvar _t'37 tuint)))
                                                  (Ssequence
                                                    (Scall None
                                                      (Evar _upd_load_store_regs_jittedthumb 
                                                      (Tfunction
                                                        (Tcons
                                                          (tptr (Tstruct _jit_state noattr))
                                                          (Tcons tuint
                                                            (Tcons tuint
                                                              Tnil))) tvoid
                                                        cc_default))
                                                      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                                       (Etempvar _r tuint) ::
                                                       (Econst_int (Int.repr 1) tuint) ::
                                                       nil))
                                                    (Sreturn None))))))))))))))))))
                  (LScons (Some 172)
                    (Ssequence
                      (Ssequence
                        (Scall (Some _t'38)
                          (Evar _encode_thumb (Tfunction
                                                (Tcons tuint
                                                  (Tcons tuint
                                                    (Tcons tuint
                                                      (Tcons tuint Tnil))))
                                                tuint cc_default))
                          ((Etempvar _dst tuint) ::
                           (Econst_int (Int.repr 60032) tint) ::
                           (Econst_int (Int.repr 0) tuint) ::
                           (Econst_int (Int.repr 4) tuint) :: nil))
                        (Sset _ins_lo (Etempvar _t'38 tuint)))
                      (Ssequence
                        (Ssequence
                          (Scall (Some _t'39)
                            (Evar _encode_thumb (Tfunction
                                                  (Tcons tuint
                                                    (Tcons tuint
                                                      (Tcons tuint
                                                        (Tcons tuint Tnil))))
                                                  tuint cc_default))
                            ((Etempvar _dst tuint) ::
                             (Etempvar _src tuint) ::
                             (Econst_int (Int.repr 8) tuint) ::
                             (Econst_int (Int.repr 4) tuint) :: nil))
                          (Sset _ins_hi (Etempvar _t'39 tuint)))
                        (Ssequence
                          (Scall None
                            (Evar _add_ins_jittedthumb (Tfunction
                                                         (Tcons
                                                           (tptr (Tstruct _jit_state noattr))
                                                           (Tcons tuint Tnil))
                                                         tvoid cc_default))
                            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                             (Etempvar _ins_lo tuint) :: nil))
                          (Ssequence
                            (Scall None
                              (Evar _add_ins_jittedthumb (Tfunction
                                                           (Tcons
                                                             (tptr (Tstruct _jit_state noattr))
                                                             (Tcons tuint
                                                               Tnil)) tvoid
                                                           cc_default))
                              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                               (Etempvar _ins_hi tuint) :: nil))
                            (Ssequence
                              (Scall None
                                (Evar _upd_load_store_regs_jittedthumb 
                                (Tfunction
                                  (Tcons (tptr (Tstruct _jit_state noattr))
                                    (Tcons tuint (Tcons tuint Tnil))) tvoid
                                  cc_default))
                                ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                 (Etempvar _dst tuint) ::
                                 (Econst_int (Int.repr 3) tuint) :: nil))
                              (Sifthenelse (Ebinop Oeq (Etempvar _src tuint)
                                             (Econst_int (Int.repr 11) tuint)
                                             tint)
                                (Sreturn None)
                                (Ssequence
                                  (Ssequence
                                    (Scall (Some _t'40)
                                      (Evar _reg_of_ireg (Tfunction
                                                           (Tcons tuint Tnil)
                                                           tuint cc_default))
                                      ((Etempvar _src tuint) :: nil))
                                    (Sset _r (Etempvar _t'40 tuint)))
                                  (Ssequence
                                    (Scall None
                                      (Evar _upd_load_store_regs_jittedthumb 
                                      (Tfunction
                                        (Tcons
                                          (tptr (Tstruct _jit_state noattr))
                                          (Tcons tuint (Tcons tuint Tnil)))
                                        tvoid cc_default))
                                      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                       (Etempvar _r tuint) ::
                                       (Econst_int (Int.repr 1) tuint) ::
                                       nil))
                                    (Sreturn None)))))))))
                    (LScons (Some 188)
                      (Sifthenelse (Ebinop Oeq (Etempvar _dst tuint)
                                     (Etempvar _src tuint) tint)
                        (Sreturn None)
                        (Ssequence
                          (Sifthenelse (Ebinop Olt (Etempvar _dst tuint)
                                         (Econst_int (Int.repr 8) tint) tint)
                            (Sset _d (Econst_int (Int.repr 0) tint))
                            (Sset _d (Econst_int (Int.repr 1) tint)))
                          (Ssequence
                            (Sifthenelse (Ebinop Olt (Etempvar _dst tuint)
                                           (Econst_int (Int.repr 8) tint)
                                           tint)
                              (Sset _rdn (Etempvar _dst tuint))
                              (Sset _rdn
                                (Ebinop Osub (Etempvar _dst tuint)
                                  (Econst_int (Int.repr 8) tint) tuint)))
                            (Ssequence
                              (Ssequence
                                (Scall (Some _t'41)
                                  (Evar _encode_thumb (Tfunction
                                                        (Tcons tuint
                                                          (Tcons tuint
                                                            (Tcons tuint
                                                              (Tcons tuint
                                                                Tnil))))
                                                        tuint cc_default))
                                  ((Etempvar _rdn tuint) ::
                                   (Econst_int (Int.repr 17920) tint) ::
                                   (Econst_int (Int.repr 0) tuint) ::
                                   (Econst_int (Int.repr 3) tuint) :: nil))
                                (Sset _ins_rdn (Etempvar _t'41 tuint)))
                              (Ssequence
                                (Ssequence
                                  (Scall (Some _t'42)
                                    (Evar _encode_thumb (Tfunction
                                                          (Tcons tuint
                                                            (Tcons tuint
                                                              (Tcons tuint
                                                                (Tcons tuint
                                                                  Tnil))))
                                                          tuint cc_default))
                                    ((Etempvar _src tuint) ::
                                     (Etempvar _ins_rdn tuint) ::
                                     (Econst_int (Int.repr 3) tuint) ::
                                     (Econst_int (Int.repr 4) tuint) :: nil))
                                  (Sset _ins_rm (Etempvar _t'42 tuint)))
                                (Ssequence
                                  (Ssequence
                                    (Scall (Some _t'43)
                                      (Evar _encode_thumb (Tfunction
                                                            (Tcons tuint
                                                              (Tcons tuint
                                                                (Tcons tuint
                                                                  (Tcons
                                                                    tuint
                                                                    Tnil))))
                                                            tuint cc_default))
                                      ((Etempvar _d tuint) ::
                                       (Etempvar _ins_rm tuint) ::
                                       (Econst_int (Int.repr 7) tuint) ::
                                       (Econst_int (Int.repr 1) tuint) ::
                                       nil))
                                    (Sset _ins (Etempvar _t'43 tuint)))
                                  (Ssequence
                                    (Scall None
                                      (Evar _add_ins_jittedthumb (Tfunction
                                                                   (Tcons
                                                                    (tptr (Tstruct _jit_state noattr))
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil))
                                                                   tvoid
                                                                   cc_default))
                                      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                       (Etempvar _ins tuint) :: nil))
                                    (Ssequence
                                      (Scall None
                                        (Evar _upd_load_store_regs_jittedthumb 
                                        (Tfunction
                                          (Tcons
                                            (tptr (Tstruct _jit_state noattr))
                                            (Tcons tuint (Tcons tuint Tnil)))
                                          tvoid cc_default))
                                        ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                         (Etempvar _dst tuint) ::
                                         (Econst_int (Int.repr 2) tuint) ::
                                         nil))
                                      (Sifthenelse (Ebinop Oeq
                                                     (Etempvar _src tuint)
                                                     (Econst_int (Int.repr 11) tuint)
                                                     tint)
                                        (Sreturn None)
                                        (Ssequence
                                          (Ssequence
                                            (Scall (Some _t'44)
                                              (Evar _reg_of_ireg (Tfunction
                                                                   (Tcons
                                                                    tuint
                                                                    Tnil)
                                                                   tuint
                                                                   cc_default))
                                              ((Etempvar _src tuint) :: nil))
                                            (Sset _r (Etempvar _t'44 tuint)))
                                          (Ssequence
                                            (Scall None
                                              (Evar _upd_load_store_regs_jittedthumb 
                                              (Tfunction
                                                (Tcons
                                                  (tptr (Tstruct _jit_state noattr))
                                                  (Tcons tuint
                                                    (Tcons tuint Tnil)))
                                                tvoid cc_default))
                                              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                               (Etempvar _r tuint) ::
                                               (Econst_int (Int.repr 1) tuint) ::
                                               nil))
                                            (Sreturn None))))))))))))
                      (LScons (Some 204)
                        (Ssequence
                          (Scall None
                            (Evar _upd_IR11_jittedthumb (Tfunction
                                                          (Tcons
                                                            (tptr (Tstruct _jit_state noattr))
                                                            (Tcons tbool
                                                              Tnil)) tvoid
                                                          cc_default))
                            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                             (Econst_int (Int.repr 1) tint) :: nil))
                          (Ssequence
                            (Ssequence
                              (Scall (Some _t'45)
                                (Evar _encode_thumb (Tfunction
                                                      (Tcons tuint
                                                        (Tcons tuint
                                                          (Tcons tuint
                                                            (Tcons tuint
                                                              Tnil)))) tuint
                                                      cc_default))
                                ((Etempvar _src tuint) ::
                                 (Econst_int (Int.repr 61872) tint) ::
                                 (Econst_int (Int.repr 0) tuint) ::
                                 (Econst_int (Int.repr 4) tuint) :: nil))
                              (Sset _cmp_lo (Etempvar _t'45 tuint)))
                            (Ssequence
                              (Scall None
                                (Evar _add_ins_jittedthumb (Tfunction
                                                             (Tcons
                                                               (tptr (Tstruct _jit_state noattr))
                                                               (Tcons tuint
                                                                 Tnil)) tvoid
                                                             cc_default))
                                ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                 (Etempvar _cmp_lo tuint) :: nil))
                              (Ssequence
                                (Scall None
                                  (Evar _add_ins_jittedthumb (Tfunction
                                                               (Tcons
                                                                 (tptr (Tstruct _jit_state noattr))
                                                                 (Tcons tuint
                                                                   Tnil))
                                                               tvoid
                                                               cc_default))
                                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                   (Econst_int (Int.repr 3872) tint) :: nil))
                                (Ssequence
                                  (Ssequence
                                    (Scall (Some _t'46)
                                      (Evar _is_non_reg (Tfunction
                                                          (Tcons
                                                            (tptr (Tstruct _jit_state noattr))
                                                            (Tcons tuint
                                                              Tnil)) tbool
                                                          cc_default))
                                      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                       (Econst_int (Int.repr 1) tuint) ::
                                       nil))
                                    (Sset _b_r1
                                      (Ecast (Etempvar _t'46 tbool) tbool)))
                                  (Ssequence
                                    (Sifthenelse (Etempvar _b_r1 tbool)
                                      (Ssequence
                                        (Scall (Some _t'47)
                                          (Evar _construct_thumb_b (Tfunction
                                                                    (Tcons
                                                                    tushort
                                                                    (Tcons
                                                                    tushort
                                                                    Tnil))
                                                                    tushort
                                                                    cc_default))
                                          ((Econst_int (Int.repr 11) tint) ::
                                           (Econst_int (Int.repr 6) tint) ::
                                           nil))
                                        (Sset _b_lt
                                          (Ecast (Etempvar _t'47 tushort)
                                            tushort)))
                                      (Ssequence
                                        (Scall (Some _t'48)
                                          (Evar _construct_thumb_b (Tfunction
                                                                    (Tcons
                                                                    tushort
                                                                    (Tcons
                                                                    tushort
                                                                    Tnil))
                                                                    tushort
                                                                    cc_default))
                                          ((Econst_int (Int.repr 11) tint) ::
                                           (Econst_int (Int.repr 10) tint) ::
                                           nil))
                                        (Sset _b_lt
                                          (Ecast (Etempvar _t'48 tushort)
                                            tushort))))
                                    (Ssequence
                                      (Scall None
                                        (Evar _add_ins_jittedthumb (Tfunction
                                                                    (Tcons
                                                                    (tptr (Tstruct _jit_state noattr))
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil))
                                                                    tvoid
                                                                    cc_default))
                                        ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                         (Etempvar _b_lt tushort) :: nil))
                                      (Ssequence
                                        (Scall None
                                          (Evar _jit_alu32_store_flag 
                                          (Tfunction
                                            (Tcons
                                              (tptr (Tstruct _jit_state noattr))
                                              (Tcons tuint Tnil)) tvoid
                                            cc_default))
                                          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                           (Econst_int (Int.repr 11) tuint) ::
                                           nil))
                                        (Ssequence
                                          (Scall None
                                            (Evar _add_ins_jittedthumb 
                                            (Tfunction
                                              (Tcons
                                                (tptr (Tstruct _jit_state noattr))
                                                (Tcons tuint Tnil)) tvoid
                                              cc_default))
                                            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                             (Econst_int (Int.repr 56064) tint) ::
                                             nil))
                                          (Ssequence
                                            (Ssequence
                                              (Scall (Some _t'49)
                                                (Evar _encode_thumb (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    (Tcons
                                                                    tuint
                                                                    (Tcons
                                                                    tuint
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil))))
                                                                    tuint
                                                                    cc_default))
                                                ((Etempvar _dst tuint) ::
                                                 (Econst_int (Int.repr 64064) tint) ::
                                                 (Econst_int (Int.repr 0) tuint) ::
                                                 (Econst_int (Int.repr 4) tuint) ::
                                                 nil))
                                              (Sset _asr_lo
                                                (Etempvar _t'49 tuint)))
                                            (Ssequence
                                              (Ssequence
                                                (Scall (Some _t'50)
                                                  (Evar _construct_thumb2_shift_rd_rm 
                                                  (Tfunction
                                                    (Tcons tushort
                                                      (Tcons tushort Tnil))
                                                    tushort cc_default))
                                                  ((Etempvar _dst tuint) ::
                                                   (Etempvar _src tuint) ::
                                                   nil))
                                                (Sset _asr_hi
                                                  (Ecast
                                                    (Etempvar _t'50 tushort)
                                                    tushort)))
                                              (Ssequence
                                                (Scall None
                                                  (Evar _add_ins_jittedthumb 
                                                  (Tfunction
                                                    (Tcons
                                                      (tptr (Tstruct _jit_state noattr))
                                                      (Tcons tuint Tnil))
                                                    tvoid cc_default))
                                                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                                   (Etempvar _asr_lo tuint) ::
                                                   nil))
                                                (Ssequence
                                                  (Scall None
                                                    (Evar _add_ins_jittedthumb 
                                                    (Tfunction
                                                      (Tcons
                                                        (tptr (Tstruct _jit_state noattr))
                                                        (Tcons tuint Tnil))
                                                      tvoid cc_default))
                                                    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                                     (Etempvar _asr_hi tushort) ::
                                                     nil))
                                                  (Ssequence
                                                    (Scall None
                                                      (Evar _upd_load_store_regs_jittedthumb 
                                                      (Tfunction
                                                        (Tcons
                                                          (tptr (Tstruct _jit_state noattr))
                                                          (Tcons tuint
                                                            (Tcons tuint
                                                              Tnil))) tvoid
                                                        cc_default))
                                                      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                                       (Etempvar _dst tuint) ::
                                                       (Econst_int (Int.repr 3) tuint) ::
                                                       nil))
                                                    (Sifthenelse (Ebinop Oeq
                                                                   (Etempvar _src tuint)
                                                                   (Econst_int (Int.repr 11) tuint)
                                                                   tint)
                                                      (Sreturn None)
                                                      (Ssequence
                                                        (Ssequence
                                                          (Scall (Some _t'51)
                                                            (Evar _reg_of_ireg 
                                                            (Tfunction
                                                              (Tcons tuint
                                                                Tnil) tuint
                                                              cc_default))
                                                            ((Etempvar _src tuint) ::
                                                             nil))
                                                          (Sset _r
                                                            (Etempvar _t'51 tuint)))
                                                        (Ssequence
                                                          (Scall None
                                                            (Evar _upd_load_store_regs_jittedthumb 
                                                            (Tfunction
                                                              (Tcons
                                                                (tptr (Tstruct _jit_state noattr))
                                                                (Tcons tuint
                                                                  (Tcons
                                                                    tuint
                                                                    Tnil)))
                                                              tvoid
                                                              cc_default))
                                                            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                                             (Etempvar _r tuint) ::
                                                             (Econst_int (Int.repr 1) tuint) ::
                                                             nil))
                                                          (Sreturn None))))))))))))))))))
                        (LScons None
                          (Ssequence
                            (Scall None
                              (Evar _upd_flag (Tfunction
                                                (Tcons
                                                  (tptr (Tstruct _jit_state noattr))
                                                  (Tcons tuint Tnil)) tvoid
                                                cc_default))
                              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                               (Econst_int (Int.repr 12) tuint) :: nil))
                            (Sreturn None))
                          LSnil)))))))))))))
|}.

Definition f_bpf_alu32_to_thumb_imm := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: (_op, tuchar) ::
                (_dst, tuint) :: (_imm8, tuint) :: nil);
  fn_vars := nil;
  fn_temps := ((_ins_lo, tuint) :: (_ins_hi, tuint) :: (_t'13, tuint) ::
               (_t'12, tuint) :: (_t'11, tuint) :: (_t'10, tuint) ::
               (_t'9, tuint) :: (_t'8, tuint) :: (_t'7, tuint) ::
               (_t'6, tuint) :: (_t'5, tuint) :: (_t'4, tuint) ::
               (_t'3, tuint) :: (_t'2, tuint) :: (_t'1, tuint) :: nil);
  fn_body :=
(Sswitch (Etempvar _op tuchar)
  (LScons (Some 4)
    (Ssequence
      (Ssequence
        (Scall (Some _t'1)
          (Evar _encode_thumb (Tfunction
                                (Tcons tuint
                                  (Tcons tuint
                                    (Tcons tuint (Tcons tuint Tnil)))) tuint
                                cc_default))
          ((Etempvar _dst tuint) :: (Econst_int (Int.repr 61696) tint) ::
           (Econst_int (Int.repr 0) tuint) ::
           (Econst_int (Int.repr 4) tuint) :: nil))
        (Sset _ins_lo (Etempvar _t'1 tuint)))
      (Ssequence
        (Ssequence
          (Scall (Some _t'2)
            (Evar _encode_thumb (Tfunction
                                  (Tcons tuint
                                    (Tcons tuint
                                      (Tcons tuint (Tcons tuint Tnil))))
                                  tuint cc_default))
            ((Etempvar _dst tuint) :: (Etempvar _imm8 tuint) ::
             (Econst_int (Int.repr 8) tuint) ::
             (Econst_int (Int.repr 4) tuint) :: nil))
          (Sset _ins_hi (Etempvar _t'2 tuint)))
        (Ssequence
          (Scall None
            (Evar _add_ins_jittedthumb (Tfunction
                                         (Tcons
                                           (tptr (Tstruct _jit_state noattr))
                                           (Tcons tuint Tnil)) tvoid
                                         cc_default))
            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
             (Etempvar _ins_lo tuint) :: nil))
          (Ssequence
            (Scall None
              (Evar _add_ins_jittedthumb (Tfunction
                                           (Tcons
                                             (tptr (Tstruct _jit_state noattr))
                                             (Tcons tuint Tnil)) tvoid
                                           cc_default))
              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
               (Etempvar _ins_hi tuint) :: nil))
            (Ssequence
              (Scall None
                (Evar _upd_load_store_regs_jittedthumb (Tfunction
                                                         (Tcons
                                                           (tptr (Tstruct _jit_state noattr))
                                                           (Tcons tuint
                                                             (Tcons tuint
                                                               Tnil))) tvoid
                                                         cc_default))
                ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                 (Etempvar _dst tuint) :: (Econst_int (Int.repr 3) tuint) ::
                 nil))
              (Sreturn None))))))
    (LScons (Some 20)
      (Ssequence
        (Ssequence
          (Scall (Some _t'3)
            (Evar _encode_thumb (Tfunction
                                  (Tcons tuint
                                    (Tcons tuint
                                      (Tcons tuint (Tcons tuint Tnil))))
                                  tuint cc_default))
            ((Etempvar _dst tuint) :: (Econst_int (Int.repr 61856) tint) ::
             (Econst_int (Int.repr 0) tuint) ::
             (Econst_int (Int.repr 4) tuint) :: nil))
          (Sset _ins_lo (Etempvar _t'3 tuint)))
        (Ssequence
          (Ssequence
            (Scall (Some _t'4)
              (Evar _encode_thumb (Tfunction
                                    (Tcons tuint
                                      (Tcons tuint
                                        (Tcons tuint (Tcons tuint Tnil))))
                                    tuint cc_default))
              ((Etempvar _dst tuint) :: (Etempvar _imm8 tuint) ::
               (Econst_int (Int.repr 8) tuint) ::
               (Econst_int (Int.repr 4) tuint) :: nil))
            (Sset _ins_hi (Etempvar _t'4 tuint)))
          (Ssequence
            (Scall None
              (Evar _add_ins_jittedthumb (Tfunction
                                           (Tcons
                                             (tptr (Tstruct _jit_state noattr))
                                             (Tcons tuint Tnil)) tvoid
                                           cc_default))
              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
               (Etempvar _ins_lo tuint) :: nil))
            (Ssequence
              (Scall None
                (Evar _add_ins_jittedthumb (Tfunction
                                             (Tcons
                                               (tptr (Tstruct _jit_state noattr))
                                               (Tcons tuint Tnil)) tvoid
                                             cc_default))
                ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                 (Etempvar _ins_hi tuint) :: nil))
              (Ssequence
                (Scall None
                  (Evar _upd_load_store_regs_jittedthumb (Tfunction
                                                           (Tcons
                                                             (tptr (Tstruct _jit_state noattr))
                                                             (Tcons tuint
                                                               (Tcons tuint
                                                                 Tnil)))
                                                           tvoid cc_default))
                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                   (Etempvar _dst tuint) ::
                   (Econst_int (Int.repr 3) tuint) :: nil))
                (Sreturn None))))))
      (LScons (Some 36)
        (Ssequence
          (Scall None
            (Evar _upd_flag (Tfunction
                              (Tcons (tptr (Tstruct _jit_state noattr))
                                (Tcons tuint Tnil)) tvoid cc_default))
            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
             (Econst_int (Int.repr 12) tuint) :: nil))
          (Sreturn None))
        (LScons (Some 68)
          (Ssequence
            (Ssequence
              (Scall (Some _t'5)
                (Evar _encode_thumb (Tfunction
                                      (Tcons tuint
                                        (Tcons tuint
                                          (Tcons tuint (Tcons tuint Tnil))))
                                      tuint cc_default))
                ((Etempvar _dst tuint) ::
                 (Econst_int (Int.repr 61504) tint) ::
                 (Econst_int (Int.repr 0) tuint) ::
                 (Econst_int (Int.repr 4) tuint) :: nil))
              (Sset _ins_lo (Etempvar _t'5 tuint)))
            (Ssequence
              (Ssequence
                (Scall (Some _t'6)
                  (Evar _encode_thumb (Tfunction
                                        (Tcons tuint
                                          (Tcons tuint
                                            (Tcons tuint (Tcons tuint Tnil))))
                                        tuint cc_default))
                  ((Etempvar _dst tuint) :: (Etempvar _imm8 tuint) ::
                   (Econst_int (Int.repr 8) tuint) ::
                   (Econst_int (Int.repr 4) tuint) :: nil))
                (Sset _ins_hi (Etempvar _t'6 tuint)))
              (Ssequence
                (Scall None
                  (Evar _add_ins_jittedthumb (Tfunction
                                               (Tcons
                                                 (tptr (Tstruct _jit_state noattr))
                                                 (Tcons tuint Tnil)) tvoid
                                               cc_default))
                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                   (Etempvar _ins_lo tuint) :: nil))
                (Ssequence
                  (Scall None
                    (Evar _add_ins_jittedthumb (Tfunction
                                                 (Tcons
                                                   (tptr (Tstruct _jit_state noattr))
                                                   (Tcons tuint Tnil)) tvoid
                                                 cc_default))
                    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                     (Etempvar _ins_hi tuint) :: nil))
                  (Ssequence
                    (Scall None
                      (Evar _upd_load_store_regs_jittedthumb (Tfunction
                                                               (Tcons
                                                                 (tptr (Tstruct _jit_state noattr))
                                                                 (Tcons tuint
                                                                   (Tcons
                                                                    tuint
                                                                    Tnil)))
                                                               tvoid
                                                               cc_default))
                      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                       (Etempvar _dst tuint) ::
                       (Econst_int (Int.repr 3) tuint) :: nil))
                    (Sreturn None))))))
          (LScons (Some 84)
            (Ssequence
              (Ssequence
                (Scall (Some _t'7)
                  (Evar _encode_thumb (Tfunction
                                        (Tcons tuint
                                          (Tcons tuint
                                            (Tcons tuint (Tcons tuint Tnil))))
                                        tuint cc_default))
                  ((Etempvar _dst tuint) ::
                   (Econst_int (Int.repr 61440) tint) ::
                   (Econst_int (Int.repr 0) tuint) ::
                   (Econst_int (Int.repr 4) tuint) :: nil))
                (Sset _ins_lo (Etempvar _t'7 tuint)))
              (Ssequence
                (Ssequence
                  (Scall (Some _t'8)
                    (Evar _encode_thumb (Tfunction
                                          (Tcons tuint
                                            (Tcons tuint
                                              (Tcons tuint
                                                (Tcons tuint Tnil)))) tuint
                                          cc_default))
                    ((Etempvar _dst tuint) :: (Etempvar _imm8 tuint) ::
                     (Econst_int (Int.repr 8) tuint) ::
                     (Econst_int (Int.repr 4) tuint) :: nil))
                  (Sset _ins_hi (Etempvar _t'8 tuint)))
                (Ssequence
                  (Scall None
                    (Evar _add_ins_jittedthumb (Tfunction
                                                 (Tcons
                                                   (tptr (Tstruct _jit_state noattr))
                                                   (Tcons tuint Tnil)) tvoid
                                                 cc_default))
                    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                     (Etempvar _ins_lo tuint) :: nil))
                  (Ssequence
                    (Scall None
                      (Evar _add_ins_jittedthumb (Tfunction
                                                   (Tcons
                                                     (tptr (Tstruct _jit_state noattr))
                                                     (Tcons tuint Tnil))
                                                   tvoid cc_default))
                      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                       (Etempvar _ins_hi tuint) :: nil))
                    (Ssequence
                      (Scall None
                        (Evar _upd_load_store_regs_jittedthumb (Tfunction
                                                                 (Tcons
                                                                   (tptr (Tstruct _jit_state noattr))
                                                                   (Tcons
                                                                    tuint
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)))
                                                                 tvoid
                                                                 cc_default))
                        ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                         (Etempvar _dst tuint) ::
                         (Econst_int (Int.repr 3) tuint) :: nil))
                      (Sreturn None))))))
            (LScons (Some 132)
              (Ssequence
                (Ssequence
                  (Scall (Some _t'9)
                    (Evar _encode_thumb (Tfunction
                                          (Tcons tuint
                                            (Tcons tuint
                                              (Tcons tuint
                                                (Tcons tuint Tnil)))) tuint
                                          cc_default))
                    ((Etempvar _dst tuint) ::
                     (Econst_int (Int.repr 61888) tint) ::
                     (Econst_int (Int.repr 0) tuint) ::
                     (Econst_int (Int.repr 4) tuint) :: nil))
                  (Sset _ins_lo (Etempvar _t'9 tuint)))
                (Ssequence
                  (Ssequence
                    (Scall (Some _t'10)
                      (Evar _encode_thumb (Tfunction
                                            (Tcons tuint
                                              (Tcons tuint
                                                (Tcons tuint
                                                  (Tcons tuint Tnil)))) tuint
                                            cc_default))
                      ((Etempvar _dst tuint) ::
                       (Econst_int (Int.repr 0) tuint) ::
                       (Econst_int (Int.repr 8) tuint) ::
                       (Econst_int (Int.repr 4) tuint) :: nil))
                    (Sset _ins_hi (Etempvar _t'10 tuint)))
                  (Ssequence
                    (Scall None
                      (Evar _add_ins_jittedthumb (Tfunction
                                                   (Tcons
                                                     (tptr (Tstruct _jit_state noattr))
                                                     (Tcons tuint Tnil))
                                                   tvoid cc_default))
                      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                       (Etempvar _ins_lo tuint) :: nil))
                    (Ssequence
                      (Scall None
                        (Evar _add_ins_jittedthumb (Tfunction
                                                     (Tcons
                                                       (tptr (Tstruct _jit_state noattr))
                                                       (Tcons tuint Tnil))
                                                     tvoid cc_default))
                        ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                         (Etempvar _ins_hi tuint) :: nil))
                      (Ssequence
                        (Scall None
                          (Evar _upd_load_store_regs_jittedthumb (Tfunction
                                                                   (Tcons
                                                                    (tptr (Tstruct _jit_state noattr))
                                                                    (Tcons
                                                                    tuint
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)))
                                                                   tvoid
                                                                   cc_default))
                          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                           (Etempvar _dst tuint) ::
                           (Econst_int (Int.repr 3) tuint) :: nil))
                        (Sreturn None))))))
              (LScons (Some 164)
                (Ssequence
                  (Ssequence
                    (Scall (Some _t'11)
                      (Evar _encode_thumb (Tfunction
                                            (Tcons tuint
                                              (Tcons tuint
                                                (Tcons tuint
                                                  (Tcons tuint Tnil)))) tuint
                                            cc_default))
                      ((Etempvar _dst tuint) ::
                       (Econst_int (Int.repr 61568) tint) ::
                       (Econst_int (Int.repr 0) tuint) ::
                       (Econst_int (Int.repr 4) tuint) :: nil))
                    (Sset _ins_lo (Etempvar _t'11 tuint)))
                  (Ssequence
                    (Ssequence
                      (Scall (Some _t'12)
                        (Evar _encode_thumb (Tfunction
                                              (Tcons tuint
                                                (Tcons tuint
                                                  (Tcons tuint
                                                    (Tcons tuint Tnil))))
                                              tuint cc_default))
                        ((Etempvar _dst tuint) :: (Etempvar _imm8 tuint) ::
                         (Econst_int (Int.repr 8) tuint) ::
                         (Econst_int (Int.repr 4) tuint) :: nil))
                      (Sset _ins_hi (Etempvar _t'12 tuint)))
                    (Ssequence
                      (Scall None
                        (Evar _add_ins_jittedthumb (Tfunction
                                                     (Tcons
                                                       (tptr (Tstruct _jit_state noattr))
                                                       (Tcons tuint Tnil))
                                                     tvoid cc_default))
                        ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                         (Etempvar _ins_lo tuint) :: nil))
                      (Ssequence
                        (Scall None
                          (Evar _add_ins_jittedthumb (Tfunction
                                                       (Tcons
                                                         (tptr (Tstruct _jit_state noattr))
                                                         (Tcons tuint Tnil))
                                                       tvoid cc_default))
                          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                           (Etempvar _ins_hi tuint) :: nil))
                        (Ssequence
                          (Scall None
                            (Evar _upd_load_store_regs_jittedthumb (Tfunction
                                                                    (Tcons
                                                                    (tptr (Tstruct _jit_state noattr))
                                                                    (Tcons
                                                                    tuint
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)))
                                                                    tvoid
                                                                    cc_default))
                            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                             (Etempvar _dst tuint) ::
                             (Econst_int (Int.repr 3) tuint) :: nil))
                          (Sreturn None))))))
                (LScons (Some 180)
                  (Ssequence
                    (Ssequence
                      (Scall (Some _t'13)
                        (Evar _encode_thumb (Tfunction
                                              (Tcons tuint
                                                (Tcons tuint
                                                  (Tcons tuint
                                                    (Tcons tuint Tnil))))
                                              tuint cc_default))
                        ((Etempvar _dst tuint) :: (Etempvar _imm8 tuint) ::
                         (Econst_int (Int.repr 8) tuint) ::
                         (Econst_int (Int.repr 4) tuint) :: nil))
                      (Sset _ins_hi (Etempvar _t'13 tuint)))
                    (Ssequence
                      (Scall None
                        (Evar _add_ins_jittedthumb (Tfunction
                                                     (Tcons
                                                       (tptr (Tstruct _jit_state noattr))
                                                       (Tcons tuint Tnil))
                                                     tvoid cc_default))
                        ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                         (Econst_int (Int.repr 62016) tint) :: nil))
                      (Ssequence
                        (Scall None
                          (Evar _add_ins_jittedthumb (Tfunction
                                                       (Tcons
                                                         (tptr (Tstruct _jit_state noattr))
                                                         (Tcons tuint Tnil))
                                                       tvoid cc_default))
                          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                           (Etempvar _ins_hi tuint) :: nil))
                        (Ssequence
                          (Scall None
                            (Evar _upd_load_store_regs_jittedthumb (Tfunction
                                                                    (Tcons
                                                                    (tptr (Tstruct _jit_state noattr))
                                                                    (Tcons
                                                                    tuint
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil)))
                                                                    tvoid
                                                                    cc_default))
                            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                             (Etempvar _dst tuint) ::
                             (Econst_int (Int.repr 2) tuint) :: nil))
                          (Sreturn None)))))
                  (LScons None
                    (Ssequence
                      (Scall None
                        (Evar _upd_flag (Tfunction
                                          (Tcons
                                            (tptr (Tstruct _jit_state noattr))
                                            (Tcons tuint Tnil)) tvoid
                                          cc_default))
                        ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                         (Econst_int (Int.repr 12) tuint) :: nil))
                      (Sreturn None))
                    LSnil))))))))))
|}.

Definition f_mov_int_to_reg_binary := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: (_i, tuint) ::
                (_r, tuint) :: nil);
  fn_vars := nil;
  fn_temps := ((_lo_imm8, tuint) :: (_lo_imm3, tuint) :: (_lo_i, tuint) ::
               (_lo_imm4, tuint) :: (_movw_lo_0, tuint) ::
               (_movw_lo, tuint) :: (_movw_hi_0, tuint) ::
               (_movw_hi, tuint) :: (_hi_32, tuint) :: (_hi_imm8, tuint) ::
               (_hi_imm3, tuint) :: (_hi_i, tuint) :: (_hi_imm4, tuint) ::
               (_movt_lo_0, tuint) :: (_movt_lo, tuint) ::
               (_movt_hi_0, tuint) :: (_movt_hi, tuint) :: (_t'17, tuint) ::
               (_t'16, tuint) :: (_t'15, tuint) :: (_t'14, tuint) ::
               (_t'13, tuint) :: (_t'12, tuint) :: (_t'11, tuint) ::
               (_t'10, tuint) :: (_t'9, tuint) :: (_t'8, tuint) ::
               (_t'7, tuint) :: (_t'6, tuint) :: (_t'5, tuint) ::
               (_t'4, tuint) :: (_t'3, tuint) :: (_t'2, tuint) ::
               (_t'1, tuint) :: nil);
  fn_body :=
(Ssequence
  (Ssequence
    (Scall (Some _t'1)
      (Evar _decode_thumb (Tfunction
                            (Tcons tuint (Tcons tuint (Tcons tuint Tnil)))
                            tuint cc_default))
      ((Etempvar _i tuint) :: (Econst_int (Int.repr 0) tuint) ::
       (Econst_int (Int.repr 8) tuint) :: nil))
    (Sset _lo_imm8 (Etempvar _t'1 tuint)))
  (Ssequence
    (Ssequence
      (Scall (Some _t'2)
        (Evar _decode_thumb (Tfunction
                              (Tcons tuint (Tcons tuint (Tcons tuint Tnil)))
                              tuint cc_default))
        ((Etempvar _i tuint) :: (Econst_int (Int.repr 8) tuint) ::
         (Econst_int (Int.repr 3) tuint) :: nil))
      (Sset _lo_imm3 (Etempvar _t'2 tuint)))
    (Ssequence
      (Ssequence
        (Scall (Some _t'3)
          (Evar _decode_thumb (Tfunction
                                (Tcons tuint
                                  (Tcons tuint (Tcons tuint Tnil))) tuint
                                cc_default))
          ((Etempvar _i tuint) :: (Econst_int (Int.repr 11) tuint) ::
           (Econst_int (Int.repr 1) tuint) :: nil))
        (Sset _lo_i (Etempvar _t'3 tuint)))
      (Ssequence
        (Ssequence
          (Scall (Some _t'4)
            (Evar _decode_thumb (Tfunction
                                  (Tcons tuint
                                    (Tcons tuint (Tcons tuint Tnil))) tuint
                                  cc_default))
            ((Etempvar _i tuint) :: (Econst_int (Int.repr 12) tuint) ::
             (Econst_int (Int.repr 4) tuint) :: nil))
          (Sset _lo_imm4 (Etempvar _t'4 tuint)))
        (Ssequence
          (Ssequence
            (Scall (Some _t'5)
              (Evar _encode_thumb (Tfunction
                                    (Tcons tuint
                                      (Tcons tuint
                                        (Tcons tuint (Tcons tuint Tnil))))
                                    tuint cc_default))
              ((Etempvar _lo_imm4 tuint) ::
               (Econst_int (Int.repr 62016) tint) ::
               (Econst_int (Int.repr 0) tuint) ::
               (Econst_int (Int.repr 4) tuint) :: nil))
            (Sset _movw_lo_0 (Etempvar _t'5 tuint)))
          (Ssequence
            (Ssequence
              (Scall (Some _t'6)
                (Evar _encode_thumb (Tfunction
                                      (Tcons tuint
                                        (Tcons tuint
                                          (Tcons tuint (Tcons tuint Tnil))))
                                      tuint cc_default))
                ((Etempvar _lo_i tuint) :: (Etempvar _movw_lo_0 tuint) ::
                 (Econst_int (Int.repr 10) tuint) ::
                 (Econst_int (Int.repr 1) tuint) :: nil))
              (Sset _movw_lo (Etempvar _t'6 tuint)))
            (Ssequence
              (Ssequence
                (Scall (Some _t'7)
                  (Evar _encode_thumb (Tfunction
                                        (Tcons tuint
                                          (Tcons tuint
                                            (Tcons tuint (Tcons tuint Tnil))))
                                        tuint cc_default))
                  ((Etempvar _r tuint) :: (Etempvar _lo_imm8 tuint) ::
                   (Econst_int (Int.repr 8) tuint) ::
                   (Econst_int (Int.repr 4) tuint) :: nil))
                (Sset _movw_hi_0 (Etempvar _t'7 tuint)))
              (Ssequence
                (Ssequence
                  (Scall (Some _t'8)
                    (Evar _encode_thumb (Tfunction
                                          (Tcons tuint
                                            (Tcons tuint
                                              (Tcons tuint
                                                (Tcons tuint Tnil)))) tuint
                                          cc_default))
                    ((Etempvar _lo_imm3 tuint) ::
                     (Etempvar _movw_hi_0 tuint) ::
                     (Econst_int (Int.repr 12) tuint) ::
                     (Econst_int (Int.repr 3) tuint) :: nil))
                  (Sset _movw_hi (Etempvar _t'8 tuint)))
                (Ssequence
                  (Scall None
                    (Evar _add_ins_jittedthumb (Tfunction
                                                 (Tcons
                                                   (tptr (Tstruct _jit_state noattr))
                                                   (Tcons tuint Tnil)) tvoid
                                                 cc_default))
                    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                     (Etempvar _movw_lo tuint) :: nil))
                  (Ssequence
                    (Scall None
                      (Evar _add_ins_jittedthumb (Tfunction
                                                   (Tcons
                                                     (tptr (Tstruct _jit_state noattr))
                                                     (Tcons tuint Tnil))
                                                   tvoid cc_default))
                      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                       (Etempvar _movw_hi tuint) :: nil))
                    (Ssequence
                      (Ssequence
                        (Scall (Some _t'9)
                          (Evar _decode_thumb (Tfunction
                                                (Tcons tuint
                                                  (Tcons tuint
                                                    (Tcons tuint Tnil)))
                                                tuint cc_default))
                          ((Etempvar _i tuint) ::
                           (Econst_int (Int.repr 16) tuint) ::
                           (Econst_int (Int.repr 16) tuint) :: nil))
                        (Sset _hi_32 (Etempvar _t'9 tuint)))
                      (Sifthenelse (Ebinop Oeq (Etempvar _hi_32 tuint)
                                     (Econst_int (Int.repr 0) tuint) tint)
                        (Sreturn None)
                        (Ssequence
                          (Ssequence
                            (Scall (Some _t'10)
                              (Evar _decode_thumb (Tfunction
                                                    (Tcons tuint
                                                      (Tcons tuint
                                                        (Tcons tuint Tnil)))
                                                    tuint cc_default))
                              ((Etempvar _i tuint) ::
                               (Econst_int (Int.repr 16) tuint) ::
                               (Econst_int (Int.repr 8) tuint) :: nil))
                            (Sset _hi_imm8 (Etempvar _t'10 tuint)))
                          (Ssequence
                            (Ssequence
                              (Scall (Some _t'11)
                                (Evar _decode_thumb (Tfunction
                                                      (Tcons tuint
                                                        (Tcons tuint
                                                          (Tcons tuint Tnil)))
                                                      tuint cc_default))
                                ((Etempvar _i tuint) ::
                                 (Econst_int (Int.repr 24) tuint) ::
                                 (Econst_int (Int.repr 3) tuint) :: nil))
                              (Sset _hi_imm3 (Etempvar _t'11 tuint)))
                            (Ssequence
                              (Ssequence
                                (Scall (Some _t'12)
                                  (Evar _decode_thumb (Tfunction
                                                        (Tcons tuint
                                                          (Tcons tuint
                                                            (Tcons tuint
                                                              Tnil))) tuint
                                                        cc_default))
                                  ((Etempvar _i tuint) ::
                                   (Econst_int (Int.repr 27) tuint) ::
                                   (Econst_int (Int.repr 1) tuint) :: nil))
                                (Sset _hi_i (Etempvar _t'12 tuint)))
                              (Ssequence
                                (Ssequence
                                  (Scall (Some _t'13)
                                    (Evar _decode_thumb (Tfunction
                                                          (Tcons tuint
                                                            (Tcons tuint
                                                              (Tcons tuint
                                                                Tnil))) tuint
                                                          cc_default))
                                    ((Etempvar _i tuint) ::
                                     (Econst_int (Int.repr 28) tuint) ::
                                     (Econst_int (Int.repr 4) tuint) :: nil))
                                  (Sset _hi_imm4 (Etempvar _t'13 tuint)))
                                (Ssequence
                                  (Ssequence
                                    (Scall (Some _t'14)
                                      (Evar _encode_thumb (Tfunction
                                                            (Tcons tuint
                                                              (Tcons tuint
                                                                (Tcons tuint
                                                                  (Tcons
                                                                    tuint
                                                                    Tnil))))
                                                            tuint cc_default))
                                      ((Etempvar _hi_imm4 tuint) ::
                                       (Econst_int (Int.repr 62144) tint) ::
                                       (Econst_int (Int.repr 0) tuint) ::
                                       (Econst_int (Int.repr 4) tuint) ::
                                       nil))
                                    (Sset _movt_lo_0 (Etempvar _t'14 tuint)))
                                  (Ssequence
                                    (Ssequence
                                      (Scall (Some _t'15)
                                        (Evar _encode_thumb (Tfunction
                                                              (Tcons tuint
                                                                (Tcons tuint
                                                                  (Tcons
                                                                    tuint
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil))))
                                                              tuint
                                                              cc_default))
                                        ((Etempvar _hi_i tuint) ::
                                         (Etempvar _movt_lo_0 tuint) ::
                                         (Econst_int (Int.repr 10) tuint) ::
                                         (Econst_int (Int.repr 1) tuint) ::
                                         nil))
                                      (Sset _movt_lo (Etempvar _t'15 tuint)))
                                    (Ssequence
                                      (Scall None
                                        (Evar _add_ins_jittedthumb (Tfunction
                                                                    (Tcons
                                                                    (tptr (Tstruct _jit_state noattr))
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil))
                                                                    tvoid
                                                                    cc_default))
                                        ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                         (Etempvar _movt_lo tuint) :: nil))
                                      (Ssequence
                                        (Ssequence
                                          (Scall (Some _t'16)
                                            (Evar _encode_thumb (Tfunction
                                                                  (Tcons
                                                                    tuint
                                                                    (Tcons
                                                                    tuint
                                                                    (Tcons
                                                                    tuint
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil))))
                                                                  tuint
                                                                  cc_default))
                                            ((Etempvar _r tuint) ::
                                             (Etempvar _hi_imm8 tuint) ::
                                             (Econst_int (Int.repr 8) tuint) ::
                                             (Econst_int (Int.repr 4) tuint) ::
                                             nil))
                                          (Sset _movt_hi_0
                                            (Etempvar _t'16 tuint)))
                                        (Ssequence
                                          (Ssequence
                                            (Scall (Some _t'17)
                                              (Evar _encode_thumb (Tfunction
                                                                    (Tcons
                                                                    tuint
                                                                    (Tcons
                                                                    tuint
                                                                    (Tcons
                                                                    tuint
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil))))
                                                                    tuint
                                                                    cc_default))
                                              ((Etempvar _hi_imm3 tuint) ::
                                               (Etempvar _movt_hi_0 tuint) ::
                                               (Econst_int (Int.repr 12) tuint) ::
                                               (Econst_int (Int.repr 3) tuint) ::
                                               nil))
                                            (Sset _movt_hi
                                              (Etempvar _t'17 tuint)))
                                          (Ssequence
                                            (Scall None
                                              (Evar _add_ins_jittedthumb 
                                              (Tfunction
                                                (Tcons
                                                  (tptr (Tstruct _jit_state noattr))
                                                  (Tcons tuint Tnil)) tvoid
                                                cc_default))
                                              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                               (Etempvar _movt_hi tuint) ::
                                               nil))
                                            (Sreturn None)))))))))))))))))))))))
|}.

Definition f_get_immediate := {|
  fn_return := tint;
  fn_callconv := cc_default;
  fn_params := ((_ins, tulong) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sreturn (Some (Ecast
                 (Ebinop Oshr (Etempvar _ins tulong)
                   (Econst_long (Int64.repr 32) tulong) tulong) tint)))
|}.

Definition f_get_opcode_ins := {|
  fn_return := tuchar;
  fn_callconv := cc_default;
  fn_params := ((_ins, tulong) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sreturn (Some (Ecast
                 (Ebinop Oand (Etempvar _ins tulong)
                   (Econst_long (Int64.repr 255) tulong) tulong) tuchar)))
|}.

Definition f_nat_to_opcode_alu32 := {|
  fn_return := tuchar;
  fn_callconv := cc_default;
  fn_params := ((_op, tuchar) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sifthenelse (Ebinop Oeq
               (Ebinop Oand (Etempvar _op tuchar)
                 (Econst_int (Int.repr 7) tuint) tuint)
               (Econst_int (Int.repr 4) tuint) tint)
  (Sifthenelse (Ebinop Oeq (Econst_int (Int.repr 0) tuint)
                 (Ebinop Oand (Etempvar _op tuchar)
                   (Econst_int (Int.repr 8) tuint) tuint) tint)
    (Sreturn (Some (Econst_int (Int.repr 4) tuint)))
    (Sreturn (Some (Econst_int (Int.repr 12) tuint))))
  (Sreturn (Some (Econst_int (Int.repr 0) tuint))))
|}.

Definition f_nat_to_opcode_alu32_reg := {|
  fn_return := tuchar;
  fn_callconv := cc_default;
  fn_params := ((_op, tuchar) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sreturn (Some (Etempvar _op tuchar)))
|}.

Definition f_nat_to_opcode_alu32_imm := {|
  fn_return := tuchar;
  fn_callconv := cc_default;
  fn_params := ((_op, tuchar) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sreturn (Some (Etempvar _op tuchar)))
|}.

Definition f_bpf_alu32_to_thumb := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) ::
                (_ins, tulong) :: nil);
  fn_vars := nil;
  fn_temps := ((_op, tuchar) :: (_opc, tuchar) :: (_dst, tuint) ::
               (_imm32, tint) :: (_opr, tuchar) :: (_src, tuint) ::
               (_opi, tuchar) :: (_opk, tuchar) :: (_t'10, tint) ::
               (_t'9, tint) :: (_t'8, tuchar) :: (_t'7, tuchar) ::
               (_t'6, tuint) :: (_t'5, tuchar) :: (_t'4, tint) ::
               (_t'3, tuint) :: (_t'2, tuchar) :: (_t'1, tuchar) :: nil);
  fn_body :=
(Ssequence
  (Ssequence
    (Scall (Some _t'1)
      (Evar _get_opcode_ins (Tfunction (Tcons tulong Tnil) tuchar cc_default))
      ((Etempvar _ins tulong) :: nil))
    (Sset _op (Ecast (Etempvar _t'1 tuchar) tuchar)))
  (Ssequence
    (Ssequence
      (Scall (Some _t'2)
        (Evar _nat_to_opcode_alu32 (Tfunction (Tcons tuchar Tnil) tuchar
                                     cc_default))
        ((Etempvar _op tuchar) :: nil))
      (Sset _opc (Ecast (Etempvar _t'2 tuchar) tuchar)))
    (Ssequence
      (Ssequence
        (Scall (Some _t'3)
          (Evar _get_dst (Tfunction (Tcons tulong Tnil) tuint cc_default))
          ((Etempvar _ins tulong) :: nil))
        (Sset _dst (Etempvar _t'3 tuint)))
      (Ssequence
        (Ssequence
          (Scall (Some _t'4)
            (Evar _get_immediate (Tfunction (Tcons tulong Tnil) tint
                                   cc_default))
            ((Etempvar _ins tulong) :: nil))
          (Sset _imm32 (Etempvar _t'4 tint)))
        (Sswitch (Etempvar _opc tuchar)
          (LScons (Some 12)
            (Ssequence
              (Ssequence
                (Scall (Some _t'5)
                  (Evar _nat_to_opcode_alu32_reg (Tfunction
                                                   (Tcons tuchar Tnil) tuchar
                                                   cc_default))
                  ((Etempvar _op tuchar) :: nil))
                (Sset _opr (Ecast (Etempvar _t'5 tuchar) tuchar)))
              (Ssequence
                (Ssequence
                  (Scall (Some _t'6)
                    (Evar _get_src (Tfunction (Tcons tulong Tnil) tuint
                                     cc_default))
                    ((Etempvar _ins tulong) :: nil))
                  (Sset _src (Etempvar _t'6 tuint)))
                (Ssequence
                  (Scall None
                    (Evar _bpf_alu32_to_thumb_reg (Tfunction
                                                    (Tcons
                                                      (tptr (Tstruct _jit_state noattr))
                                                      (Tcons tuchar
                                                        (Tcons tuint
                                                          (Tcons tuint Tnil))))
                                                    tvoid cc_default))
                    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                     (Etempvar _opr tuchar) :: (Etempvar _dst tuint) ::
                     (Etempvar _src tuint) :: nil))
                  (Sreturn None))))
            (LScons (Some 4)
              (Ssequence
                (Ssequence
                  (Scall (Some _t'7)
                    (Evar _nat_to_opcode_alu32_imm (Tfunction
                                                     (Tcons tuchar Tnil)
                                                     tuchar cc_default))
                    ((Etempvar _op tuchar) :: nil))
                  (Sset _opi (Ecast (Etempvar _t'7 tuchar) tuchar)))
                (Ssequence
                  (Ssequence
                    (Sifthenelse (Ebinop Oeq
                                   (Ebinop Oeq (Etempvar _opi tuchar)
                                     (Econst_int (Int.repr 36) tuint) tint)
                                   (Econst_int (Int.repr 0) tint) tint)
                      (Sset _t'9
                        (Ecast
                          (Ebinop Ole (Econst_int (Int.repr 0) tuint)
                            (Etempvar _imm32 tint) tint) tbool))
                      (Sset _t'9 (Econst_int (Int.repr 0) tint)))
                    (Sifthenelse (Etempvar _t'9 tint)
                      (Sset _t'10
                        (Ecast
                          (Ebinop Ole (Etempvar _imm32 tint)
                            (Econst_int (Int.repr 255) tuint) tint) tbool))
                      (Sset _t'10 (Econst_int (Int.repr 0) tint))))
                  (Sifthenelse (Etempvar _t'10 tint)
                    (Ssequence
                      (Scall None
                        (Evar _bpf_alu32_to_thumb_imm (Tfunction
                                                        (Tcons
                                                          (tptr (Tstruct _jit_state noattr))
                                                          (Tcons tuchar
                                                            (Tcons tuint
                                                              (Tcons tuint
                                                                Tnil))))
                                                        tvoid cc_default))
                        ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                         (Etempvar _opi tuchar) :: (Etempvar _dst tuint) ::
                         (Etempvar _imm32 tint) :: nil))
                      (Sreturn None))
                    (Ssequence
                      (Scall None
                        (Evar _upd_IR11_jittedthumb (Tfunction
                                                      (Tcons
                                                        (tptr (Tstruct _jit_state noattr))
                                                        (Tcons tbool Tnil))
                                                      tvoid cc_default))
                        ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                         (Econst_int (Int.repr 1) tint) :: nil))
                      (Ssequence
                        (Scall None
                          (Evar _mov_int_to_reg_binary (Tfunction
                                                         (Tcons
                                                           (tptr (Tstruct _jit_state noattr))
                                                           (Tcons tuint
                                                             (Tcons tuint
                                                               Tnil))) tvoid
                                                         cc_default))
                          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                           (Ecast (Etempvar _imm32 tint) tuint) ::
                           (Econst_int (Int.repr 11) tuint) :: nil))
                        (Ssequence
                          (Ssequence
                            (Scall (Some _t'8)
                              (Evar _opcode_reg_of_imm (Tfunction
                                                         (Tcons tuchar Tnil)
                                                         tuchar cc_default))
                              ((Etempvar _opi tuchar) :: nil))
                            (Sset _opk (Ecast (Etempvar _t'8 tuchar) tuchar)))
                          (Ssequence
                            (Scall None
                              (Evar _bpf_alu32_to_thumb_reg (Tfunction
                                                              (Tcons
                                                                (tptr (Tstruct _jit_state noattr))
                                                                (Tcons tuchar
                                                                  (Tcons
                                                                    tuint
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil))))
                                                              tvoid
                                                              cc_default))
                              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                               (Etempvar _opk tuchar) ::
                               (Etempvar _dst tuint) ::
                               (Econst_int (Int.repr 11) tuint) :: nil))
                            (Sreturn None))))))))
              (LScons None
                (Ssequence
                  (Scall None
                    (Evar _upd_flag (Tfunction
                                      (Tcons
                                        (tptr (Tstruct _jit_state noattr))
                                        (Tcons tuint Tnil)) tvoid cc_default))
                    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                     (Econst_int (Int.repr 12) tuint) :: nil))
                  (Sreturn None))
                LSnil))))))))
|}.

Definition f_get_store_ins_num := {|
  fn_return := tuint;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: nil);
  fn_vars := nil;
  fn_temps := ((_b, tbool) :: (_n0, tuint) :: (_n1, tuint) :: (_n2, tuint) ::
               (_n3, tuint) :: (_n4, tuint) :: (_n5, tuint) ::
               (_n6, tuint) :: (_n7, tuint) :: (_n8, tuint) ::
               (_n9, tuint) :: (_t'11, tbool) :: (_t'10, tbool) ::
               (_t'9, tbool) :: (_t'8, tbool) :: (_t'7, tbool) ::
               (_t'6, tbool) :: (_t'5, tbool) :: (_t'4, tbool) ::
               (_t'3, tbool) :: (_t'2, tbool) :: (_t'1, tbool) :: nil);
  fn_body :=
(Ssequence
  (Ssequence
    (Scall (Some _t'1)
      (Evar _is_store_reg (Tfunction
                            (Tcons (tptr (Tstruct _jit_state noattr))
                              (Tcons tuint Tnil)) tbool cc_default))
      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
       (Econst_int (Int.repr 0) tuint) :: nil))
    (Sset _b (Ecast (Etempvar _t'1 tbool) tbool)))
  (Ssequence
    (Sifthenelse (Etempvar _b tbool)
      (Sset _n0 (Econst_int (Int.repr 1) tuint))
      (Sset _n0 (Econst_int (Int.repr 0) tuint)))
    (Ssequence
      (Ssequence
        (Scall (Some _t'2)
          (Evar _is_store_reg (Tfunction
                                (Tcons (tptr (Tstruct _jit_state noattr))
                                  (Tcons tuint Tnil)) tbool cc_default))
          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
           (Econst_int (Int.repr 1) tuint) :: nil))
        (Sset _b (Ecast (Etempvar _t'2 tbool) tbool)))
      (Ssequence
        (Sifthenelse (Etempvar _b tbool)
          (Sset _n1
            (Ebinop Oadd (Etempvar _n0 tuint) (Econst_int (Int.repr 1) tuint)
              tuint))
          (Sset _n1 (Etempvar _n0 tuint)))
        (Ssequence
          (Ssequence
            (Scall (Some _t'3)
              (Evar _is_store_reg (Tfunction
                                    (Tcons (tptr (Tstruct _jit_state noattr))
                                      (Tcons tuint Tnil)) tbool cc_default))
              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
               (Econst_int (Int.repr 2) tuint) :: nil))
            (Sset _b (Ecast (Etempvar _t'3 tbool) tbool)))
          (Ssequence
            (Sifthenelse (Etempvar _b tbool)
              (Sset _n2
                (Ebinop Oadd (Etempvar _n1 tuint)
                  (Econst_int (Int.repr 1) tuint) tuint))
              (Sset _n2 (Etempvar _n1 tuint)))
            (Ssequence
              (Ssequence
                (Scall (Some _t'4)
                  (Evar _is_store_reg (Tfunction
                                        (Tcons
                                          (tptr (Tstruct _jit_state noattr))
                                          (Tcons tuint Tnil)) tbool
                                        cc_default))
                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                   (Econst_int (Int.repr 3) tuint) :: nil))
                (Sset _b (Ecast (Etempvar _t'4 tbool) tbool)))
              (Ssequence
                (Sifthenelse (Etempvar _b tbool)
                  (Sset _n3
                    (Ebinop Oadd (Etempvar _n2 tuint)
                      (Econst_int (Int.repr 1) tuint) tuint))
                  (Sset _n3 (Etempvar _n2 tuint)))
                (Ssequence
                  (Ssequence
                    (Scall (Some _t'5)
                      (Evar _is_store_reg (Tfunction
                                            (Tcons
                                              (tptr (Tstruct _jit_state noattr))
                                              (Tcons tuint Tnil)) tbool
                                            cc_default))
                      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                       (Econst_int (Int.repr 4) tuint) :: nil))
                    (Sset _b (Ecast (Etempvar _t'5 tbool) tbool)))
                  (Ssequence
                    (Sifthenelse (Etempvar _b tbool)
                      (Sset _n4
                        (Ebinop Oadd (Etempvar _n3 tuint)
                          (Econst_int (Int.repr 1) tuint) tuint))
                      (Sset _n4 (Etempvar _n3 tuint)))
                    (Ssequence
                      (Ssequence
                        (Scall (Some _t'6)
                          (Evar _is_store_reg (Tfunction
                                                (Tcons
                                                  (tptr (Tstruct _jit_state noattr))
                                                  (Tcons tuint Tnil)) tbool
                                                cc_default))
                          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                           (Econst_int (Int.repr 5) tuint) :: nil))
                        (Sset _b (Ecast (Etempvar _t'6 tbool) tbool)))
                      (Ssequence
                        (Sifthenelse (Etempvar _b tbool)
                          (Sset _n5
                            (Ebinop Oadd (Etempvar _n4 tuint)
                              (Econst_int (Int.repr 1) tuint) tuint))
                          (Sset _n5 (Etempvar _n4 tuint)))
                        (Ssequence
                          (Ssequence
                            (Scall (Some _t'7)
                              (Evar _is_store_reg (Tfunction
                                                    (Tcons
                                                      (tptr (Tstruct _jit_state noattr))
                                                      (Tcons tuint Tnil))
                                                    tbool cc_default))
                              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                               (Econst_int (Int.repr 6) tuint) :: nil))
                            (Sset _b (Ecast (Etempvar _t'7 tbool) tbool)))
                          (Ssequence
                            (Sifthenelse (Etempvar _b tbool)
                              (Sset _n6
                                (Ebinop Oadd (Etempvar _n5 tuint)
                                  (Econst_int (Int.repr 1) tuint) tuint))
                              (Sset _n6 (Etempvar _n5 tuint)))
                            (Ssequence
                              (Ssequence
                                (Scall (Some _t'8)
                                  (Evar _is_store_reg (Tfunction
                                                        (Tcons
                                                          (tptr (Tstruct _jit_state noattr))
                                                          (Tcons tuint Tnil))
                                                        tbool cc_default))
                                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                   (Econst_int (Int.repr 7) tuint) :: nil))
                                (Sset _b (Ecast (Etempvar _t'8 tbool) tbool)))
                              (Ssequence
                                (Sifthenelse (Etempvar _b tbool)
                                  (Sset _n7
                                    (Ebinop Oadd (Etempvar _n6 tuint)
                                      (Econst_int (Int.repr 1) tuint) tuint))
                                  (Sset _n7 (Etempvar _n6 tuint)))
                                (Ssequence
                                  (Ssequence
                                    (Scall (Some _t'9)
                                      (Evar _is_store_reg (Tfunction
                                                            (Tcons
                                                              (tptr (Tstruct _jit_state noattr))
                                                              (Tcons tuint
                                                                Tnil)) tbool
                                                            cc_default))
                                      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                       (Econst_int (Int.repr 8) tuint) ::
                                       nil))
                                    (Sset _b
                                      (Ecast (Etempvar _t'9 tbool) tbool)))
                                  (Ssequence
                                    (Sifthenelse (Etempvar _b tbool)
                                      (Sset _n8
                                        (Ebinop Oadd (Etempvar _n7 tuint)
                                          (Econst_int (Int.repr 1) tuint)
                                          tuint))
                                      (Sset _n8 (Etempvar _n7 tuint)))
                                    (Ssequence
                                      (Ssequence
                                        (Scall (Some _t'10)
                                          (Evar _is_store_reg (Tfunction
                                                                (Tcons
                                                                  (tptr (Tstruct _jit_state noattr))
                                                                  (Tcons
                                                                    tuint
                                                                    Tnil))
                                                                tbool
                                                                cc_default))
                                          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                           (Econst_int (Int.repr 9) tuint) ::
                                           nil))
                                        (Sset _b
                                          (Ecast (Etempvar _t'10 tbool)
                                            tbool)))
                                      (Ssequence
                                        (Sifthenelse (Etempvar _b tbool)
                                          (Sset _n9
                                            (Ebinop Oadd (Etempvar _n8 tuint)
                                              (Econst_int (Int.repr 1) tuint)
                                              tuint))
                                          (Sset _n9 (Etempvar _n8 tuint)))
                                        (Ssequence
                                          (Ssequence
                                            (Scall (Some _t'11)
                                              (Evar _is_store_reg (Tfunction
                                                                    (Tcons
                                                                    (tptr (Tstruct _jit_state noattr))
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil))
                                                                    tbool
                                                                    cc_default))
                                              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                               (Econst_int (Int.repr 10) tuint) ::
                                               nil))
                                            (Sset _b
                                              (Ecast (Etempvar _t'11 tbool)
                                                tbool)))
                                          (Sifthenelse (Etempvar _b tbool)
                                            (Sreturn (Some (Ebinop Oadd
                                                             (Etempvar _n9 tuint)
                                                             (Econst_int (Int.repr 1) tuint)
                                                             tuint)))
                                            (Sreturn (Some (Etempvar _n9 tuint)))))))))))))))))))))))))
|}.

Definition f_jit_alu32_to_thumb_pass2_aux := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) ::
                (_fuel, tuint) :: (_pc, tuint) :: nil);
  fn_vars := nil;
  fn_temps := ((_n, tuint) :: (_ins0, tuint) :: (_store_len, tuint) ::
               (_ofs, tuint) :: (_ins, tuint) :: (_t'4, tint) ::
               (_t'3, tuint) :: (_t'2, tuint) :: (_t'1, tuint) :: nil);
  fn_body :=
(Sifthenelse (Ebinop Oeq (Etempvar _fuel tuint)
               (Econst_int (Int.repr 0) tuint) tint)
  (Sreturn None)
  (Ssequence
    (Sset _n
      (Ebinop Osub (Etempvar _fuel tuint) (Econst_int (Int.repr 1) tuint)
        tuint))
    (Ssequence
      (Ssequence
        (Scall (Some _t'1)
          (Evar _eval_thumb_ins (Tfunction
                                  (Tcons (tptr (Tstruct _jit_state noattr))
                                    (Tcons tuint Tnil)) tuint cc_default))
          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
           (Etempvar _pc tuint) :: nil))
        (Sset _ins0 (Etempvar _t'1 tuint)))
      (Ssequence
        (Sifthenelse (Ebinop Oeq (Etempvar _ins0 tuint)
                       (Econst_int (Int.repr 53504) tint) tint)
          (Sset _t'4 (Econst_int (Int.repr 1) tint))
          (Sset _t'4
            (Ecast
              (Ebinop Oeq (Etempvar _ins0 tuint)
                (Econst_int (Int.repr 56064) tint) tint) tbool)))
        (Sifthenelse (Etempvar _t'4 tint)
          (Ssequence
            (Ssequence
              (Scall (Some _t'2)
                (Evar _get_store_ins_num (Tfunction
                                           (Tcons
                                             (tptr (Tstruct _jit_state noattr))
                                             Tnil) tuint cc_default))
                ((Etempvar _st (tptr (Tstruct _jit_state noattr))) :: nil))
              (Sset _store_len (Etempvar _t'2 tuint)))
            (Ssequence
              (Sset _ofs
                (Ebinop Odiv
                  (Ebinop Oadd
                    (Ebinop Omul (Etempvar _fuel tuint)
                      (Econst_int (Int.repr 2) tuint) tuint)
                    (Ebinop Omul (Etempvar _store_len tuint)
                      (Econst_int (Int.repr 4) tuint) tuint) tuint)
                  (Econst_int (Int.repr 2) tuint) tuint))
              (Ssequence
                (Ssequence
                  (Scall (Some _t'3)
                    (Evar _encode_thumb (Tfunction
                                          (Tcons tuint
                                            (Tcons tuint
                                              (Tcons tuint
                                                (Tcons tuint Tnil)))) tuint
                                          cc_default))
                    ((Etempvar _ofs tuint) :: (Etempvar _ins0 tuint) ::
                     (Econst_int (Int.repr 0) tuint) ::
                     (Econst_int (Int.repr 8) tuint) :: nil))
                  (Sset _ins (Etempvar _t'3 tuint)))
                (Ssequence
                  (Scall None
                    (Evar _upd_thumb_jittedthumb (Tfunction
                                                   (Tcons
                                                     (tptr (Tstruct _jit_state noattr))
                                                     (Tcons tuint
                                                       (Tcons tuint Tnil)))
                                                   tvoid cc_default))
                    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                     (Etempvar _ins tuint) :: (Etempvar _pc tuint) :: nil))
                  (Ssequence
                    (Scall None
                      (Evar _jit_alu32_to_thumb_pass2_aux (Tfunction
                                                            (Tcons
                                                              (tptr (Tstruct _jit_state noattr))
                                                              (Tcons tuint
                                                                (Tcons tuint
                                                                  Tnil)))
                                                            tvoid cc_default))
                      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                       (Etempvar _n tuint) ::
                       (Ebinop Oadd (Etempvar _pc tuint)
                         (Econst_int (Int.repr 1) tuint) tuint) :: nil))
                    (Sreturn None))))))
          (Ssequence
            (Scall None
              (Evar _jit_alu32_to_thumb_pass2_aux (Tfunction
                                                    (Tcons
                                                      (tptr (Tstruct _jit_state noattr))
                                                      (Tcons tuint
                                                        (Tcons tuint Tnil)))
                                                    tvoid cc_default))
              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
               (Etempvar _n tuint) ::
               (Ebinop Oadd (Etempvar _pc tuint)
                 (Econst_int (Int.repr 1) tuint) tuint) :: nil))
            (Sreturn None)))))))
|}.

Definition f_jit_alu32_to_thumb_pass2 := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: nil);
  fn_vars := nil;
  fn_temps := ((_len, tuint) :: (_t'1, tuint) :: nil);
  fn_body :=
(Ssequence
  (Ssequence
    (Scall (Some _t'1)
      (Evar _eval_thumb_len (Tfunction
                              (Tcons (tptr (Tstruct _jit_state noattr)) Tnil)
                              tuint cc_default))
      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) :: nil))
    (Sset _len (Etempvar _t'1 tuint)))
  (Ssequence
    (Scall None
      (Evar _jit_alu32_to_thumb_pass2_aux (Tfunction
                                            (Tcons
                                              (tptr (Tstruct _jit_state noattr))
                                              (Tcons tuint
                                                (Tcons tuint Tnil))) tvoid
                                            cc_default))
      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
       (Etempvar _len tuint) :: (Econst_int (Int.repr 0) tuint) :: nil))
    (Sreturn None)))
|}.

Definition f_jit_alu32_to_thumb_pass1 := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) ::
                (_fuel, tuint) :: (_entry_point, tuint) :: nil);
  fn_vars := nil;
  fn_temps := ((_n, tuint) :: (_ins, tulong) :: (_b, tbool) ::
               (_t'2, tbool) :: (_t'1, tulong) :: nil);
  fn_body :=
(Sifthenelse (Ebinop Oeq (Etempvar _fuel tuint)
               (Econst_int (Int.repr 0) tuint) tint)
  (Ssequence
    (Scall None
      (Evar _jit_alu32_to_thumb_pass2 (Tfunction
                                        (Tcons
                                          (tptr (Tstruct _jit_state noattr))
                                          Tnil) tvoid cc_default))
      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) :: nil))
    (Sreturn None))
  (Ssequence
    (Sset _n
      (Ebinop Osub (Etempvar _fuel tuint) (Econst_int (Int.repr 1) tuint)
        tuint))
    (Ssequence
      (Ssequence
        (Scall (Some _t'1)
          (Evar _eval_ins (Tfunction
                            (Tcons (tptr (Tstruct _jit_state noattr))
                              (Tcons tuint Tnil)) tulong cc_default))
          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
           (Etempvar _entry_point tuint) :: nil))
        (Sset _ins (Etempvar _t'1 tulong)))
      (Ssequence
        (Ssequence
          (Scall (Some _t'2)
            (Evar _ins_is_bpf_alu32 (Tfunction (Tcons tulong Tnil) tbool
                                      cc_default))
            ((Etempvar _ins tulong) :: nil))
          (Sset _b (Ecast (Etempvar _t'2 tbool) tbool)))
        (Sifthenelse (Etempvar _b tbool)
          (Ssequence
            (Scall None
              (Evar _bpf_alu32_to_thumb (Tfunction
                                          (Tcons
                                            (tptr (Tstruct _jit_state noattr))
                                            (Tcons tulong Tnil)) tvoid
                                          cc_default))
              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
               (Etempvar _ins tulong) :: nil))
            (Ssequence
              (Scall None
                (Evar _upd_bpf_offset_jittedthumb (Tfunction
                                                    (Tcons
                                                      (tptr (Tstruct _jit_state noattr))
                                                      Tnil) tvoid cc_default))
                ((Etempvar _st (tptr (Tstruct _jit_state noattr))) :: nil))
              (Ssequence
                (Scall None
                  (Evar _jit_alu32_to_thumb_pass1 (Tfunction
                                                    (Tcons
                                                      (tptr (Tstruct _jit_state noattr))
                                                      (Tcons tuint
                                                        (Tcons tuint Tnil)))
                                                    tvoid cc_default))
                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                   (Etempvar _n tuint) ::
                   (Ebinop Oadd (Etempvar _entry_point tuint)
                     (Econst_int (Int.repr 1) tuint) tuint) :: nil))
                (Sreturn None))))
          (Ssequence
            (Scall None
              (Evar _jit_alu32_to_thumb_pass2 (Tfunction
                                                (Tcons
                                                  (tptr (Tstruct _jit_state noattr))
                                                  Tnil) tvoid cc_default))
              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) :: nil))
            (Sreturn None)))))))
|}.

Definition f_jit_alu32_thumb_upd_store := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: (_r, tuint) ::
                nil);
  fn_vars := nil;
  fn_temps := ((_b, tbool) :: (_int_r, tuint) :: (_t'1, tbool) :: nil);
  fn_body :=
(Ssequence
  (Ssequence
    (Scall (Some _t'1)
      (Evar _is_store_reg (Tfunction
                            (Tcons (tptr (Tstruct _jit_state noattr))
                              (Tcons tuint Tnil)) tbool cc_default))
      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
       (Etempvar _r tuint) :: nil))
    (Sset _b (Ecast (Etempvar _t'1 tbool) tbool)))
  (Sifthenelse (Etempvar _b tbool)
    (Ssequence
      (Sset _int_r (Etempvar _r tuint))
      (Ssequence
        (Scall None
          (Evar _jit_alu32_thumb_store_template_jit (Tfunction
                                                      (Tcons
                                                        (tptr (Tstruct _jit_state noattr))
                                                        (Tcons tushort
                                                          (Tcons tushort
                                                            (Tcons tushort
                                                              Tnil)))) tvoid
                                                      cc_default))
          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
           (Etempvar _int_r tuint) :: (Econst_int (Int.repr 12) tint) ::
           (Ebinop Omul (Etempvar _int_r tuint)
             (Econst_int (Int.repr 8) tint) tuint) :: nil))
        (Sreturn None)))
    (Sreturn None)))
|}.

Definition f_jit_alu32_thumb_store := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Ssequence
  (Scall None
    (Evar _jit_alu32_thumb_load_template_jit (Tfunction
                                               (Tcons
                                                 (tptr (Tstruct _jit_state noattr))
                                                 (Tcons tushort
                                                   (Tcons tushort
                                                     (Tcons tushort Tnil))))
                                               tvoid cc_default))
    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
     (Econst_int (Int.repr 12) tint) :: (Econst_int (Int.repr 12) tint) ::
     (Econst_int (Int.repr 8) tint) :: nil))
  (Ssequence
    (Scall None
      (Evar _jit_alu32_thumb_upd_store (Tfunction
                                         (Tcons
                                           (tptr (Tstruct _jit_state noattr))
                                           (Tcons tuint Tnil)) tvoid
                                         cc_default))
      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
       (Econst_int (Int.repr 0) tuint) :: nil))
    (Ssequence
      (Scall None
        (Evar _jit_alu32_thumb_upd_store (Tfunction
                                           (Tcons
                                             (tptr (Tstruct _jit_state noattr))
                                             (Tcons tuint Tnil)) tvoid
                                           cc_default))
        ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
         (Econst_int (Int.repr 1) tuint) :: nil))
      (Ssequence
        (Scall None
          (Evar _jit_alu32_thumb_upd_store (Tfunction
                                             (Tcons
                                               (tptr (Tstruct _jit_state noattr))
                                               (Tcons tuint Tnil)) tvoid
                                             cc_default))
          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
           (Econst_int (Int.repr 2) tuint) :: nil))
        (Ssequence
          (Scall None
            (Evar _jit_alu32_thumb_upd_store (Tfunction
                                               (Tcons
                                                 (tptr (Tstruct _jit_state noattr))
                                                 (Tcons tuint Tnil)) tvoid
                                               cc_default))
            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
             (Econst_int (Int.repr 3) tuint) :: nil))
          (Ssequence
            (Scall None
              (Evar _jit_alu32_thumb_upd_store (Tfunction
                                                 (Tcons
                                                   (tptr (Tstruct _jit_state noattr))
                                                   (Tcons tuint Tnil)) tvoid
                                                 cc_default))
              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
               (Econst_int (Int.repr 4) tuint) :: nil))
            (Ssequence
              (Scall None
                (Evar _jit_alu32_thumb_upd_store (Tfunction
                                                   (Tcons
                                                     (tptr (Tstruct _jit_state noattr))
                                                     (Tcons tuint Tnil))
                                                   tvoid cc_default))
                ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                 (Econst_int (Int.repr 5) tuint) :: nil))
              (Ssequence
                (Scall None
                  (Evar _jit_alu32_thumb_upd_store (Tfunction
                                                     (Tcons
                                                       (tptr (Tstruct _jit_state noattr))
                                                       (Tcons tuint Tnil))
                                                     tvoid cc_default))
                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                   (Econst_int (Int.repr 6) tuint) :: nil))
                (Ssequence
                  (Scall None
                    (Evar _jit_alu32_thumb_upd_store (Tfunction
                                                       (Tcons
                                                         (tptr (Tstruct _jit_state noattr))
                                                         (Tcons tuint Tnil))
                                                       tvoid cc_default))
                    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                     (Econst_int (Int.repr 7) tuint) :: nil))
                  (Ssequence
                    (Scall None
                      (Evar _jit_alu32_thumb_upd_store (Tfunction
                                                         (Tcons
                                                           (tptr (Tstruct _jit_state noattr))
                                                           (Tcons tuint Tnil))
                                                         tvoid cc_default))
                      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                       (Econst_int (Int.repr 8) tuint) :: nil))
                    (Ssequence
                      (Scall None
                        (Evar _jit_alu32_thumb_upd_store (Tfunction
                                                           (Tcons
                                                             (tptr (Tstruct _jit_state noattr))
                                                             (Tcons tuint
                                                               Tnil)) tvoid
                                                           cc_default))
                        ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                         (Econst_int (Int.repr 9) tuint) :: nil))
                      (Ssequence
                        (Scall None
                          (Evar _jit_alu32_thumb_upd_store (Tfunction
                                                             (Tcons
                                                               (tptr (Tstruct _jit_state noattr))
                                                               (Tcons tuint
                                                                 Tnil)) tvoid
                                                             cc_default))
                          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                           (Econst_int (Int.repr 10) tuint) :: nil))
                        (Sreturn None)))))))))))))
|}.

Definition f_jit_alu32_thumb_upd_reset := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: (_r, tuint) ::
                nil);
  fn_vars := nil;
  fn_temps := ((_b, tbool) :: (_ir, tuint) :: (_t'1, tbool) :: nil);
  fn_body :=
(Ssequence
  (Ssequence
    (Scall (Some _t'1)
      (Evar _is_non_reg (Tfunction
                          (Tcons (tptr (Tstruct _jit_state noattr))
                            (Tcons tuint Tnil)) tbool cc_default))
      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
       (Etempvar _r tuint) :: nil))
    (Sset _b (Ecast (Etempvar _t'1 tbool) tbool)))
  (Sifthenelse (Etempvar _b tbool)
    (Sreturn None)
    (Ssequence
      (Sset _ir (Etempvar _r tuint))
      (Ssequence
        (Scall None
          (Evar _jit_alu32_thumb_load_template_jit (Tfunction
                                                     (Tcons
                                                       (tptr (Tstruct _jit_state noattr))
                                                       (Tcons tushort
                                                         (Tcons tushort
                                                           (Tcons tushort
                                                             Tnil)))) tvoid
                                                     cc_default))
          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
           (Etempvar _ir tuint) :: (Econst_int (Int.repr 13) tuint) ::
           (Ebinop Omul (Etempvar _ir tuint) (Econst_int (Int.repr 4) tint)
             tuint) :: nil))
        (Sreturn None)))))
|}.

Definition f_jit_alu32_thumb_reset := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: nil);
  fn_vars := nil;
  fn_temps := ((_f, tbool) :: (_t'1, tbool) :: nil);
  fn_body :=
(Ssequence
  (Ssequence
    (Scall (Some _t'1)
      (Evar _eval_use_IR11 (Tfunction
                             (Tcons (tptr (Tstruct _jit_state noattr)) Tnil)
                             tbool cc_default))
      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) :: nil))
    (Sset _f (Ecast (Etempvar _t'1 tbool) tbool)))
  (Ssequence
    (Sifthenelse (Etempvar _f tbool)
      (Scall None
        (Evar _jit_alu32_thumb_load_template_jit (Tfunction
                                                   (Tcons
                                                     (tptr (Tstruct _jit_state noattr))
                                                     (Tcons tushort
                                                       (Tcons tushort
                                                         (Tcons tushort Tnil))))
                                                   tvoid cc_default))
        ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
         (Econst_int (Int.repr 11) tint) ::
         (Econst_int (Int.repr 13) tuint) ::
         (Econst_int (Int.repr 44) tint) :: nil))
      Sskip)
    (Ssequence
      (Scall None
        (Evar _jit_alu32_thumb_upd_reset (Tfunction
                                           (Tcons
                                             (tptr (Tstruct _jit_state noattr))
                                             (Tcons tuint Tnil)) tvoid
                                           cc_default))
        ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
         (Econst_int (Int.repr 10) tuint) :: nil))
      (Ssequence
        (Scall None
          (Evar _jit_alu32_thumb_upd_reset (Tfunction
                                             (Tcons
                                               (tptr (Tstruct _jit_state noattr))
                                               (Tcons tuint Tnil)) tvoid
                                             cc_default))
          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
           (Econst_int (Int.repr 9) tuint) :: nil))
        (Ssequence
          (Scall None
            (Evar _jit_alu32_thumb_upd_reset (Tfunction
                                               (Tcons
                                                 (tptr (Tstruct _jit_state noattr))
                                                 (Tcons tuint Tnil)) tvoid
                                               cc_default))
            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
             (Econst_int (Int.repr 8) tuint) :: nil))
          (Ssequence
            (Scall None
              (Evar _jit_alu32_thumb_upd_reset (Tfunction
                                                 (Tcons
                                                   (tptr (Tstruct _jit_state noattr))
                                                   (Tcons tuint Tnil)) tvoid
                                                 cc_default))
              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
               (Econst_int (Int.repr 7) tuint) :: nil))
            (Ssequence
              (Scall None
                (Evar _jit_alu32_thumb_upd_reset (Tfunction
                                                   (Tcons
                                                     (tptr (Tstruct _jit_state noattr))
                                                     (Tcons tuint Tnil))
                                                   tvoid cc_default))
                ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                 (Econst_int (Int.repr 6) tuint) :: nil))
              (Ssequence
                (Scall None
                  (Evar _jit_alu32_thumb_upd_reset (Tfunction
                                                     (Tcons
                                                       (tptr (Tstruct _jit_state noattr))
                                                       (Tcons tuint Tnil))
                                                     tvoid cc_default))
                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                   (Econst_int (Int.repr 5) tuint) :: nil))
                (Ssequence
                  (Scall None
                    (Evar _jit_alu32_thumb_upd_reset (Tfunction
                                                       (Tcons
                                                         (tptr (Tstruct _jit_state noattr))
                                                         (Tcons tuint Tnil))
                                                       tvoid cc_default))
                    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                     (Econst_int (Int.repr 4) tuint) :: nil))
                  (Sreturn None))))))))))
|}.

Definition f_jit_alu32_post := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: nil);
  fn_vars := nil;
  fn_temps := ((_ins_rm, tuint) :: (_t'1, tuint) :: nil);
  fn_body :=
(Ssequence
  (Scall None
    (Evar _jit_alu32_thumb_load_template_jit (Tfunction
                                               (Tcons
                                                 (tptr (Tstruct _jit_state noattr))
                                                 (Tcons tushort
                                                   (Tcons tushort
                                                     (Tcons tushort Tnil))))
                                               tvoid cc_default))
    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
     (Econst_int (Int.repr 13) tuint) :: (Econst_int (Int.repr 13) tuint) ::
     (Econst_int (Int.repr 0) tint) :: nil))
  (Ssequence
    (Ssequence
      (Scall (Some _t'1)
        (Evar _encode_thumb (Tfunction
                              (Tcons tuint
                                (Tcons tuint
                                  (Tcons tuint (Tcons tuint Tnil)))) tuint
                              cc_default))
        ((Econst_int (Int.repr 14) tuint) ::
         (Econst_int (Int.repr 18176) tint) ::
         (Econst_int (Int.repr 3) tuint) ::
         (Econst_int (Int.repr 4) tuint) :: nil))
      (Sset _ins_rm (Etempvar _t'1 tuint)))
    (Ssequence
      (Scall None
        (Evar _upd_jitted_list (Tfunction
                                 (Tcons (tptr (Tstruct _jit_state noattr))
                                   (Tcons tuint Tnil)) tvoid cc_default))
        ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
         (Etempvar _ins_rm tuint) :: nil))
      (Sreturn None))))
|}.

Definition f_copy_thumb_list_from_to_aux := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) ::
                (_fuel, tuint) :: (_pc, tuint) :: nil);
  fn_vars := nil;
  fn_temps := ((_n, tuint) :: (_ins0, tuint) :: (_t'1, tuint) :: nil);
  fn_body :=
(Sifthenelse (Ebinop Oeq (Etempvar _fuel tuint)
               (Econst_int (Int.repr 0) tuint) tint)
  (Sreturn None)
  (Ssequence
    (Sset _n
      (Ebinop Osub (Etempvar _fuel tuint) (Econst_int (Int.repr 1) tuint)
        tuint))
    (Ssequence
      (Ssequence
        (Scall (Some _t'1)
          (Evar _eval_thumb_ins (Tfunction
                                  (Tcons (tptr (Tstruct _jit_state noattr))
                                    (Tcons tuint Tnil)) tuint cc_default))
          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
           (Etempvar _pc tuint) :: nil))
        (Sset _ins0 (Etempvar _t'1 tuint)))
      (Ssequence
        (Scall None
          (Evar _upd_jitted_list (Tfunction
                                   (Tcons (tptr (Tstruct _jit_state noattr))
                                     (Tcons tuint Tnil)) tvoid cc_default))
          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
           (Etempvar _ins0 tuint) :: nil))
        (Ssequence
          (Scall None
            (Evar _copy_thumb_list_from_to_aux (Tfunction
                                                 (Tcons
                                                   (tptr (Tstruct _jit_state noattr))
                                                   (Tcons tuint
                                                     (Tcons tuint Tnil)))
                                                 tvoid cc_default))
            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
             (Etempvar _n tuint) ::
             (Ebinop Oadd (Etempvar _pc tuint)
               (Econst_int (Int.repr 1) tuint) tuint) :: nil))
          (Sreturn None))))))
|}.

Definition f_copy_thumb_list_from_to := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: nil);
  fn_vars := nil;
  fn_temps := ((_len, tuint) :: (_t'1, tuint) :: nil);
  fn_body :=
(Ssequence
  (Ssequence
    (Scall (Some _t'1)
      (Evar _eval_thumb_len (Tfunction
                              (Tcons (tptr (Tstruct _jit_state noattr)) Tnil)
                              tuint cc_default))
      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) :: nil))
    (Sset _len (Etempvar _t'1 tuint)))
  (Ssequence
    (Scall None
      (Evar _copy_thumb_list_from_to_aux (Tfunction
                                           (Tcons
                                             (tptr (Tstruct _jit_state noattr))
                                             (Tcons tuint (Tcons tuint Tnil)))
                                           tvoid cc_default))
      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
       (Etempvar _len tuint) :: (Econst_int (Int.repr 0) tuint) :: nil))
    (Sreturn None)))
|}.

Definition f_jit_alu32_to_thumb := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: (_pc, tuint) ::
                nil);
  fn_vars := nil;
  fn_temps := ((_len, tuint) :: (_ofs0, tuint) :: (_ofs1, tuint) ::
               (_t'3, tuint) :: (_t'2, tuint) :: (_t'1, tuint) :: nil);
  fn_body :=
(Ssequence
  (Scall None
    (Evar _reset_init_jittedthumb (Tfunction
                                    (Tcons (tptr (Tstruct _jit_state noattr))
                                      Tnil) tvoid cc_default))
    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) :: nil))
  (Ssequence
    (Ssequence
      (Scall (Some _t'1)
        (Evar _eval_ins_len (Tfunction
                              (Tcons (tptr (Tstruct _jit_state noattr)) Tnil)
                              tuint cc_default))
        ((Etempvar _st (tptr (Tstruct _jit_state noattr))) :: nil))
      (Sset _len (Etempvar _t'1 tuint)))
    (Ssequence
      (Scall None
        (Evar _jit_alu32_to_thumb_pass1 (Tfunction
                                          (Tcons
                                            (tptr (Tstruct _jit_state noattr))
                                            (Tcons tuint (Tcons tuint Tnil)))
                                          tvoid cc_default))
        ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
         (Etempvar _len tuint) :: (Etempvar _pc tuint) :: nil))
      (Ssequence
        (Ssequence
          (Scall (Some _t'2)
            (Evar _eval_jitted_len (Tfunction
                                     (Tcons
                                       (tptr (Tstruct _jit_state noattr))
                                       Tnil) tuint cc_default))
            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) :: nil))
          (Sset _ofs0 (Etempvar _t'2 tuint)))
        (Ssequence
          (Ssequence
            (Scall (Some _t'3)
              (Evar _eval_offset (Tfunction
                                   (Tcons (tptr (Tstruct _jit_state noattr))
                                     Tnil) tuint cc_default))
              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) :: nil))
            (Sset _ofs1 (Etempvar _t'3 tuint)))
          (Ssequence
            (Scall None
              (Evar _add_key_value2 (Tfunction
                                      (Tcons
                                        (tptr (Tstruct _jit_state noattr))
                                        (Tcons tuint
                                          (Tcons tuint (Tcons tuint Tnil))))
                                      tvoid cc_default))
              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
               (Etempvar _pc tuint) :: (Etempvar _ofs0 tuint) ::
               (Etempvar _ofs1 tuint) :: nil))
            (Ssequence
              (Scall None
                (Evar _jit_alu32_pre (Tfunction
                                       (Tcons
                                         (tptr (Tstruct _jit_state noattr))
                                         Tnil) tvoid cc_default))
                ((Etempvar _st (tptr (Tstruct _jit_state noattr))) :: nil))
              (Ssequence
                (Scall None
                  (Evar _jit_alu32_thumb_save (Tfunction
                                                (Tcons
                                                  (tptr (Tstruct _jit_state noattr))
                                                  Tnil) tvoid cc_default))
                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) :: nil))
                (Ssequence
                  (Scall None
                    (Evar _jit_alu32_thumb_load (Tfunction
                                                  (Tcons
                                                    (tptr (Tstruct _jit_state noattr))
                                                    Tnil) tvoid cc_default))
                    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                     nil))
                  (Ssequence
                    (Scall None
                      (Evar _copy_thumb_list_from_to (Tfunction
                                                       (Tcons
                                                         (tptr (Tstruct _jit_state noattr))
                                                         Tnil) tvoid
                                                       cc_default))
                      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                       nil))
                    (Ssequence
                      (Scall None
                        (Evar _jit_alu32_thumb_store (Tfunction
                                                       (Tcons
                                                         (tptr (Tstruct _jit_state noattr))
                                                         Tnil) tvoid
                                                       cc_default))
                        ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                         nil))
                      (Ssequence
                        (Scall None
                          (Evar _jit_alu32_thumb_reset (Tfunction
                                                         (Tcons
                                                           (tptr (Tstruct _jit_state noattr))
                                                           Tnil) tvoid
                                                         cc_default))
                          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                           nil))
                        (Ssequence
                          (Scall None
                            (Evar _jit_alu32_post (Tfunction
                                                    (Tcons
                                                      (tptr (Tstruct _jit_state noattr))
                                                      Tnil) tvoid cc_default))
                            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                             nil))
                          (Sreturn None))))))))))))))
|}.

Definition f_jit_alu32_aux := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) ::
                (_fuel, tuint) :: (_pc, tuint) :: (_pre_is_alu32, tbool) ::
                nil);
  fn_vars := nil;
  fn_temps := ((_n, tuint) :: (_ins, tulong) :: (_b, tbool) ::
               (_ofs, tint) :: (_next_pc, tuint) :: (_next_ins, tulong) ::
               (_t'6, tbool) :: (_t'5, tulong) :: (_t'4, tint) ::
               (_t'3, tbool) :: (_t'2, tbool) :: (_t'1, tulong) :: nil);
  fn_body :=
(Sifthenelse (Ebinop Oeq (Etempvar _fuel tuint)
               (Econst_int (Int.repr 0) tuint) tint)
  (Sreturn None)
  (Ssequence
    (Sset _n
      (Ebinop Osub (Etempvar _fuel tuint) (Econst_int (Int.repr 1) tuint)
        tuint))
    (Ssequence
      (Ssequence
        (Scall (Some _t'1)
          (Evar _eval_ins (Tfunction
                            (Tcons (tptr (Tstruct _jit_state noattr))
                              (Tcons tuint Tnil)) tulong cc_default))
          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
           (Etempvar _pc tuint) :: nil))
        (Sset _ins (Etempvar _t'1 tulong)))
      (Ssequence
        (Ssequence
          (Scall (Some _t'2)
            (Evar _ins_is_bpf_alu32 (Tfunction (Tcons tulong Tnil) tbool
                                      cc_default))
            ((Etempvar _ins tulong) :: nil))
          (Sset _b (Ecast (Etempvar _t'2 tbool) tbool)))
        (Sifthenelse (Etempvar _b tbool)
          (Sifthenelse (Ebinop Oeq (Etempvar _pre_is_alu32 tbool)
                         (Econst_int (Int.repr 0) tint) tint)
            (Ssequence
              (Scall None
                (Evar _jit_alu32_to_thumb (Tfunction
                                            (Tcons
                                              (tptr (Tstruct _jit_state noattr))
                                              (Tcons tuint Tnil)) tvoid
                                            cc_default))
                ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                 (Etempvar _pc tuint) :: nil))
              (Ssequence
                (Scall None
                  (Evar _jit_alu32_aux (Tfunction
                                         (Tcons
                                           (tptr (Tstruct _jit_state noattr))
                                           (Tcons tuint
                                             (Tcons tuint (Tcons tbool Tnil))))
                                         tvoid cc_default))
                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                   (Etempvar _n tuint) ::
                   (Ebinop Oadd (Etempvar _pc tuint)
                     (Econst_int (Int.repr 1) tuint) tuint) ::
                   (Econst_int (Int.repr 1) tint) :: nil))
                (Sreturn None)))
            (Ssequence
              (Scall None
                (Evar _jit_alu32_aux (Tfunction
                                       (Tcons
                                         (tptr (Tstruct _jit_state noattr))
                                         (Tcons tuint
                                           (Tcons tuint (Tcons tbool Tnil))))
                                       tvoid cc_default))
                ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                 (Etempvar _n tuint) ::
                 (Ebinop Oadd (Etempvar _pc tuint)
                   (Econst_int (Int.repr 1) tuint) tuint) ::
                 (Econst_int (Int.repr 1) tint) :: nil))
              (Sreturn None)))
          (Ssequence
            (Ssequence
              (Scall (Some _t'3)
                (Evar _ins_is_bpf_jump (Tfunction (Tcons tulong Tnil) tbool
                                         cc_default))
                ((Etempvar _ins tulong) :: nil))
              (Sset _b (Ecast (Etempvar _t'3 tbool) tbool)))
            (Sifthenelse (Etempvar _b tbool)
              (Ssequence
                (Ssequence
                  (Scall (Some _t'4)
                    (Evar _get_offset (Tfunction (Tcons tulong Tnil) tint
                                        cc_default))
                    ((Etempvar _ins tulong) :: nil))
                  (Sset _ofs (Etempvar _t'4 tint)))
                (Ssequence
                  (Sset _next_pc
                    (Ebinop Oadd
                      (Ebinop Oadd (Etempvar _pc tuint) (Etempvar _ofs tint)
                        tuint) (Econst_int (Int.repr 1) tuint) tuint))
                  (Ssequence
                    (Ssequence
                      (Scall (Some _t'5)
                        (Evar _eval_ins (Tfunction
                                          (Tcons
                                            (tptr (Tstruct _jit_state noattr))
                                            (Tcons tuint Tnil)) tulong
                                          cc_default))
                        ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                         (Etempvar _next_pc tuint) :: nil))
                      (Sset _next_ins (Etempvar _t'5 tulong)))
                    (Ssequence
                      (Ssequence
                        (Scall (Some _t'6)
                          (Evar _ins_is_bpf_alu32 (Tfunction
                                                    (Tcons tulong Tnil) tbool
                                                    cc_default))
                          ((Etempvar _next_ins tulong) :: nil))
                        (Sset _b (Ecast (Etempvar _t'6 tbool) tbool)))
                      (Sifthenelse (Etempvar _b tbool)
                        (Ssequence
                          (Scall None
                            (Evar _jit_alu32_to_thumb (Tfunction
                                                        (Tcons
                                                          (tptr (Tstruct _jit_state noattr))
                                                          (Tcons tuint Tnil))
                                                        tvoid cc_default))
                            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                             (Etempvar _next_pc tuint) :: nil))
                          (Ssequence
                            (Scall None
                              (Evar _jit_alu32_aux (Tfunction
                                                     (Tcons
                                                       (tptr (Tstruct _jit_state noattr))
                                                       (Tcons tuint
                                                         (Tcons tuint
                                                           (Tcons tbool Tnil))))
                                                     tvoid cc_default))
                              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                               (Etempvar _n tuint) ::
                               (Ebinop Oadd (Etempvar _pc tuint)
                                 (Econst_int (Int.repr 1) tuint) tuint) ::
                               (Econst_int (Int.repr 0) tint) :: nil))
                            (Sreturn None)))
                        (Ssequence
                          (Scall None
                            (Evar _jit_alu32_aux (Tfunction
                                                   (Tcons
                                                     (tptr (Tstruct _jit_state noattr))
                                                     (Tcons tuint
                                                       (Tcons tuint
                                                         (Tcons tbool Tnil))))
                                                   tvoid cc_default))
                            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                             (Etempvar _n tuint) ::
                             (Ebinop Oadd (Etempvar _pc tuint)
                               (Econst_int (Int.repr 1) tuint) tuint) ::
                             (Econst_int (Int.repr 0) tint) :: nil))
                          (Sreturn None)))))))
              (Ssequence
                (Scall None
                  (Evar _jit_alu32_aux (Tfunction
                                         (Tcons
                                           (tptr (Tstruct _jit_state noattr))
                                           (Tcons tuint
                                             (Tcons tuint (Tcons tbool Tnil))))
                                         tvoid cc_default))
                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                   (Etempvar _n tuint) ::
                   (Ebinop Oadd (Etempvar _pc tuint)
                     (Econst_int (Int.repr 1) tuint) tuint) ::
                   (Econst_int (Int.repr 0) tint) :: nil))
                (Sreturn None)))))))))
|}.

Definition f_jit_alu32 := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: nil);
  fn_vars := nil;
  fn_temps := ((_len, tuint) :: (_t'1, tuint) :: nil);
  fn_body :=
(Ssequence
  (Ssequence
    (Scall (Some _t'1)
      (Evar _eval_ins_len (Tfunction
                            (Tcons (tptr (Tstruct _jit_state noattr)) Tnil)
                            tuint cc_default))
      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) :: nil))
    (Sset _len (Etempvar _t'1 tuint)))
  (Ssequence
    (Scall None
      (Evar _jit_alu32_aux (Tfunction
                             (Tcons (tptr (Tstruct _jit_state noattr))
                               (Tcons tuint (Tcons tuint (Tcons tbool Tnil))))
                             tvoid cc_default))
      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
       (Etempvar _len tuint) :: (Econst_int (Int.repr 0) tuint) ::
       (Econst_int (Int.repr 0) tint) :: nil))
    (Sreturn None)))
|}.

Definition f_reg64_to_reg32 := {|
  fn_return := tuint;
  fn_callconv := cc_default;
  fn_params := ((_d, tulong) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sreturn (Some (Ecast (Etempvar _d tulong) tuint)))
|}.

Definition f_eval_immediate := {|
  fn_return := tlong;
  fn_callconv := cc_default;
  fn_params := ((_ins, tint) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sreturn (Some (Ecast (Etempvar _ins tint) tlong)))
|}.

Definition f_get_src64 := {|
  fn_return := tulong;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: (_x, tuchar) ::
                (_ins, tulong) :: nil);
  fn_vars := nil;
  fn_temps := ((_imm, tint) :: (_imm64, tlong) :: (_src, tuint) ::
               (_src64, tulong) :: (_t'4, tulong) :: (_t'3, tuint) ::
               (_t'2, tlong) :: (_t'1, tint) :: nil);
  fn_body :=
(Sifthenelse (Ebinop Oeq (Econst_int (Int.repr 0) tuint)
               (Ebinop Oand (Etempvar _x tuchar)
                 (Econst_int (Int.repr 8) tuint) tuint) tint)
  (Ssequence
    (Ssequence
      (Scall (Some _t'1)
        (Evar _get_immediate (Tfunction (Tcons tulong Tnil) tint cc_default))
        ((Etempvar _ins tulong) :: nil))
      (Sset _imm (Etempvar _t'1 tint)))
    (Ssequence
      (Ssequence
        (Scall (Some _t'2)
          (Evar _eval_immediate (Tfunction (Tcons tint Tnil) tlong
                                  cc_default)) ((Etempvar _imm tint) :: nil))
        (Sset _imm64 (Etempvar _t'2 tlong)))
      (Sreturn (Some (Ecast (Etempvar _imm64 tlong) tulong)))))
  (Ssequence
    (Ssequence
      (Scall (Some _t'3)
        (Evar _get_src (Tfunction (Tcons tulong Tnil) tuint cc_default))
        ((Etempvar _ins tulong) :: nil))
      (Sset _src (Etempvar _t'3 tuint)))
    (Ssequence
      (Ssequence
        (Scall (Some _t'4)
          (Evar _eval_reg (Tfunction
                            (Tcons (tptr (Tstruct _jit_state noattr))
                              (Tcons tuint Tnil)) tulong cc_default))
          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
           (Etempvar _src tuint) :: nil))
        (Sset _src64 (Etempvar _t'4 tulong)))
      (Sreturn (Some (Etempvar _src64 tulong))))))
|}.

Definition f_get_opcode_alu64 := {|
  fn_return := tuchar;
  fn_callconv := cc_default;
  fn_params := ((_op, tuchar) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sreturn (Some (Ecast
                 (Ebinop Oand (Etempvar _op tuchar)
                   (Econst_int (Int.repr 240) tint) tint) tuchar)))
|}.

Definition f_get_opcode_alu32 := {|
  fn_return := tuchar;
  fn_callconv := cc_default;
  fn_params := ((_op, tuchar) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sreturn (Some (Ecast
                 (Ebinop Oand (Etempvar _op tuchar)
                   (Econst_int (Int.repr 240) tint) tint) tuchar)))
|}.

Definition f_get_opcode_branch := {|
  fn_return := tuchar;
  fn_callconv := cc_default;
  fn_params := ((_op, tuchar) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sreturn (Some (Ecast
                 (Ebinop Oand (Etempvar _op tuchar)
                   (Econst_int (Int.repr 240) tint) tint) tuchar)))
|}.

Definition f_get_opcode_mem_ld_imm := {|
  fn_return := tuchar;
  fn_callconv := cc_default;
  fn_params := ((_op, tuchar) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sreturn (Some (Ecast
                 (Ebinop Oand (Etempvar _op tuchar)
                   (Econst_int (Int.repr 255) tint) tint) tuchar)))
|}.

Definition f_get_opcode_mem_ld_reg := {|
  fn_return := tuchar;
  fn_callconv := cc_default;
  fn_params := ((_op, tuchar) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sreturn (Some (Ecast
                 (Ebinop Oand (Etempvar _op tuchar)
                   (Econst_int (Int.repr 255) tint) tint) tuchar)))
|}.

Definition f_get_opcode_mem_st_imm := {|
  fn_return := tuchar;
  fn_callconv := cc_default;
  fn_params := ((_op, tuchar) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sreturn (Some (Ecast
                 (Ebinop Oand (Etempvar _op tuchar)
                   (Econst_int (Int.repr 255) tint) tint) tuchar)))
|}.

Definition f_get_opcode_mem_st_reg := {|
  fn_return := tuchar;
  fn_callconv := cc_default;
  fn_params := ((_op, tuchar) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sreturn (Some (Ecast
                 (Ebinop Oand (Etempvar _op tuchar)
                   (Econst_int (Int.repr 255) tint) tint) tuchar)))
|}.

Definition f_get_opcode := {|
  fn_return := tuchar;
  fn_callconv := cc_default;
  fn_params := ((_op, tuchar) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sreturn (Some (Ecast
                 (Ebinop Oand (Etempvar _op tuchar)
                   (Econst_int (Int.repr 7) tint) tint) tuchar)))
|}.

Definition f_get_add := {|
  fn_return := tuint;
  fn_callconv := cc_default;
  fn_params := ((_x, tuint) :: (_y, tuint) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sreturn (Some (Ebinop Oadd (Etempvar _x tuint) (Etempvar _y tuint) tuint)))
|}.

Definition f_get_sub := {|
  fn_return := tuint;
  fn_callconv := cc_default;
  fn_params := ((_x, tuint) :: (_y, tuint) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sreturn (Some (Ebinop Osub (Etempvar _x tuint) (Etempvar _y tuint) tuint)))
|}.

Definition f_get_addr_ofs := {|
  fn_return := tuint;
  fn_callconv := cc_default;
  fn_params := ((_x, tulong) :: (_ofs, tint) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sreturn (Some (Ecast
                 (Ebinop Oadd (Etempvar _x tulong)
                   (Ecast (Etempvar _ofs tint) tulong) tulong) tuint)))
|}.

Definition f_get_start_addr := {|
  fn_return := tuint;
  fn_callconv := cc_default;
  fn_params := ((_mr, (tptr (Tstruct _memory_region noattr))) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sreturn (Some (Efield
                 (Ederef
                   (Etempvar _mr (tptr (Tstruct _memory_region noattr)))
                   (Tstruct _memory_region noattr)) _start_addr tuint)))
|}.

Definition f_get_block_size := {|
  fn_return := tuint;
  fn_callconv := cc_default;
  fn_params := ((_mr, (tptr (Tstruct _memory_region noattr))) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sreturn (Some (Efield
                 (Ederef
                   (Etempvar _mr (tptr (Tstruct _memory_region noattr)))
                   (Tstruct _memory_region noattr)) _block_size tuint)))
|}.

Definition f_get_block_perm := {|
  fn_return := tuint;
  fn_callconv := cc_default;
  fn_params := ((_mr, (tptr (Tstruct _memory_region noattr))) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sreturn (Some (Efield
                 (Ederef
                   (Etempvar _mr (tptr (Tstruct _memory_region noattr)))
                   (Tstruct _memory_region noattr)) _block_perm tuint)))
|}.

Definition f_is_well_chunk_bool := {|
  fn_return := tbool;
  fn_callconv := cc_default;
  fn_params := ((_chunk, tuint) :: nil);
  fn_vars := nil;
  fn_temps := nil;
  fn_body :=
(Sswitch (Etempvar _chunk tuint)
  (LScons (Some 1)
    (Sreturn (Some (Econst_int (Int.repr 1) tint)))
    (LScons (Some 2)
      (Sreturn (Some (Econst_int (Int.repr 1) tint)))
      (LScons (Some 4)
        (Sreturn (Some (Econst_int (Int.repr 1) tint)))
        (LScons (Some 8)
          (Sreturn (Some (Econst_int (Int.repr 1) tint)))
          (LScons None (Sreturn (Some (Econst_int (Int.repr 0) tint))) LSnil))))))
|}.

Definition f_check_mem_aux2 := {|
  fn_return := (tptr tuchar);
  fn_callconv := cc_default;
  fn_params := ((_mr, (tptr (Tstruct _memory_region noattr))) ::
                (_perm, tuint) :: (_addr, tuint) :: (_chunk, tuint) :: nil);
  fn_vars := nil;
  fn_temps := ((_start, tuint) :: (_size, tuint) :: (_mr_perm, tuint) ::
               (_lo_ofs, tuint) :: (_hi_ofs, tuint) :: (_t'7, tint) ::
               (_t'6, tint) :: (_t'5, tuint) :: (_t'4, tuint) ::
               (_t'3, tuint) :: (_t'2, tuint) :: (_t'1, tuint) :: nil);
  fn_body :=
(Ssequence
  (Ssequence
    (Scall (Some _t'1)
      (Evar _get_start_addr (Tfunction
                              (Tcons (tptr (Tstruct _memory_region noattr))
                                Tnil) tuint cc_default))
      ((Etempvar _mr (tptr (Tstruct _memory_region noattr))) :: nil))
    (Sset _start (Etempvar _t'1 tuint)))
  (Ssequence
    (Ssequence
      (Scall (Some _t'2)
        (Evar _get_block_size (Tfunction
                                (Tcons (tptr (Tstruct _memory_region noattr))
                                  Tnil) tuint cc_default))
        ((Etempvar _mr (tptr (Tstruct _memory_region noattr))) :: nil))
      (Sset _size (Etempvar _t'2 tuint)))
    (Ssequence
      (Ssequence
        (Scall (Some _t'3)
          (Evar _get_block_perm (Tfunction
                                  (Tcons
                                    (tptr (Tstruct _memory_region noattr))
                                    Tnil) tuint cc_default))
          ((Etempvar _mr (tptr (Tstruct _memory_region noattr))) :: nil))
        (Sset _mr_perm (Etempvar _t'3 tuint)))
      (Ssequence
        (Ssequence
          (Scall (Some _t'4)
            (Evar _get_sub (Tfunction (Tcons tuint (Tcons tuint Tnil)) tuint
                             cc_default))
            ((Etempvar _addr tuint) :: (Etempvar _start tuint) :: nil))
          (Sset _lo_ofs (Etempvar _t'4 tuint)))
        (Ssequence
          (Ssequence
            (Scall (Some _t'5)
              (Evar _get_add (Tfunction (Tcons tuint (Tcons tuint Tnil))
                               tuint cc_default))
              ((Etempvar _lo_ofs tuint) :: (Etempvar _chunk tuint) :: nil))
            (Sset _hi_ofs (Etempvar _t'5 tuint)))
          (Ssequence
            (Ssequence
              (Sifthenelse (Ebinop Olt (Etempvar _hi_ofs tuint)
                             (Etempvar _size tuint) tint)
                (Sifthenelse (Ebinop Ole (Etempvar _lo_ofs tuint)
                               (Ebinop Osub
                                 (Econst_int (Int.repr (-1)) tuint)
                                 (Etempvar _chunk tuint) tuint) tint)
                  (Ssequence
                    (Sset _t'6
                      (Ecast
                        (Ebinop Oeq (Econst_int (Int.repr 0) tuint)
                          (Ebinop Omod (Etempvar _lo_ofs tuint)
                            (Etempvar _chunk tuint) tuint) tint) tbool))
                    (Sset _t'6 (Ecast (Etempvar _t'6 tint) tbool)))
                  (Sset _t'6 (Ecast (Econst_int (Int.repr 0) tint) tbool)))
                (Sset _t'6 (Econst_int (Int.repr 0) tint)))
              (Sifthenelse (Etempvar _t'6 tint)
                (Sset _t'7
                  (Ecast
                    (Ebinop Oge (Etempvar _mr_perm tuint)
                      (Etempvar _perm tuint) tint) tbool))
                (Sset _t'7 (Econst_int (Int.repr 0) tint))))
            (Sifthenelse (Etempvar _t'7 tint)
              (Sreturn (Some (Ebinop Oadd
                               (Efield
                                 (Ederef
                                   (Etempvar _mr (tptr (Tstruct _memory_region noattr)))
                                   (Tstruct _memory_region noattr))
                                 _block_ptr (tptr tuchar))
                               (Etempvar _lo_ofs tuint) (tptr tuchar))))
              (Sreturn (Some (Econst_int (Int.repr 0) tint))))))))))
|}.

Definition f_check_mem_aux := {|
  fn_return := (tptr tuchar);
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: (_num, tuint) ::
                (_perm, tuint) :: (_chunk, tuint) :: (_addr, tuint) ::
                (_mrs, (tptr (Tstruct _memory_region noattr))) :: nil);
  fn_vars := nil;
  fn_temps := ((_n, tuint) ::
               (_cur_mr, (tptr (Tstruct _memory_region noattr))) ::
               (_check_mem__1, (tptr tuchar)) :: (_is_null, tbool) ::
               (_t'4, (tptr tuchar)) :: (_t'3, tbool) ::
               (_t'2, (tptr tuchar)) ::
               (_t'1, (tptr (Tstruct _memory_region noattr))) :: nil);
  fn_body :=
(Sifthenelse (Ebinop Oeq (Etempvar _num tuint)
               (Econst_int (Int.repr 0) tuint) tint)
  (Sreturn (Some (Econst_int (Int.repr 0) tint)))
  (Ssequence
    (Sset _n
      (Ebinop Osub (Etempvar _num tuint) (Econst_int (Int.repr 1) tuint)
        tuint))
    (Ssequence
      (Ssequence
        (Scall (Some _t'1)
          (Evar _get_mem_region (Tfunction
                                  (Tcons tuint
                                    (Tcons
                                      (tptr (Tstruct _memory_region noattr))
                                      Tnil))
                                  (tptr (Tstruct _memory_region noattr))
                                  cc_default))
          ((Etempvar _n tuint) ::
           (Etempvar _mrs (tptr (Tstruct _memory_region noattr))) :: nil))
        (Sset _cur_mr (Etempvar _t'1 (tptr (Tstruct _memory_region noattr)))))
      (Ssequence
        (Ssequence
          (Scall (Some _t'2)
            (Evar _check_mem_aux2 (Tfunction
                                    (Tcons
                                      (tptr (Tstruct _memory_region noattr))
                                      (Tcons tuint
                                        (Tcons tuint (Tcons tuint Tnil))))
                                    (tptr tuchar) cc_default))
            ((Etempvar _cur_mr (tptr (Tstruct _memory_region noattr))) ::
             (Etempvar _perm tuint) :: (Etempvar _addr tuint) ::
             (Etempvar _chunk tuint) :: nil))
          (Sset _check_mem__1 (Etempvar _t'2 (tptr tuchar))))
        (Ssequence
          (Ssequence
            (Scall (Some _t'3)
              (Evar _cmp_ptr32_nullM (Tfunction (Tcons (tptr tuchar) Tnil)
                                       tbool cc_default))
              ((Etempvar _check_mem__1 (tptr tuchar)) :: nil))
            (Sset _is_null (Ecast (Etempvar _t'3 tbool) tbool)))
          (Sifthenelse (Etempvar _is_null tbool)
            (Ssequence
              (Scall (Some _t'4)
                (Evar _check_mem_aux (Tfunction
                                       (Tcons
                                         (tptr (Tstruct _jit_state noattr))
                                         (Tcons tuint
                                           (Tcons tuint
                                             (Tcons tuint
                                               (Tcons tuint
                                                 (Tcons
                                                   (tptr (Tstruct _memory_region noattr))
                                                   Tnil)))))) (tptr tuchar)
                                       cc_default))
                ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                 (Etempvar _n tuint) :: (Etempvar _perm tuint) ::
                 (Etempvar _chunk tuint) :: (Etempvar _addr tuint) ::
                 (Etempvar _mrs (tptr (Tstruct _memory_region noattr))) ::
                 nil))
              (Sreturn (Some (Etempvar _t'4 (tptr tuchar)))))
            (Sreturn (Some (Etempvar _check_mem__1 (tptr tuchar))))))))))
|}.

Definition f_check_mem := {|
  fn_return := (tptr tuchar);
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) ::
                (_perm, tuint) :: (_chunk, tuint) :: (_addr, tuint) :: nil);
  fn_vars := nil;
  fn_temps := ((_well_chunk, tbool) :: (_mem_reg_num, tuint) ::
               (_mrs, (tptr (Tstruct _memory_region noattr))) ::
               (_check_mem__1, (tptr tuchar)) :: (_is_null, tbool) ::
               (_t'5, tbool) :: (_t'4, (tptr tuchar)) ::
               (_t'3, (tptr (Tstruct _memory_region noattr))) ::
               (_t'2, tuint) :: (_t'1, tbool) :: nil);
  fn_body :=
(Ssequence
  (Ssequence
    (Scall (Some _t'1)
      (Evar _is_well_chunk_bool (Tfunction (Tcons tuint Tnil) tbool
                                  cc_default))
      ((Etempvar _chunk tuint) :: nil))
    (Sset _well_chunk (Ecast (Etempvar _t'1 tbool) tbool)))
  (Sifthenelse (Etempvar _well_chunk tbool)
    (Ssequence
      (Ssequence
        (Scall (Some _t'2)
          (Evar _eval_mrs_num (Tfunction
                                (Tcons (tptr (Tstruct _jit_state noattr))
                                  Tnil) tuint cc_default))
          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) :: nil))
        (Sset _mem_reg_num (Etempvar _t'2 tuint)))
      (Ssequence
        (Ssequence
          (Scall (Some _t'3)
            (Evar _eval_mrs_regions (Tfunction
                                      (Tcons
                                        (tptr (Tstruct _jit_state noattr))
                                        Tnil)
                                      (tptr (Tstruct _memory_region noattr))
                                      cc_default))
            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) :: nil))
          (Sset _mrs (Etempvar _t'3 (tptr (Tstruct _memory_region noattr)))))
        (Ssequence
          (Ssequence
            (Scall (Some _t'4)
              (Evar _check_mem_aux (Tfunction
                                     (Tcons
                                       (tptr (Tstruct _jit_state noattr))
                                       (Tcons tuint
                                         (Tcons tuint
                                           (Tcons tuint
                                             (Tcons tuint
                                               (Tcons
                                                 (tptr (Tstruct _memory_region noattr))
                                                 Tnil)))))) (tptr tuchar)
                                     cc_default))
              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
               (Etempvar _mem_reg_num tuint) :: (Etempvar _perm tuint) ::
               (Etempvar _chunk tuint) :: (Etempvar _addr tuint) ::
               (Etempvar _mrs (tptr (Tstruct _memory_region noattr))) :: nil))
            (Sset _check_mem__1 (Etempvar _t'4 (tptr tuchar))))
          (Ssequence
            (Ssequence
              (Scall (Some _t'5)
                (Evar _cmp_ptr32_nullM (Tfunction (Tcons (tptr tuchar) Tnil)
                                         tbool cc_default))
                ((Etempvar _check_mem__1 (tptr tuchar)) :: nil))
              (Sset _is_null (Ecast (Etempvar _t'5 tbool) tbool)))
            (Sifthenelse (Etempvar _is_null tbool)
              (Sreturn (Some (Econst_int (Int.repr 0) tint)))
              (Sreturn (Some (Etempvar _check_mem__1 (tptr tuchar)))))))))
    (Sreturn (Some (Econst_int (Int.repr 0) tint)))))
|}.

Definition f_step_opcode_alu64 := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) ::
                (_dst64, tulong) :: (_src64, tulong) :: (_dst, tuint) ::
                (_op, tuchar) :: nil);
  fn_vars := nil;
  fn_temps := ((_opcode_alu64, tuchar) :: (_src32, tuint) :: (_t'4, tuint) ::
               (_t'3, tuint) :: (_t'2, tuint) :: (_t'1, tuchar) :: nil);
  fn_body :=
(Ssequence
  (Ssequence
    (Scall (Some _t'1)
      (Evar _get_opcode_alu64 (Tfunction (Tcons tuchar Tnil) tuchar
                                cc_default)) ((Etempvar _op tuchar) :: nil))
    (Sset _opcode_alu64 (Ecast (Etempvar _t'1 tuchar) tuchar)))
  (Sswitch (Etempvar _opcode_alu64 tuchar)
    (LScons (Some 0)
      (Ssequence
        (Scall None
          (Evar _upd_reg (Tfunction
                           (Tcons (tptr (Tstruct _jit_state noattr))
                             (Tcons tuint (Tcons tulong Tnil))) tvoid
                           cc_default))
          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
           (Etempvar _dst tuint) ::
           (Ebinop Oadd (Etempvar _dst64 tulong) (Etempvar _src64 tulong)
             tulong) :: nil))
        (Sreturn None))
      (LScons (Some 16)
        (Ssequence
          (Scall None
            (Evar _upd_reg (Tfunction
                             (Tcons (tptr (Tstruct _jit_state noattr))
                               (Tcons tuint (Tcons tulong Tnil))) tvoid
                             cc_default))
            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
             (Etempvar _dst tuint) ::
             (Ebinop Osub (Etempvar _dst64 tulong) (Etempvar _src64 tulong)
               tulong) :: nil))
          (Sreturn None))
        (LScons (Some 32)
          (Ssequence
            (Scall None
              (Evar _upd_reg (Tfunction
                               (Tcons (tptr (Tstruct _jit_state noattr))
                                 (Tcons tuint (Tcons tulong Tnil))) tvoid
                               cc_default))
              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
               (Etempvar _dst tuint) ::
               (Ebinop Omul (Etempvar _dst64 tulong) (Etempvar _src64 tulong)
                 tulong) :: nil))
            (Sreturn None))
          (LScons (Some 48)
            (Sifthenelse (Ebinop One (Etempvar _src64 tulong)
                           (Econst_long (Int64.repr 0) tulong) tint)
              (Ssequence
                (Scall None
                  (Evar _upd_reg (Tfunction
                                   (Tcons (tptr (Tstruct _jit_state noattr))
                                     (Tcons tuint (Tcons tulong Tnil))) tvoid
                                   cc_default))
                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                   (Etempvar _dst tuint) ::
                   (Ebinop Odiv (Etempvar _dst64 tulong)
                     (Etempvar _src64 tulong) tulong) :: nil))
                (Sreturn None))
              (Ssequence
                (Scall None
                  (Evar _upd_flag (Tfunction
                                    (Tcons (tptr (Tstruct _jit_state noattr))
                                      (Tcons tuint Tnil)) tvoid cc_default))
                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                   (Econst_int (Int.repr 10) tuint) :: nil))
                (Sreturn None)))
            (LScons (Some 64)
              (Ssequence
                (Scall None
                  (Evar _upd_reg (Tfunction
                                   (Tcons (tptr (Tstruct _jit_state noattr))
                                     (Tcons tuint (Tcons tulong Tnil))) tvoid
                                   cc_default))
                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                   (Etempvar _dst tuint) ::
                   (Ebinop Oor (Etempvar _dst64 tulong)
                     (Etempvar _src64 tulong) tulong) :: nil))
                (Sreturn None))
              (LScons (Some 80)
                (Ssequence
                  (Scall None
                    (Evar _upd_reg (Tfunction
                                     (Tcons
                                       (tptr (Tstruct _jit_state noattr))
                                       (Tcons tuint (Tcons tulong Tnil)))
                                     tvoid cc_default))
                    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                     (Etempvar _dst tuint) ::
                     (Ebinop Oand (Etempvar _dst64 tulong)
                       (Etempvar _src64 tulong) tulong) :: nil))
                  (Sreturn None))
                (LScons (Some 96)
                  (Ssequence
                    (Ssequence
                      (Scall (Some _t'2)
                        (Evar _reg64_to_reg32 (Tfunction (Tcons tulong Tnil)
                                                tuint cc_default))
                        ((Etempvar _src64 tulong) :: nil))
                      (Sset _src32 (Etempvar _t'2 tuint)))
                    (Sifthenelse (Ebinop Olt (Etempvar _src32 tuint)
                                   (Econst_int (Int.repr 64) tuint) tint)
                      (Ssequence
                        (Scall None
                          (Evar _upd_reg (Tfunction
                                           (Tcons
                                             (tptr (Tstruct _jit_state noattr))
                                             (Tcons tuint
                                               (Tcons tulong Tnil))) tvoid
                                           cc_default))
                          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                           (Etempvar _dst tuint) ::
                           (Ebinop Oshl (Etempvar _dst64 tulong)
                             (Etempvar _src32 tuint) tulong) :: nil))
                        (Sreturn None))
                      (Ssequence
                        (Scall None
                          (Evar _upd_flag (Tfunction
                                            (Tcons
                                              (tptr (Tstruct _jit_state noattr))
                                              (Tcons tuint Tnil)) tvoid
                                            cc_default))
                          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                           (Econst_int (Int.repr 11) tuint) :: nil))
                        (Sreturn None))))
                  (LScons (Some 112)
                    (Ssequence
                      (Ssequence
                        (Scall (Some _t'3)
                          (Evar _reg64_to_reg32 (Tfunction
                                                  (Tcons tulong Tnil) tuint
                                                  cc_default))
                          ((Etempvar _src64 tulong) :: nil))
                        (Sset _src32 (Etempvar _t'3 tuint)))
                      (Sifthenelse (Ebinop Olt (Etempvar _src32 tuint)
                                     (Econst_int (Int.repr 64) tuint) tint)
                        (Ssequence
                          (Scall None
                            (Evar _upd_reg (Tfunction
                                             (Tcons
                                               (tptr (Tstruct _jit_state noattr))
                                               (Tcons tuint
                                                 (Tcons tulong Tnil))) tvoid
                                             cc_default))
                            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                             (Etempvar _dst tuint) ::
                             (Ebinop Oshr (Etempvar _dst64 tulong)
                               (Etempvar _src32 tuint) tulong) :: nil))
                          (Sreturn None))
                        (Ssequence
                          (Scall None
                            (Evar _upd_flag (Tfunction
                                              (Tcons
                                                (tptr (Tstruct _jit_state noattr))
                                                (Tcons tuint Tnil)) tvoid
                                              cc_default))
                            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                             (Econst_int (Int.repr 11) tuint) :: nil))
                          (Sreturn None))))
                    (LScons (Some 128)
                      (Sifthenelse (Ebinop Oeq (Etempvar _op tuchar)
                                     (Econst_int (Int.repr 135) tint) tint)
                        (Ssequence
                          (Scall None
                            (Evar _upd_reg (Tfunction
                                             (Tcons
                                               (tptr (Tstruct _jit_state noattr))
                                               (Tcons tuint
                                                 (Tcons tulong Tnil))) tvoid
                                             cc_default))
                            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                             (Etempvar _dst tuint) ::
                             (Eunop Oneg (Etempvar _dst64 tulong) tulong) ::
                             nil))
                          (Sreturn None))
                        (Ssequence
                          (Scall None
                            (Evar _upd_flag (Tfunction
                                              (Tcons
                                                (tptr (Tstruct _jit_state noattr))
                                                (Tcons tuint Tnil)) tvoid
                                              cc_default))
                            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                             (Econst_int (Int.repr 2) tuint) :: nil))
                          (Sreturn None)))
                      (LScons (Some 144)
                        (Sifthenelse (Ebinop One (Etempvar _src64 tulong)
                                       (Econst_long (Int64.repr 0) tulong)
                                       tint)
                          (Ssequence
                            (Scall None
                              (Evar _upd_reg (Tfunction
                                               (Tcons
                                                 (tptr (Tstruct _jit_state noattr))
                                                 (Tcons tuint
                                                   (Tcons tulong Tnil)))
                                               tvoid cc_default))
                              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                               (Etempvar _dst tuint) ::
                               (Ebinop Omod (Etempvar _dst64 tulong)
                                 (Etempvar _src64 tulong) tulong) :: nil))
                            (Sreturn None))
                          (Ssequence
                            (Scall None
                              (Evar _upd_flag (Tfunction
                                                (Tcons
                                                  (tptr (Tstruct _jit_state noattr))
                                                  (Tcons tuint Tnil)) tvoid
                                                cc_default))
                              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                               (Econst_int (Int.repr 10) tuint) :: nil))
                            (Sreturn None)))
                        (LScons (Some 160)
                          (Ssequence
                            (Scall None
                              (Evar _upd_reg (Tfunction
                                               (Tcons
                                                 (tptr (Tstruct _jit_state noattr))
                                                 (Tcons tuint
                                                   (Tcons tulong Tnil)))
                                               tvoid cc_default))
                              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                               (Etempvar _dst tuint) ::
                               (Ebinop Oxor (Etempvar _dst64 tulong)
                                 (Etempvar _src64 tulong) tulong) :: nil))
                            (Sreturn None))
                          (LScons (Some 176)
                            (Ssequence
                              (Scall None
                                (Evar _upd_reg (Tfunction
                                                 (Tcons
                                                   (tptr (Tstruct _jit_state noattr))
                                                   (Tcons tuint
                                                     (Tcons tulong Tnil)))
                                                 tvoid cc_default))
                                ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                 (Etempvar _dst tuint) ::
                                 (Etempvar _src64 tulong) :: nil))
                              (Sreturn None))
                            (LScons (Some 192)
                              (Ssequence
                                (Ssequence
                                  (Scall (Some _t'4)
                                    (Evar _reg64_to_reg32 (Tfunction
                                                            (Tcons tulong
                                                              Tnil) tuint
                                                            cc_default))
                                    ((Etempvar _src64 tulong) :: nil))
                                  (Sset _src32 (Etempvar _t'4 tuint)))
                                (Sifthenelse (Ebinop Olt
                                               (Etempvar _src32 tuint)
                                               (Econst_int (Int.repr 64) tuint)
                                               tint)
                                  (Ssequence
                                    (Scall None
                                      (Evar _upd_reg (Tfunction
                                                       (Tcons
                                                         (tptr (Tstruct _jit_state noattr))
                                                         (Tcons tuint
                                                           (Tcons tulong
                                                             Tnil))) tvoid
                                                       cc_default))
                                      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                       (Etempvar _dst tuint) ::
                                       (Ecast
                                         (Ebinop Oshr
                                           (Ecast (Etempvar _dst64 tulong)
                                             tlong) (Etempvar _src32 tuint)
                                           tlong) tulong) :: nil))
                                    (Sreturn None))
                                  (Ssequence
                                    (Scall None
                                      (Evar _upd_flag (Tfunction
                                                        (Tcons
                                                          (tptr (Tstruct _jit_state noattr))
                                                          (Tcons tuint Tnil))
                                                        tvoid cc_default))
                                      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                       (Econst_int (Int.repr 11) tuint) ::
                                       nil))
                                    (Sreturn None))))
                              (LScons None
                                (Ssequence
                                  (Scall None
                                    (Evar _upd_flag (Tfunction
                                                      (Tcons
                                                        (tptr (Tstruct _jit_state noattr))
                                                        (Tcons tuint Tnil))
                                                      tvoid cc_default))
                                    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                     (Econst_int (Int.repr 2) tuint) :: nil))
                                  (Sreturn None))
                                LSnil))))))))))))))))
|}.

Definition f_step_opcode_alu32 := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: (_op, tuchar) ::
                (_pc, tuint) :: nil);
  fn_vars := nil;
  fn_temps := ((_opcode_alu32, tuchar) :: (_ofs0, tuint) :: (_ofs1, tuint) ::
               (_t'27, tuint) :: (_t'26, tuint) :: (_t'25, tuint) ::
               (_t'24, tuint) :: (_t'23, tuint) :: (_t'22, tuint) ::
               (_t'21, tuint) :: (_t'20, tuint) :: (_t'19, tuint) ::
               (_t'18, tuint) :: (_t'17, tuint) :: (_t'16, tuint) ::
               (_t'15, tuint) :: (_t'14, tuint) :: (_t'13, tuint) ::
               (_t'12, tuint) :: (_t'11, tuint) :: (_t'10, tuint) ::
               (_t'9, tuint) :: (_t'8, tuint) :: (_t'7, tuint) ::
               (_t'6, tuint) :: (_t'5, tuint) :: (_t'4, tuint) ::
               (_t'3, tuint) :: (_t'2, tuint) :: (_t'1, tuchar) :: nil);
  fn_body :=
(Ssequence
  (Ssequence
    (Scall (Some _t'1)
      (Evar _get_opcode_alu32 (Tfunction (Tcons tuchar Tnil) tuchar
                                cc_default)) ((Etempvar _op tuchar) :: nil))
    (Sset _opcode_alu32 (Ecast (Etempvar _t'1 tuchar) tuchar)))
  (Sswitch (Etempvar _opcode_alu32 tuchar)
    (LScons (Some 0)
      (Ssequence
        (Ssequence
          (Scall (Some _t'2)
            (Evar _eval_key_value2_arm_ofs (Tfunction
                                             (Tcons
                                               (tptr (Tstruct _jit_state noattr))
                                               (Tcons tuint Tnil)) tuint
                                             cc_default))
            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
             (Etempvar _pc tuint) :: nil))
          (Sset _ofs0 (Etempvar _t'2 tuint)))
        (Ssequence
          (Ssequence
            (Scall (Some _t'3)
              (Evar _eval_key_value2_alu32_ofs (Tfunction
                                                 (Tcons
                                                   (tptr (Tstruct _jit_state noattr))
                                                   (Tcons tuint Tnil)) tuint
                                                 cc_default))
              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
               (Etempvar _pc tuint) :: nil))
            (Sset _ofs1 (Etempvar _t'3 tuint)))
          (Ssequence
            (Scall None
              (Evar _magic_function (Tfunction
                                      (Tcons
                                        (tptr (Tstruct _jit_state noattr))
                                        (Tcons tuint Tnil)) tvoid cc_default))
              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
               (Etempvar _ofs0 tuint) :: nil))
            (Ssequence
              (Scall None
                (Evar _upd_pc (Tfunction
                                (Tcons (tptr (Tstruct _jit_state noattr))
                                  (Tcons tuint Tnil)) tvoid cc_default))
                ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                 (Ebinop Oadd (Etempvar _pc tuint) (Etempvar _ofs1 tuint)
                   tuint) :: nil))
              (Sreturn None)))))
      (LScons (Some 16)
        (Ssequence
          (Ssequence
            (Scall (Some _t'4)
              (Evar _eval_key_value2_arm_ofs (Tfunction
                                               (Tcons
                                                 (tptr (Tstruct _jit_state noattr))
                                                 (Tcons tuint Tnil)) tuint
                                               cc_default))
              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
               (Etempvar _pc tuint) :: nil))
            (Sset _ofs0 (Etempvar _t'4 tuint)))
          (Ssequence
            (Ssequence
              (Scall (Some _t'5)
                (Evar _eval_key_value2_alu32_ofs (Tfunction
                                                   (Tcons
                                                     (tptr (Tstruct _jit_state noattr))
                                                     (Tcons tuint Tnil))
                                                   tuint cc_default))
                ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                 (Etempvar _pc tuint) :: nil))
              (Sset _ofs1 (Etempvar _t'5 tuint)))
            (Ssequence
              (Scall None
                (Evar _magic_function (Tfunction
                                        (Tcons
                                          (tptr (Tstruct _jit_state noattr))
                                          (Tcons tuint Tnil)) tvoid
                                        cc_default))
                ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                 (Etempvar _ofs0 tuint) :: nil))
              (Ssequence
                (Scall None
                  (Evar _upd_pc (Tfunction
                                  (Tcons (tptr (Tstruct _jit_state noattr))
                                    (Tcons tuint Tnil)) tvoid cc_default))
                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                   (Ebinop Oadd (Etempvar _pc tuint) (Etempvar _ofs1 tuint)
                     tuint) :: nil))
                (Sreturn None)))))
        (LScons (Some 32)
          (Ssequence
            (Ssequence
              (Scall (Some _t'6)
                (Evar _eval_key_value2_arm_ofs (Tfunction
                                                 (Tcons
                                                   (tptr (Tstruct _jit_state noattr))
                                                   (Tcons tuint Tnil)) tuint
                                                 cc_default))
                ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                 (Etempvar _pc tuint) :: nil))
              (Sset _ofs0 (Etempvar _t'6 tuint)))
            (Ssequence
              (Ssequence
                (Scall (Some _t'7)
                  (Evar _eval_key_value2_alu32_ofs (Tfunction
                                                     (Tcons
                                                       (tptr (Tstruct _jit_state noattr))
                                                       (Tcons tuint Tnil))
                                                     tuint cc_default))
                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                   (Etempvar _pc tuint) :: nil))
                (Sset _ofs1 (Etempvar _t'7 tuint)))
              (Ssequence
                (Scall None
                  (Evar _magic_function (Tfunction
                                          (Tcons
                                            (tptr (Tstruct _jit_state noattr))
                                            (Tcons tuint Tnil)) tvoid
                                          cc_default))
                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                   (Etempvar _ofs0 tuint) :: nil))
                (Ssequence
                  (Scall None
                    (Evar _upd_pc (Tfunction
                                    (Tcons (tptr (Tstruct _jit_state noattr))
                                      (Tcons tuint Tnil)) tvoid cc_default))
                    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                     (Ebinop Oadd (Etempvar _pc tuint) (Etempvar _ofs1 tuint)
                       tuint) :: nil))
                  (Sreturn None)))))
          (LScons (Some 48)
            (Ssequence
              (Ssequence
                (Scall (Some _t'8)
                  (Evar _eval_key_value2_arm_ofs (Tfunction
                                                   (Tcons
                                                     (tptr (Tstruct _jit_state noattr))
                                                     (Tcons tuint Tnil))
                                                   tuint cc_default))
                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                   (Etempvar _pc tuint) :: nil))
                (Sset _ofs0 (Etempvar _t'8 tuint)))
              (Ssequence
                (Ssequence
                  (Scall (Some _t'9)
                    (Evar _eval_key_value2_alu32_ofs (Tfunction
                                                       (Tcons
                                                         (tptr (Tstruct _jit_state noattr))
                                                         (Tcons tuint Tnil))
                                                       tuint cc_default))
                    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                     (Etempvar _pc tuint) :: nil))
                  (Sset _ofs1 (Etempvar _t'9 tuint)))
                (Ssequence
                  (Scall None
                    (Evar _magic_function (Tfunction
                                            (Tcons
                                              (tptr (Tstruct _jit_state noattr))
                                              (Tcons tuint Tnil)) tvoid
                                            cc_default))
                    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                     (Etempvar _ofs0 tuint) :: nil))
                  (Ssequence
                    (Scall None
                      (Evar _upd_pc (Tfunction
                                      (Tcons
                                        (tptr (Tstruct _jit_state noattr))
                                        (Tcons tuint Tnil)) tvoid cc_default))
                      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                       (Ebinop Oadd (Etempvar _pc tuint)
                         (Etempvar _ofs1 tuint) tuint) :: nil))
                    (Sreturn None)))))
            (LScons (Some 64)
              (Ssequence
                (Ssequence
                  (Scall (Some _t'10)
                    (Evar _eval_key_value2_arm_ofs (Tfunction
                                                     (Tcons
                                                       (tptr (Tstruct _jit_state noattr))
                                                       (Tcons tuint Tnil))
                                                     tuint cc_default))
                    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                     (Etempvar _pc tuint) :: nil))
                  (Sset _ofs0 (Etempvar _t'10 tuint)))
                (Ssequence
                  (Ssequence
                    (Scall (Some _t'11)
                      (Evar _eval_key_value2_alu32_ofs (Tfunction
                                                         (Tcons
                                                           (tptr (Tstruct _jit_state noattr))
                                                           (Tcons tuint Tnil))
                                                         tuint cc_default))
                      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                       (Etempvar _pc tuint) :: nil))
                    (Sset _ofs1 (Etempvar _t'11 tuint)))
                  (Ssequence
                    (Scall None
                      (Evar _magic_function (Tfunction
                                              (Tcons
                                                (tptr (Tstruct _jit_state noattr))
                                                (Tcons tuint Tnil)) tvoid
                                              cc_default))
                      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                       (Etempvar _ofs0 tuint) :: nil))
                    (Ssequence
                      (Scall None
                        (Evar _upd_pc (Tfunction
                                        (Tcons
                                          (tptr (Tstruct _jit_state noattr))
                                          (Tcons tuint Tnil)) tvoid
                                        cc_default))
                        ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                         (Ebinop Oadd (Etempvar _pc tuint)
                           (Etempvar _ofs1 tuint) tuint) :: nil))
                      (Sreturn None)))))
              (LScons (Some 80)
                (Ssequence
                  (Ssequence
                    (Scall (Some _t'12)
                      (Evar _eval_key_value2_arm_ofs (Tfunction
                                                       (Tcons
                                                         (tptr (Tstruct _jit_state noattr))
                                                         (Tcons tuint Tnil))
                                                       tuint cc_default))
                      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                       (Etempvar _pc tuint) :: nil))
                    (Sset _ofs0 (Etempvar _t'12 tuint)))
                  (Ssequence
                    (Ssequence
                      (Scall (Some _t'13)
                        (Evar _eval_key_value2_alu32_ofs (Tfunction
                                                           (Tcons
                                                             (tptr (Tstruct _jit_state noattr))
                                                             (Tcons tuint
                                                               Tnil)) tuint
                                                           cc_default))
                        ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                         (Etempvar _pc tuint) :: nil))
                      (Sset _ofs1 (Etempvar _t'13 tuint)))
                    (Ssequence
                      (Scall None
                        (Evar _magic_function (Tfunction
                                                (Tcons
                                                  (tptr (Tstruct _jit_state noattr))
                                                  (Tcons tuint Tnil)) tvoid
                                                cc_default))
                        ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                         (Etempvar _ofs0 tuint) :: nil))
                      (Ssequence
                        (Scall None
                          (Evar _upd_pc (Tfunction
                                          (Tcons
                                            (tptr (Tstruct _jit_state noattr))
                                            (Tcons tuint Tnil)) tvoid
                                          cc_default))
                          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                           (Ebinop Oadd (Etempvar _pc tuint)
                             (Etempvar _ofs1 tuint) tuint) :: nil))
                        (Sreturn None)))))
                (LScons (Some 96)
                  (Ssequence
                    (Ssequence
                      (Scall (Some _t'14)
                        (Evar _eval_key_value2_arm_ofs (Tfunction
                                                         (Tcons
                                                           (tptr (Tstruct _jit_state noattr))
                                                           (Tcons tuint Tnil))
                                                         tuint cc_default))
                        ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                         (Etempvar _pc tuint) :: nil))
                      (Sset _ofs0 (Etempvar _t'14 tuint)))
                    (Ssequence
                      (Ssequence
                        (Scall (Some _t'15)
                          (Evar _eval_key_value2_alu32_ofs (Tfunction
                                                             (Tcons
                                                               (tptr (Tstruct _jit_state noattr))
                                                               (Tcons tuint
                                                                 Tnil)) tuint
                                                             cc_default))
                          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                           (Etempvar _pc tuint) :: nil))
                        (Sset _ofs1 (Etempvar _t'15 tuint)))
                      (Ssequence
                        (Scall None
                          (Evar _magic_function (Tfunction
                                                  (Tcons
                                                    (tptr (Tstruct _jit_state noattr))
                                                    (Tcons tuint Tnil)) tvoid
                                                  cc_default))
                          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                           (Etempvar _ofs0 tuint) :: nil))
                        (Ssequence
                          (Scall None
                            (Evar _upd_pc (Tfunction
                                            (Tcons
                                              (tptr (Tstruct _jit_state noattr))
                                              (Tcons tuint Tnil)) tvoid
                                            cc_default))
                            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                             (Ebinop Oadd (Etempvar _pc tuint)
                               (Etempvar _ofs1 tuint) tuint) :: nil))
                          (Sreturn None)))))
                  (LScons (Some 112)
                    (Ssequence
                      (Ssequence
                        (Scall (Some _t'16)
                          (Evar _eval_key_value2_arm_ofs (Tfunction
                                                           (Tcons
                                                             (tptr (Tstruct _jit_state noattr))
                                                             (Tcons tuint
                                                               Tnil)) tuint
                                                           cc_default))
                          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                           (Etempvar _pc tuint) :: nil))
                        (Sset _ofs0 (Etempvar _t'16 tuint)))
                      (Ssequence
                        (Ssequence
                          (Scall (Some _t'17)
                            (Evar _eval_key_value2_alu32_ofs (Tfunction
                                                               (Tcons
                                                                 (tptr (Tstruct _jit_state noattr))
                                                                 (Tcons tuint
                                                                   Tnil))
                                                               tuint
                                                               cc_default))
                            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                             (Etempvar _pc tuint) :: nil))
                          (Sset _ofs1 (Etempvar _t'17 tuint)))
                        (Ssequence
                          (Scall None
                            (Evar _magic_function (Tfunction
                                                    (Tcons
                                                      (tptr (Tstruct _jit_state noattr))
                                                      (Tcons tuint Tnil))
                                                    tvoid cc_default))
                            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                             (Etempvar _ofs0 tuint) :: nil))
                          (Ssequence
                            (Scall None
                              (Evar _upd_pc (Tfunction
                                              (Tcons
                                                (tptr (Tstruct _jit_state noattr))
                                                (Tcons tuint Tnil)) tvoid
                                              cc_default))
                              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                               (Ebinop Oadd (Etempvar _pc tuint)
                                 (Etempvar _ofs1 tuint) tuint) :: nil))
                            (Sreturn None)))))
                    (LScons (Some 128)
                      (Ssequence
                        (Ssequence
                          (Scall (Some _t'18)
                            (Evar _eval_key_value2_arm_ofs (Tfunction
                                                             (Tcons
                                                               (tptr (Tstruct _jit_state noattr))
                                                               (Tcons tuint
                                                                 Tnil)) tuint
                                                             cc_default))
                            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                             (Etempvar _pc tuint) :: nil))
                          (Sset _ofs0 (Etempvar _t'18 tuint)))
                        (Ssequence
                          (Ssequence
                            (Scall (Some _t'19)
                              (Evar _eval_key_value2_alu32_ofs (Tfunction
                                                                 (Tcons
                                                                   (tptr (Tstruct _jit_state noattr))
                                                                   (Tcons
                                                                    tuint
                                                                    Tnil))
                                                                 tuint
                                                                 cc_default))
                              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                               (Etempvar _pc tuint) :: nil))
                            (Sset _ofs1 (Etempvar _t'19 tuint)))
                          (Ssequence
                            (Scall None
                              (Evar _magic_function (Tfunction
                                                      (Tcons
                                                        (tptr (Tstruct _jit_state noattr))
                                                        (Tcons tuint Tnil))
                                                      tvoid cc_default))
                              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                               (Etempvar _ofs0 tuint) :: nil))
                            (Ssequence
                              (Scall None
                                (Evar _upd_pc (Tfunction
                                                (Tcons
                                                  (tptr (Tstruct _jit_state noattr))
                                                  (Tcons tuint Tnil)) tvoid
                                                cc_default))
                                ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                 (Ebinop Oadd (Etempvar _pc tuint)
                                   (Etempvar _ofs1 tuint) tuint) :: nil))
                              (Sreturn None)))))
                      (LScons (Some 144)
                        (Ssequence
                          (Ssequence
                            (Scall (Some _t'20)
                              (Evar _eval_key_value2_arm_ofs (Tfunction
                                                               (Tcons
                                                                 (tptr (Tstruct _jit_state noattr))
                                                                 (Tcons tuint
                                                                   Tnil))
                                                               tuint
                                                               cc_default))
                              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                               (Etempvar _pc tuint) :: nil))
                            (Sset _ofs0 (Etempvar _t'20 tuint)))
                          (Ssequence
                            (Ssequence
                              (Scall (Some _t'21)
                                (Evar _eval_key_value2_alu32_ofs (Tfunction
                                                                   (Tcons
                                                                    (tptr (Tstruct _jit_state noattr))
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil))
                                                                   tuint
                                                                   cc_default))
                                ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                 (Etempvar _pc tuint) :: nil))
                              (Sset _ofs1 (Etempvar _t'21 tuint)))
                            (Ssequence
                              (Scall None
                                (Evar _magic_function (Tfunction
                                                        (Tcons
                                                          (tptr (Tstruct _jit_state noattr))
                                                          (Tcons tuint Tnil))
                                                        tvoid cc_default))
                                ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                 (Etempvar _ofs0 tuint) :: nil))
                              (Ssequence
                                (Scall None
                                  (Evar _upd_pc (Tfunction
                                                  (Tcons
                                                    (tptr (Tstruct _jit_state noattr))
                                                    (Tcons tuint Tnil)) tvoid
                                                  cc_default))
                                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                   (Ebinop Oadd (Etempvar _pc tuint)
                                     (Etempvar _ofs1 tuint) tuint) :: nil))
                                (Sreturn None)))))
                        (LScons (Some 160)
                          (Ssequence
                            (Ssequence
                              (Scall (Some _t'22)
                                (Evar _eval_key_value2_arm_ofs (Tfunction
                                                                 (Tcons
                                                                   (tptr (Tstruct _jit_state noattr))
                                                                   (Tcons
                                                                    tuint
                                                                    Tnil))
                                                                 tuint
                                                                 cc_default))
                                ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                 (Etempvar _pc tuint) :: nil))
                              (Sset _ofs0 (Etempvar _t'22 tuint)))
                            (Ssequence
                              (Ssequence
                                (Scall (Some _t'23)
                                  (Evar _eval_key_value2_alu32_ofs (Tfunction
                                                                    (Tcons
                                                                    (tptr (Tstruct _jit_state noattr))
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil))
                                                                    tuint
                                                                    cc_default))
                                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                   (Etempvar _pc tuint) :: nil))
                                (Sset _ofs1 (Etempvar _t'23 tuint)))
                              (Ssequence
                                (Scall None
                                  (Evar _magic_function (Tfunction
                                                          (Tcons
                                                            (tptr (Tstruct _jit_state noattr))
                                                            (Tcons tuint
                                                              Tnil)) tvoid
                                                          cc_default))
                                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                   (Etempvar _ofs0 tuint) :: nil))
                                (Ssequence
                                  (Scall None
                                    (Evar _upd_pc (Tfunction
                                                    (Tcons
                                                      (tptr (Tstruct _jit_state noattr))
                                                      (Tcons tuint Tnil))
                                                    tvoid cc_default))
                                    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                     (Ebinop Oadd (Etempvar _pc tuint)
                                       (Etempvar _ofs1 tuint) tuint) :: nil))
                                  (Sreturn None)))))
                          (LScons (Some 176)
                            (Ssequence
                              (Ssequence
                                (Scall (Some _t'24)
                                  (Evar _eval_key_value2_arm_ofs (Tfunction
                                                                   (Tcons
                                                                    (tptr (Tstruct _jit_state noattr))
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil))
                                                                   tuint
                                                                   cc_default))
                                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                   (Etempvar _pc tuint) :: nil))
                                (Sset _ofs0 (Etempvar _t'24 tuint)))
                              (Ssequence
                                (Ssequence
                                  (Scall (Some _t'25)
                                    (Evar _eval_key_value2_alu32_ofs 
                                    (Tfunction
                                      (Tcons
                                        (tptr (Tstruct _jit_state noattr))
                                        (Tcons tuint Tnil)) tuint cc_default))
                                    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                     (Etempvar _pc tuint) :: nil))
                                  (Sset _ofs1 (Etempvar _t'25 tuint)))
                                (Ssequence
                                  (Scall None
                                    (Evar _magic_function (Tfunction
                                                            (Tcons
                                                              (tptr (Tstruct _jit_state noattr))
                                                              (Tcons tuint
                                                                Tnil)) tvoid
                                                            cc_default))
                                    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                     (Etempvar _ofs0 tuint) :: nil))
                                  (Ssequence
                                    (Scall None
                                      (Evar _upd_pc (Tfunction
                                                      (Tcons
                                                        (tptr (Tstruct _jit_state noattr))
                                                        (Tcons tuint Tnil))
                                                      tvoid cc_default))
                                      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                       (Ebinop Oadd (Etempvar _pc tuint)
                                         (Etempvar _ofs1 tuint) tuint) ::
                                       nil))
                                    (Sreturn None)))))
                            (LScons (Some 192)
                              (Ssequence
                                (Ssequence
                                  (Scall (Some _t'26)
                                    (Evar _eval_key_value2_arm_ofs (Tfunction
                                                                    (Tcons
                                                                    (tptr (Tstruct _jit_state noattr))
                                                                    (Tcons
                                                                    tuint
                                                                    Tnil))
                                                                    tuint
                                                                    cc_default))
                                    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                     (Etempvar _pc tuint) :: nil))
                                  (Sset _ofs0 (Etempvar _t'26 tuint)))
                                (Ssequence
                                  (Ssequence
                                    (Scall (Some _t'27)
                                      (Evar _eval_key_value2_alu32_ofs 
                                      (Tfunction
                                        (Tcons
                                          (tptr (Tstruct _jit_state noattr))
                                          (Tcons tuint Tnil)) tuint
                                        cc_default))
                                      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                       (Etempvar _pc tuint) :: nil))
                                    (Sset _ofs1 (Etempvar _t'27 tuint)))
                                  (Ssequence
                                    (Scall None
                                      (Evar _magic_function (Tfunction
                                                              (Tcons
                                                                (tptr (Tstruct _jit_state noattr))
                                                                (Tcons tuint
                                                                  Tnil))
                                                              tvoid
                                                              cc_default))
                                      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                       (Etempvar _ofs0 tuint) :: nil))
                                    (Ssequence
                                      (Scall None
                                        (Evar _upd_pc (Tfunction
                                                        (Tcons
                                                          (tptr (Tstruct _jit_state noattr))
                                                          (Tcons tuint Tnil))
                                                        tvoid cc_default))
                                        ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                         (Ebinop Oadd (Etempvar _pc tuint)
                                           (Etempvar _ofs1 tuint) tuint) ::
                                         nil))
                                      (Sreturn None)))))
                              (LScons None
                                (Ssequence
                                  (Scall None
                                    (Evar _upd_flag (Tfunction
                                                      (Tcons
                                                        (tptr (Tstruct _jit_state noattr))
                                                        (Tcons tuint Tnil))
                                                      tvoid cc_default))
                                    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                     (Econst_int (Int.repr 2) tuint) :: nil))
                                  (Sreturn None))
                                LSnil))))))))))))))))
|}.

Definition f_step_opcode_branch := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) ::
                (_dst64, tulong) :: (_src64, tulong) :: (_pc, tuint) ::
                (_ofs, tuint) :: (_op, tuchar) :: nil);
  fn_vars := nil;
  fn_temps := ((_opcode_jmp, tuchar) :: (_f_ptr, (tptr tuchar)) ::
               (_is_null, tbool) :: (_res, tuint) :: (_t'4, tuint) ::
               (_t'3, tbool) :: (_t'2, (tptr tuchar)) :: (_t'1, tuchar) ::
               nil);
  fn_body :=
(Ssequence
  (Ssequence
    (Scall (Some _t'1)
      (Evar _get_opcode_branch (Tfunction (Tcons tuchar Tnil) tuchar
                                 cc_default)) ((Etempvar _op tuchar) :: nil))
    (Sset _opcode_jmp (Ecast (Etempvar _t'1 tuchar) tuchar)))
  (Sswitch (Etempvar _opcode_jmp tuchar)
    (LScons (Some 0)
      (Sifthenelse (Ebinop Oeq (Etempvar _op tuchar)
                     (Econst_int (Int.repr 5) tint) tint)
        (Ssequence
          (Scall None
            (Evar _upd_pc (Tfunction
                            (Tcons (tptr (Tstruct _jit_state noattr))
                              (Tcons tuint Tnil)) tvoid cc_default))
            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
             (Ebinop Oadd (Etempvar _pc tuint) (Etempvar _ofs tuint) tuint) ::
             nil))
          (Sreturn None))
        (Ssequence
          (Scall None
            (Evar _upd_flag (Tfunction
                              (Tcons (tptr (Tstruct _jit_state noattr))
                                (Tcons tuint Tnil)) tvoid cc_default))
            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
             (Econst_int (Int.repr 2) tuint) :: nil))
          (Sreturn None)))
      (LScons (Some 16)
        (Sifthenelse (Ebinop Oeq (Etempvar _dst64 tulong)
                       (Etempvar _src64 tulong) tint)
          (Ssequence
            (Scall None
              (Evar _upd_pc (Tfunction
                              (Tcons (tptr (Tstruct _jit_state noattr))
                                (Tcons tuint Tnil)) tvoid cc_default))
              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
               (Ebinop Oadd (Etempvar _pc tuint) (Etempvar _ofs tuint) tuint) ::
               nil))
            (Sreturn None))
          (Sreturn None))
        (LScons (Some 32)
          (Sifthenelse (Ebinop Ogt (Etempvar _dst64 tulong)
                         (Etempvar _src64 tulong) tint)
            (Ssequence
              (Scall None
                (Evar _upd_pc (Tfunction
                                (Tcons (tptr (Tstruct _jit_state noattr))
                                  (Tcons tuint Tnil)) tvoid cc_default))
                ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                 (Ebinop Oadd (Etempvar _pc tuint) (Etempvar _ofs tuint)
                   tuint) :: nil))
              (Sreturn None))
            (Sreturn None))
          (LScons (Some 48)
            (Sifthenelse (Ebinop Oge (Etempvar _dst64 tulong)
                           (Etempvar _src64 tulong) tint)
              (Ssequence
                (Scall None
                  (Evar _upd_pc (Tfunction
                                  (Tcons (tptr (Tstruct _jit_state noattr))
                                    (Tcons tuint Tnil)) tvoid cc_default))
                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                   (Ebinop Oadd (Etempvar _pc tuint) (Etempvar _ofs tuint)
                     tuint) :: nil))
                (Sreturn None))
              (Sreturn None))
            (LScons (Some 160)
              (Sifthenelse (Ebinop Olt (Etempvar _dst64 tulong)
                             (Etempvar _src64 tulong) tint)
                (Ssequence
                  (Scall None
                    (Evar _upd_pc (Tfunction
                                    (Tcons (tptr (Tstruct _jit_state noattr))
                                      (Tcons tuint Tnil)) tvoid cc_default))
                    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                     (Ebinop Oadd (Etempvar _pc tuint) (Etempvar _ofs tuint)
                       tuint) :: nil))
                  (Sreturn None))
                (Sreturn None))
              (LScons (Some 176)
                (Sifthenelse (Ebinop Ole (Etempvar _dst64 tulong)
                               (Etempvar _src64 tulong) tint)
                  (Ssequence
                    (Scall None
                      (Evar _upd_pc (Tfunction
                                      (Tcons
                                        (tptr (Tstruct _jit_state noattr))
                                        (Tcons tuint Tnil)) tvoid cc_default))
                      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                       (Ebinop Oadd (Etempvar _pc tuint)
                         (Etempvar _ofs tuint) tuint) :: nil))
                    (Sreturn None))
                  (Sreturn None))
                (LScons (Some 64)
                  (Sifthenelse (Ebinop One
                                 (Ebinop Oand (Etempvar _dst64 tulong)
                                   (Etempvar _src64 tulong) tulong)
                                 (Econst_long (Int64.repr 0) tulong) tint)
                    (Ssequence
                      (Scall None
                        (Evar _upd_pc (Tfunction
                                        (Tcons
                                          (tptr (Tstruct _jit_state noattr))
                                          (Tcons tuint Tnil)) tvoid
                                        cc_default))
                        ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                         (Ebinop Oadd (Etempvar _pc tuint)
                           (Etempvar _ofs tuint) tuint) :: nil))
                      (Sreturn None))
                    (Sreturn None))
                  (LScons (Some 80)
                    (Sifthenelse (Ebinop One (Etempvar _dst64 tulong)
                                   (Etempvar _src64 tulong) tint)
                      (Ssequence
                        (Scall None
                          (Evar _upd_pc (Tfunction
                                          (Tcons
                                            (tptr (Tstruct _jit_state noattr))
                                            (Tcons tuint Tnil)) tvoid
                                          cc_default))
                          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                           (Ebinop Oadd (Etempvar _pc tuint)
                             (Etempvar _ofs tuint) tuint) :: nil))
                        (Sreturn None))
                      (Sreturn None))
                    (LScons (Some 96)
                      (Sifthenelse (Ebinop Ogt
                                     (Ecast (Etempvar _dst64 tulong) tlong)
                                     (Ecast (Etempvar _src64 tulong) tlong)
                                     tint)
                        (Ssequence
                          (Scall None
                            (Evar _upd_pc (Tfunction
                                            (Tcons
                                              (tptr (Tstruct _jit_state noattr))
                                              (Tcons tuint Tnil)) tvoid
                                            cc_default))
                            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                             (Ebinop Oadd (Etempvar _pc tuint)
                               (Etempvar _ofs tuint) tuint) :: nil))
                          (Sreturn None))
                        (Sreturn None))
                      (LScons (Some 112)
                        (Sifthenelse (Ebinop Oge
                                       (Ecast (Etempvar _dst64 tulong) tlong)
                                       (Ecast (Etempvar _src64 tulong) tlong)
                                       tint)
                          (Ssequence
                            (Scall None
                              (Evar _upd_pc (Tfunction
                                              (Tcons
                                                (tptr (Tstruct _jit_state noattr))
                                                (Tcons tuint Tnil)) tvoid
                                              cc_default))
                              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                               (Ebinop Oadd (Etempvar _pc tuint)
                                 (Etempvar _ofs tuint) tuint) :: nil))
                            (Sreturn None))
                          (Sreturn None))
                        (LScons (Some 192)
                          (Sifthenelse (Ebinop Olt
                                         (Ecast (Etempvar _dst64 tulong)
                                           tlong)
                                         (Ecast (Etempvar _src64 tulong)
                                           tlong) tint)
                            (Ssequence
                              (Scall None
                                (Evar _upd_pc (Tfunction
                                                (Tcons
                                                  (tptr (Tstruct _jit_state noattr))
                                                  (Tcons tuint Tnil)) tvoid
                                                cc_default))
                                ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                 (Ebinop Oadd (Etempvar _pc tuint)
                                   (Etempvar _ofs tuint) tuint) :: nil))
                              (Sreturn None))
                            (Sreturn None))
                          (LScons (Some 208)
                            (Sifthenelse (Ebinop Ole
                                           (Ecast (Etempvar _dst64 tulong)
                                             tlong)
                                           (Ecast (Etempvar _src64 tulong)
                                             tlong) tint)
                              (Ssequence
                                (Scall None
                                  (Evar _upd_pc (Tfunction
                                                  (Tcons
                                                    (tptr (Tstruct _jit_state noattr))
                                                    (Tcons tuint Tnil)) tvoid
                                                  cc_default))
                                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                   (Ebinop Oadd (Etempvar _pc tuint)
                                     (Etempvar _ofs tuint) tuint) :: nil))
                                (Sreturn None))
                              (Sreturn None))
                            (LScons (Some 128)
                              (Sifthenelse (Ebinop Oeq (Etempvar _op tuchar)
                                             (Econst_int (Int.repr 133) tint)
                                             tint)
                                (Ssequence
                                  (Ssequence
                                    (Scall (Some _t'2)
                                      (Evar __bpf_get_call (Tfunction
                                                             (Tcons tint
                                                               Tnil)
                                                             (tptr tuchar)
                                                             cc_default))
                                      ((Ecast (Etempvar _src64 tulong) tint) ::
                                       nil))
                                    (Sset _f_ptr
                                      (Etempvar _t'2 (tptr tuchar))))
                                  (Ssequence
                                    (Ssequence
                                      (Scall (Some _t'3)
                                        (Evar _cmp_ptr32_nullM (Tfunction
                                                                 (Tcons
                                                                   (tptr tuchar)
                                                                   Tnil)
                                                                 tbool
                                                                 cc_default))
                                        ((Etempvar _f_ptr (tptr tuchar)) ::
                                         nil))
                                      (Sset _is_null
                                        (Ecast (Etempvar _t'3 tbool) tbool)))
                                    (Sifthenelse (Etempvar _is_null tbool)
                                      (Ssequence
                                        (Scall None
                                          (Evar _upd_flag (Tfunction
                                                            (Tcons
                                                              (tptr (Tstruct _jit_state noattr))
                                                              (Tcons tuint
                                                                Tnil)) tvoid
                                                            cc_default))
                                          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                           (Econst_int (Int.repr 5) tuint) ::
                                           nil))
                                        (Sreturn None))
                                      (Ssequence
                                        (Ssequence
                                          (Scall (Some _t'4)
                                            (Evar _exec_function (Tfunction
                                                                   (Tcons
                                                                    (tptr (Tstruct _jit_state noattr))
                                                                    (Tcons
                                                                    (tptr tuchar)
                                                                    Tnil))
                                                                   tuint
                                                                   cc_default))
                                            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                             (Etempvar _f_ptr (tptr tuchar)) ::
                                             nil))
                                          (Sset _res (Etempvar _t'4 tuint)))
                                        (Ssequence
                                          (Scall None
                                            (Evar _upd_reg (Tfunction
                                                             (Tcons
                                                               (tptr (Tstruct _jit_state noattr))
                                                               (Tcons tuint
                                                                 (Tcons
                                                                   tulong
                                                                   Tnil)))
                                                             tvoid
                                                             cc_default))
                                            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                             (Econst_int (Int.repr 0) tuint) ::
                                             (Ecast (Etempvar _res tuint)
                                               tulong) :: nil))
                                          (Sreturn None))))))
                                (Ssequence
                                  (Scall None
                                    (Evar _upd_flag (Tfunction
                                                      (Tcons
                                                        (tptr (Tstruct _jit_state noattr))
                                                        (Tcons tuint Tnil))
                                                      tvoid cc_default))
                                    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                     (Econst_int (Int.repr 2) tuint) :: nil))
                                  (Sreturn None)))
                              (LScons (Some 144)
                                (Sifthenelse (Ebinop Oeq
                                               (Etempvar _op tuchar)
                                               (Econst_int (Int.repr 149) tint)
                                               tint)
                                  (Ssequence
                                    (Scall None
                                      (Evar _upd_flag (Tfunction
                                                        (Tcons
                                                          (tptr (Tstruct _jit_state noattr))
                                                          (Tcons tuint Tnil))
                                                        tvoid cc_default))
                                      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                       (Econst_int (Int.repr 1) tuint) ::
                                       nil))
                                    (Sreturn None))
                                  (Ssequence
                                    (Scall None
                                      (Evar _upd_flag (Tfunction
                                                        (Tcons
                                                          (tptr (Tstruct _jit_state noattr))
                                                          (Tcons tuint Tnil))
                                                        tvoid cc_default))
                                      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                       (Econst_int (Int.repr 2) tuint) ::
                                       nil))
                                    (Sreturn None)))
                                (LScons None
                                  (Ssequence
                                    (Scall None
                                      (Evar _upd_flag (Tfunction
                                                        (Tcons
                                                          (tptr (Tstruct _jit_state noattr))
                                                          (Tcons tuint Tnil))
                                                        tvoid cc_default))
                                      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                       (Econst_int (Int.repr 2) tuint) ::
                                       nil))
                                    (Sreturn None))
                                  LSnil)))))))))))))))))
|}.

Definition f_step_opcode_mem_ld_imm := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: (_imm, tint) ::
                (_dst64, tulong) :: (_dst, tuint) :: (_op, tuchar) :: nil);
  fn_vars := nil;
  fn_temps := ((_opcode_ld, tuchar) :: (_t'1, tuchar) :: nil);
  fn_body :=
(Ssequence
  (Ssequence
    (Scall (Some _t'1)
      (Evar _get_opcode_mem_ld_imm (Tfunction (Tcons tuchar Tnil) tuchar
                                     cc_default))
      ((Etempvar _op tuchar) :: nil))
    (Sset _opcode_ld (Ecast (Etempvar _t'1 tuchar) tuchar)))
  (Sswitch (Etempvar _opcode_ld tuchar)
    (LScons (Some 24)
      (Ssequence
        (Scall None
          (Evar _upd_reg (Tfunction
                           (Tcons (tptr (Tstruct _jit_state noattr))
                             (Tcons tuint (Tcons tulong Tnil))) tvoid
                           cc_default))
          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
           (Etempvar _dst tuint) ::
           (Ecast (Ecast (Etempvar _imm tint) tuint) tulong) :: nil))
        (Sreturn None))
      (LScons (Some 16)
        (Ssequence
          (Scall None
            (Evar _upd_reg (Tfunction
                             (Tcons (tptr (Tstruct _jit_state noattr))
                               (Tcons tuint (Tcons tulong Tnil))) tvoid
                             cc_default))
            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
             (Etempvar _dst tuint) ::
             (Ebinop Oor (Etempvar _dst64 tulong)
               (Ebinop Oshl (Ecast (Ecast (Etempvar _imm tint) tuint) tulong)
                 (Econst_int (Int.repr 32) tuint) tulong) tulong) :: nil))
          (Sreturn None))
        (LScons None
          (Ssequence
            (Scall None
              (Evar _upd_flag (Tfunction
                                (Tcons (tptr (Tstruct _jit_state noattr))
                                  (Tcons tuint Tnil)) tvoid cc_default))
              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
               (Econst_int (Int.repr 2) tuint) :: nil))
            (Sreturn None))
          LSnil)))))
|}.

Definition f_step_opcode_mem_ld_reg := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) ::
                (_addr, tuint) :: (_dst, tuint) :: (_op, tuchar) :: nil);
  fn_vars := nil;
  fn_temps := ((_opcode_ld, tuchar) :: (_addr_ptr, (tptr tuchar)) ::
               (_is_null, tbool) :: (_v, tulong) :: (_t'13, tulong) ::
               (_t'12, tbool) :: (_t'11, (tptr tuchar)) :: (_t'10, tulong) ::
               (_t'9, tbool) :: (_t'8, (tptr tuchar)) :: (_t'7, tulong) ::
               (_t'6, tbool) :: (_t'5, (tptr tuchar)) :: (_t'4, tulong) ::
               (_t'3, tbool) :: (_t'2, (tptr tuchar)) :: (_t'1, tuchar) ::
               nil);
  fn_body :=
(Ssequence
  (Ssequence
    (Scall (Some _t'1)
      (Evar _get_opcode_mem_ld_reg (Tfunction (Tcons tuchar Tnil) tuchar
                                     cc_default))
      ((Etempvar _op tuchar) :: nil))
    (Sset _opcode_ld (Ecast (Etempvar _t'1 tuchar) tuchar)))
  (Sswitch (Etempvar _opcode_ld tuchar)
    (LScons (Some 97)
      (Ssequence
        (Ssequence
          (Scall (Some _t'2)
            (Evar _check_mem (Tfunction
                               (Tcons (tptr (Tstruct _jit_state noattr))
                                 (Tcons tuint
                                   (Tcons tuint (Tcons tuint Tnil))))
                               (tptr tuchar) cc_default))
            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
             (Econst_int (Int.repr 1) tuint) ::
             (Econst_int (Int.repr 4) tuint) :: (Etempvar _addr tuint) ::
             nil))
          (Sset _addr_ptr (Etempvar _t'2 (tptr tuchar))))
        (Ssequence
          (Ssequence
            (Scall (Some _t'3)
              (Evar _cmp_ptr32_nullM (Tfunction (Tcons (tptr tuchar) Tnil)
                                       tbool cc_default))
              ((Etempvar _addr_ptr (tptr tuchar)) :: nil))
            (Sset _is_null (Ecast (Etempvar _t'3 tbool) tbool)))
          (Sifthenelse (Etempvar _is_null tbool)
            (Ssequence
              (Scall None
                (Evar _upd_flag (Tfunction
                                  (Tcons (tptr (Tstruct _jit_state noattr))
                                    (Tcons tuint Tnil)) tvoid cc_default))
                ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                 (Econst_int (Int.repr 3) tuint) :: nil))
              (Sreturn None))
            (Ssequence
              (Ssequence
                (Scall (Some _t'4)
                  (Evar _load_mem (Tfunction
                                    (Tcons (tptr (Tstruct _jit_state noattr))
                                      (Tcons tuint
                                        (Tcons (tptr tuchar) Tnil))) tulong
                                    cc_default))
                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                   (Econst_int (Int.repr 4) tuint) ::
                   (Etempvar _addr_ptr (tptr tuchar)) :: nil))
                (Sset _v (Etempvar _t'4 tulong)))
              (Ssequence
                (Scall None
                  (Evar _upd_reg (Tfunction
                                   (Tcons (tptr (Tstruct _jit_state noattr))
                                     (Tcons tuint (Tcons tulong Tnil))) tvoid
                                   cc_default))
                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                   (Etempvar _dst tuint) :: (Etempvar _v tulong) :: nil))
                (Sreturn None))))))
      (LScons (Some 105)
        (Ssequence
          (Ssequence
            (Scall (Some _t'5)
              (Evar _check_mem (Tfunction
                                 (Tcons (tptr (Tstruct _jit_state noattr))
                                   (Tcons tuint
                                     (Tcons tuint (Tcons tuint Tnil))))
                                 (tptr tuchar) cc_default))
              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
               (Econst_int (Int.repr 1) tuint) ::
               (Econst_int (Int.repr 2) tuint) :: (Etempvar _addr tuint) ::
               nil))
            (Sset _addr_ptr (Etempvar _t'5 (tptr tuchar))))
          (Ssequence
            (Ssequence
              (Scall (Some _t'6)
                (Evar _cmp_ptr32_nullM (Tfunction (Tcons (tptr tuchar) Tnil)
                                         tbool cc_default))
                ((Etempvar _addr_ptr (tptr tuchar)) :: nil))
              (Sset _is_null (Ecast (Etempvar _t'6 tbool) tbool)))
            (Sifthenelse (Etempvar _is_null tbool)
              (Ssequence
                (Scall None
                  (Evar _upd_flag (Tfunction
                                    (Tcons (tptr (Tstruct _jit_state noattr))
                                      (Tcons tuint Tnil)) tvoid cc_default))
                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                   (Econst_int (Int.repr 3) tuint) :: nil))
                (Sreturn None))
              (Ssequence
                (Ssequence
                  (Scall (Some _t'7)
                    (Evar _load_mem (Tfunction
                                      (Tcons
                                        (tptr (Tstruct _jit_state noattr))
                                        (Tcons tuint
                                          (Tcons (tptr tuchar) Tnil))) tulong
                                      cc_default))
                    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                     (Econst_int (Int.repr 2) tuint) ::
                     (Etempvar _addr_ptr (tptr tuchar)) :: nil))
                  (Sset _v (Etempvar _t'7 tulong)))
                (Ssequence
                  (Scall None
                    (Evar _upd_reg (Tfunction
                                     (Tcons
                                       (tptr (Tstruct _jit_state noattr))
                                       (Tcons tuint (Tcons tulong Tnil)))
                                     tvoid cc_default))
                    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                     (Etempvar _dst tuint) :: (Etempvar _v tulong) :: nil))
                  (Sreturn None))))))
        (LScons (Some 113)
          (Ssequence
            (Ssequence
              (Scall (Some _t'8)
                (Evar _check_mem (Tfunction
                                   (Tcons (tptr (Tstruct _jit_state noattr))
                                     (Tcons tuint
                                       (Tcons tuint (Tcons tuint Tnil))))
                                   (tptr tuchar) cc_default))
                ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                 (Econst_int (Int.repr 1) tuint) ::
                 (Econst_int (Int.repr 1) tuint) :: (Etempvar _addr tuint) ::
                 nil))
              (Sset _addr_ptr (Etempvar _t'8 (tptr tuchar))))
            (Ssequence
              (Ssequence
                (Scall (Some _t'9)
                  (Evar _cmp_ptr32_nullM (Tfunction
                                           (Tcons (tptr tuchar) Tnil) tbool
                                           cc_default))
                  ((Etempvar _addr_ptr (tptr tuchar)) :: nil))
                (Sset _is_null (Ecast (Etempvar _t'9 tbool) tbool)))
              (Sifthenelse (Etempvar _is_null tbool)
                (Ssequence
                  (Scall None
                    (Evar _upd_flag (Tfunction
                                      (Tcons
                                        (tptr (Tstruct _jit_state noattr))
                                        (Tcons tuint Tnil)) tvoid cc_default))
                    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                     (Econst_int (Int.repr 3) tuint) :: nil))
                  (Sreturn None))
                (Ssequence
                  (Ssequence
                    (Scall (Some _t'10)
                      (Evar _load_mem (Tfunction
                                        (Tcons
                                          (tptr (Tstruct _jit_state noattr))
                                          (Tcons tuint
                                            (Tcons (tptr tuchar) Tnil)))
                                        tulong cc_default))
                      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                       (Econst_int (Int.repr 1) tuint) ::
                       (Etempvar _addr_ptr (tptr tuchar)) :: nil))
                    (Sset _v (Etempvar _t'10 tulong)))
                  (Ssequence
                    (Scall None
                      (Evar _upd_reg (Tfunction
                                       (Tcons
                                         (tptr (Tstruct _jit_state noattr))
                                         (Tcons tuint (Tcons tulong Tnil)))
                                       tvoid cc_default))
                      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                       (Etempvar _dst tuint) :: (Etempvar _v tulong) :: nil))
                    (Sreturn None))))))
          (LScons (Some 121)
            (Ssequence
              (Ssequence
                (Scall (Some _t'11)
                  (Evar _check_mem (Tfunction
                                     (Tcons
                                       (tptr (Tstruct _jit_state noattr))
                                       (Tcons tuint
                                         (Tcons tuint (Tcons tuint Tnil))))
                                     (tptr tuchar) cc_default))
                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                   (Econst_int (Int.repr 1) tuint) ::
                   (Econst_int (Int.repr 8) tuint) ::
                   (Etempvar _addr tuint) :: nil))
                (Sset _addr_ptr (Etempvar _t'11 (tptr tuchar))))
              (Ssequence
                (Ssequence
                  (Scall (Some _t'12)
                    (Evar _cmp_ptr32_nullM (Tfunction
                                             (Tcons (tptr tuchar) Tnil) tbool
                                             cc_default))
                    ((Etempvar _addr_ptr (tptr tuchar)) :: nil))
                  (Sset _is_null (Ecast (Etempvar _t'12 tbool) tbool)))
                (Sifthenelse (Etempvar _is_null tbool)
                  (Ssequence
                    (Scall None
                      (Evar _upd_flag (Tfunction
                                        (Tcons
                                          (tptr (Tstruct _jit_state noattr))
                                          (Tcons tuint Tnil)) tvoid
                                        cc_default))
                      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                       (Econst_int (Int.repr 3) tuint) :: nil))
                    (Sreturn None))
                  (Ssequence
                    (Ssequence
                      (Scall (Some _t'13)
                        (Evar _load_mem (Tfunction
                                          (Tcons
                                            (tptr (Tstruct _jit_state noattr))
                                            (Tcons tuint
                                              (Tcons (tptr tuchar) Tnil)))
                                          tulong cc_default))
                        ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                         (Econst_int (Int.repr 8) tuint) ::
                         (Etempvar _addr_ptr (tptr tuchar)) :: nil))
                      (Sset _v (Etempvar _t'13 tulong)))
                    (Ssequence
                      (Scall None
                        (Evar _upd_reg (Tfunction
                                         (Tcons
                                           (tptr (Tstruct _jit_state noattr))
                                           (Tcons tuint (Tcons tulong Tnil)))
                                         tvoid cc_default))
                        ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                         (Etempvar _dst tuint) :: (Etempvar _v tulong) ::
                         nil))
                      (Sreturn None))))))
            (LScons None
              (Ssequence
                (Scall None
                  (Evar _upd_flag (Tfunction
                                    (Tcons (tptr (Tstruct _jit_state noattr))
                                      (Tcons tuint Tnil)) tvoid cc_default))
                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                   (Econst_int (Int.repr 2) tuint) :: nil))
                (Sreturn None))
              LSnil)))))))
|}.

Definition f_step_opcode_mem_st_imm := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: (_imm, tint) ::
                (_addr, tuint) :: (_op, tuchar) :: nil);
  fn_vars := nil;
  fn_temps := ((_opcode_st, tuchar) :: (_addr_ptr, (tptr tuchar)) ::
               (_is_null, tbool) :: (_t'9, tbool) :: (_t'8, (tptr tuchar)) ::
               (_t'7, tbool) :: (_t'6, (tptr tuchar)) :: (_t'5, tbool) ::
               (_t'4, (tptr tuchar)) :: (_t'3, tbool) ::
               (_t'2, (tptr tuchar)) :: (_t'1, tuchar) :: nil);
  fn_body :=
(Ssequence
  (Ssequence
    (Scall (Some _t'1)
      (Evar _get_opcode_mem_st_imm (Tfunction (Tcons tuchar Tnil) tuchar
                                     cc_default))
      ((Etempvar _op tuchar) :: nil))
    (Sset _opcode_st (Ecast (Etempvar _t'1 tuchar) tuchar)))
  (Sswitch (Etempvar _opcode_st tuchar)
    (LScons (Some 98)
      (Ssequence
        (Ssequence
          (Scall (Some _t'2)
            (Evar _check_mem (Tfunction
                               (Tcons (tptr (Tstruct _jit_state noattr))
                                 (Tcons tuint
                                   (Tcons tuint (Tcons tuint Tnil))))
                               (tptr tuchar) cc_default))
            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
             (Econst_int (Int.repr 2) tuint) ::
             (Econst_int (Int.repr 4) tuint) :: (Etempvar _addr tuint) ::
             nil))
          (Sset _addr_ptr (Etempvar _t'2 (tptr tuchar))))
        (Ssequence
          (Ssequence
            (Scall (Some _t'3)
              (Evar _cmp_ptr32_nullM (Tfunction (Tcons (tptr tuchar) Tnil)
                                       tbool cc_default))
              ((Etempvar _addr_ptr (tptr tuchar)) :: nil))
            (Sset _is_null (Ecast (Etempvar _t'3 tbool) tbool)))
          (Sifthenelse (Etempvar _is_null tbool)
            (Ssequence
              (Scall None
                (Evar _upd_flag (Tfunction
                                  (Tcons (tptr (Tstruct _jit_state noattr))
                                    (Tcons tuint Tnil)) tvoid cc_default))
                ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                 (Econst_int (Int.repr 3) tuint) :: nil))
              (Sreturn None))
            (Ssequence
              (Scall None
                (Evar _store_mem_imm (Tfunction
                                       (Tcons
                                         (tptr (Tstruct _jit_state noattr))
                                         (Tcons (tptr tuchar)
                                           (Tcons tuint (Tcons tint Tnil))))
                                       tvoid cc_default))
                ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                 (Etempvar _addr_ptr (tptr tuchar)) ::
                 (Econst_int (Int.repr 4) tuint) :: (Etempvar _imm tint) ::
                 nil))
              (Sreturn None)))))
      (LScons (Some 106)
        (Ssequence
          (Ssequence
            (Scall (Some _t'4)
              (Evar _check_mem (Tfunction
                                 (Tcons (tptr (Tstruct _jit_state noattr))
                                   (Tcons tuint
                                     (Tcons tuint (Tcons tuint Tnil))))
                                 (tptr tuchar) cc_default))
              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
               (Econst_int (Int.repr 2) tuint) ::
               (Econst_int (Int.repr 2) tuint) :: (Etempvar _addr tuint) ::
               nil))
            (Sset _addr_ptr (Etempvar _t'4 (tptr tuchar))))
          (Ssequence
            (Ssequence
              (Scall (Some _t'5)
                (Evar _cmp_ptr32_nullM (Tfunction (Tcons (tptr tuchar) Tnil)
                                         tbool cc_default))
                ((Etempvar _addr_ptr (tptr tuchar)) :: nil))
              (Sset _is_null (Ecast (Etempvar _t'5 tbool) tbool)))
            (Sifthenelse (Etempvar _is_null tbool)
              (Ssequence
                (Scall None
                  (Evar _upd_flag (Tfunction
                                    (Tcons (tptr (Tstruct _jit_state noattr))
                                      (Tcons tuint Tnil)) tvoid cc_default))
                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                   (Econst_int (Int.repr 3) tuint) :: nil))
                (Sreturn None))
              (Ssequence
                (Scall None
                  (Evar _store_mem_imm (Tfunction
                                         (Tcons
                                           (tptr (Tstruct _jit_state noattr))
                                           (Tcons (tptr tuchar)
                                             (Tcons tuint (Tcons tint Tnil))))
                                         tvoid cc_default))
                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                   (Etempvar _addr_ptr (tptr tuchar)) ::
                   (Econst_int (Int.repr 2) tuint) :: (Etempvar _imm tint) ::
                   nil))
                (Sreturn None)))))
        (LScons (Some 114)
          (Ssequence
            (Ssequence
              (Scall (Some _t'6)
                (Evar _check_mem (Tfunction
                                   (Tcons (tptr (Tstruct _jit_state noattr))
                                     (Tcons tuint
                                       (Tcons tuint (Tcons tuint Tnil))))
                                   (tptr tuchar) cc_default))
                ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                 (Econst_int (Int.repr 2) tuint) ::
                 (Econst_int (Int.repr 1) tuint) :: (Etempvar _addr tuint) ::
                 nil))
              (Sset _addr_ptr (Etempvar _t'6 (tptr tuchar))))
            (Ssequence
              (Ssequence
                (Scall (Some _t'7)
                  (Evar _cmp_ptr32_nullM (Tfunction
                                           (Tcons (tptr tuchar) Tnil) tbool
                                           cc_default))
                  ((Etempvar _addr_ptr (tptr tuchar)) :: nil))
                (Sset _is_null (Ecast (Etempvar _t'7 tbool) tbool)))
              (Sifthenelse (Etempvar _is_null tbool)
                (Ssequence
                  (Scall None
                    (Evar _upd_flag (Tfunction
                                      (Tcons
                                        (tptr (Tstruct _jit_state noattr))
                                        (Tcons tuint Tnil)) tvoid cc_default))
                    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                     (Econst_int (Int.repr 3) tuint) :: nil))
                  (Sreturn None))
                (Ssequence
                  (Scall None
                    (Evar _store_mem_imm (Tfunction
                                           (Tcons
                                             (tptr (Tstruct _jit_state noattr))
                                             (Tcons (tptr tuchar)
                                               (Tcons tuint
                                                 (Tcons tint Tnil)))) tvoid
                                           cc_default))
                    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                     (Etempvar _addr_ptr (tptr tuchar)) ::
                     (Econst_int (Int.repr 1) tuint) ::
                     (Etempvar _imm tint) :: nil))
                  (Sreturn None)))))
          (LScons (Some 122)
            (Ssequence
              (Ssequence
                (Scall (Some _t'8)
                  (Evar _check_mem (Tfunction
                                     (Tcons
                                       (tptr (Tstruct _jit_state noattr))
                                       (Tcons tuint
                                         (Tcons tuint (Tcons tuint Tnil))))
                                     (tptr tuchar) cc_default))
                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                   (Econst_int (Int.repr 2) tuint) ::
                   (Econst_int (Int.repr 8) tuint) ::
                   (Etempvar _addr tuint) :: nil))
                (Sset _addr_ptr (Etempvar _t'8 (tptr tuchar))))
              (Ssequence
                (Ssequence
                  (Scall (Some _t'9)
                    (Evar _cmp_ptr32_nullM (Tfunction
                                             (Tcons (tptr tuchar) Tnil) tbool
                                             cc_default))
                    ((Etempvar _addr_ptr (tptr tuchar)) :: nil))
                  (Sset _is_null (Ecast (Etempvar _t'9 tbool) tbool)))
                (Sifthenelse (Etempvar _is_null tbool)
                  (Ssequence
                    (Scall None
                      (Evar _upd_flag (Tfunction
                                        (Tcons
                                          (tptr (Tstruct _jit_state noattr))
                                          (Tcons tuint Tnil)) tvoid
                                        cc_default))
                      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                       (Econst_int (Int.repr 3) tuint) :: nil))
                    (Sreturn None))
                  (Ssequence
                    (Scall None
                      (Evar _store_mem_imm (Tfunction
                                             (Tcons
                                               (tptr (Tstruct _jit_state noattr))
                                               (Tcons (tptr tuchar)
                                                 (Tcons tuint
                                                   (Tcons tint Tnil)))) tvoid
                                             cc_default))
                      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                       (Etempvar _addr_ptr (tptr tuchar)) ::
                       (Econst_int (Int.repr 8) tuint) ::
                       (Etempvar _imm tint) :: nil))
                    (Sreturn None)))))
            (LScons None
              (Ssequence
                (Scall None
                  (Evar _upd_flag (Tfunction
                                    (Tcons (tptr (Tstruct _jit_state noattr))
                                      (Tcons tuint Tnil)) tvoid cc_default))
                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                   (Econst_int (Int.repr 2) tuint) :: nil))
                (Sreturn None))
              LSnil)))))))
|}.

Definition f_step_opcode_mem_st_reg := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) ::
                (_src64, tulong) :: (_addr, tuint) :: (_op, tuchar) :: nil);
  fn_vars := nil;
  fn_temps := ((_opcode_st, tuchar) :: (_addr_ptr, (tptr tuchar)) ::
               (_is_null, tbool) :: (_t'9, tbool) :: (_t'8, (tptr tuchar)) ::
               (_t'7, tbool) :: (_t'6, (tptr tuchar)) :: (_t'5, tbool) ::
               (_t'4, (tptr tuchar)) :: (_t'3, tbool) ::
               (_t'2, (tptr tuchar)) :: (_t'1, tuchar) :: nil);
  fn_body :=
(Ssequence
  (Ssequence
    (Scall (Some _t'1)
      (Evar _get_opcode_mem_st_reg (Tfunction (Tcons tuchar Tnil) tuchar
                                     cc_default))
      ((Etempvar _op tuchar) :: nil))
    (Sset _opcode_st (Ecast (Etempvar _t'1 tuchar) tuchar)))
  (Sswitch (Etempvar _opcode_st tuchar)
    (LScons (Some 99)
      (Ssequence
        (Ssequence
          (Scall (Some _t'2)
            (Evar _check_mem (Tfunction
                               (Tcons (tptr (Tstruct _jit_state noattr))
                                 (Tcons tuint
                                   (Tcons tuint (Tcons tuint Tnil))))
                               (tptr tuchar) cc_default))
            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
             (Econst_int (Int.repr 2) tuint) ::
             (Econst_int (Int.repr 4) tuint) :: (Etempvar _addr tuint) ::
             nil))
          (Sset _addr_ptr (Etempvar _t'2 (tptr tuchar))))
        (Ssequence
          (Ssequence
            (Scall (Some _t'3)
              (Evar _cmp_ptr32_nullM (Tfunction (Tcons (tptr tuchar) Tnil)
                                       tbool cc_default))
              ((Etempvar _addr_ptr (tptr tuchar)) :: nil))
            (Sset _is_null (Ecast (Etempvar _t'3 tbool) tbool)))
          (Sifthenelse (Etempvar _is_null tbool)
            (Ssequence
              (Scall None
                (Evar _upd_flag (Tfunction
                                  (Tcons (tptr (Tstruct _jit_state noattr))
                                    (Tcons tuint Tnil)) tvoid cc_default))
                ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                 (Econst_int (Int.repr 3) tuint) :: nil))
              (Sreturn None))
            (Ssequence
              (Scall None
                (Evar _store_mem_reg (Tfunction
                                       (Tcons
                                         (tptr (Tstruct _jit_state noattr))
                                         (Tcons (tptr tuchar)
                                           (Tcons tuint (Tcons tulong Tnil))))
                                       tvoid cc_default))
                ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                 (Etempvar _addr_ptr (tptr tuchar)) ::
                 (Econst_int (Int.repr 4) tuint) ::
                 (Etempvar _src64 tulong) :: nil))
              (Sreturn None)))))
      (LScons (Some 107)
        (Ssequence
          (Ssequence
            (Scall (Some _t'4)
              (Evar _check_mem (Tfunction
                                 (Tcons (tptr (Tstruct _jit_state noattr))
                                   (Tcons tuint
                                     (Tcons tuint (Tcons tuint Tnil))))
                                 (tptr tuchar) cc_default))
              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
               (Econst_int (Int.repr 2) tuint) ::
               (Econst_int (Int.repr 2) tuint) :: (Etempvar _addr tuint) ::
               nil))
            (Sset _addr_ptr (Etempvar _t'4 (tptr tuchar))))
          (Ssequence
            (Ssequence
              (Scall (Some _t'5)
                (Evar _cmp_ptr32_nullM (Tfunction (Tcons (tptr tuchar) Tnil)
                                         tbool cc_default))
                ((Etempvar _addr_ptr (tptr tuchar)) :: nil))
              (Sset _is_null (Ecast (Etempvar _t'5 tbool) tbool)))
            (Sifthenelse (Etempvar _is_null tbool)
              (Ssequence
                (Scall None
                  (Evar _upd_flag (Tfunction
                                    (Tcons (tptr (Tstruct _jit_state noattr))
                                      (Tcons tuint Tnil)) tvoid cc_default))
                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                   (Econst_int (Int.repr 3) tuint) :: nil))
                (Sreturn None))
              (Ssequence
                (Scall None
                  (Evar _store_mem_reg (Tfunction
                                         (Tcons
                                           (tptr (Tstruct _jit_state noattr))
                                           (Tcons (tptr tuchar)
                                             (Tcons tuint
                                               (Tcons tulong Tnil)))) tvoid
                                         cc_default))
                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                   (Etempvar _addr_ptr (tptr tuchar)) ::
                   (Econst_int (Int.repr 2) tuint) ::
                   (Etempvar _src64 tulong) :: nil))
                (Sreturn None)))))
        (LScons (Some 115)
          (Ssequence
            (Ssequence
              (Scall (Some _t'6)
                (Evar _check_mem (Tfunction
                                   (Tcons (tptr (Tstruct _jit_state noattr))
                                     (Tcons tuint
                                       (Tcons tuint (Tcons tuint Tnil))))
                                   (tptr tuchar) cc_default))
                ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                 (Econst_int (Int.repr 2) tuint) ::
                 (Econst_int (Int.repr 1) tuint) :: (Etempvar _addr tuint) ::
                 nil))
              (Sset _addr_ptr (Etempvar _t'6 (tptr tuchar))))
            (Ssequence
              (Ssequence
                (Scall (Some _t'7)
                  (Evar _cmp_ptr32_nullM (Tfunction
                                           (Tcons (tptr tuchar) Tnil) tbool
                                           cc_default))
                  ((Etempvar _addr_ptr (tptr tuchar)) :: nil))
                (Sset _is_null (Ecast (Etempvar _t'7 tbool) tbool)))
              (Sifthenelse (Etempvar _is_null tbool)
                (Ssequence
                  (Scall None
                    (Evar _upd_flag (Tfunction
                                      (Tcons
                                        (tptr (Tstruct _jit_state noattr))
                                        (Tcons tuint Tnil)) tvoid cc_default))
                    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                     (Econst_int (Int.repr 3) tuint) :: nil))
                  (Sreturn None))
                (Ssequence
                  (Scall None
                    (Evar _store_mem_reg (Tfunction
                                           (Tcons
                                             (tptr (Tstruct _jit_state noattr))
                                             (Tcons (tptr tuchar)
                                               (Tcons tuint
                                                 (Tcons tulong Tnil)))) tvoid
                                           cc_default))
                    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                     (Etempvar _addr_ptr (tptr tuchar)) ::
                     (Econst_int (Int.repr 1) tuint) ::
                     (Etempvar _src64 tulong) :: nil))
                  (Sreturn None)))))
          (LScons (Some 123)
            (Ssequence
              (Ssequence
                (Scall (Some _t'8)
                  (Evar _check_mem (Tfunction
                                     (Tcons
                                       (tptr (Tstruct _jit_state noattr))
                                       (Tcons tuint
                                         (Tcons tuint (Tcons tuint Tnil))))
                                     (tptr tuchar) cc_default))
                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                   (Econst_int (Int.repr 2) tuint) ::
                   (Econst_int (Int.repr 8) tuint) ::
                   (Etempvar _addr tuint) :: nil))
                (Sset _addr_ptr (Etempvar _t'8 (tptr tuchar))))
              (Ssequence
                (Ssequence
                  (Scall (Some _t'9)
                    (Evar _cmp_ptr32_nullM (Tfunction
                                             (Tcons (tptr tuchar) Tnil) tbool
                                             cc_default))
                    ((Etempvar _addr_ptr (tptr tuchar)) :: nil))
                  (Sset _is_null (Ecast (Etempvar _t'9 tbool) tbool)))
                (Sifthenelse (Etempvar _is_null tbool)
                  (Ssequence
                    (Scall None
                      (Evar _upd_flag (Tfunction
                                        (Tcons
                                          (tptr (Tstruct _jit_state noattr))
                                          (Tcons tuint Tnil)) tvoid
                                        cc_default))
                      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                       (Econst_int (Int.repr 3) tuint) :: nil))
                    (Sreturn None))
                  (Ssequence
                    (Scall None
                      (Evar _store_mem_reg (Tfunction
                                             (Tcons
                                               (tptr (Tstruct _jit_state noattr))
                                               (Tcons (tptr tuchar)
                                                 (Tcons tuint
                                                   (Tcons tulong Tnil))))
                                             tvoid cc_default))
                      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                       (Etempvar _addr_ptr (tptr tuchar)) ::
                       (Econst_int (Int.repr 8) tuint) ::
                       (Etempvar _src64 tulong) :: nil))
                    (Sreturn None)))))
            (LScons None
              (Ssequence
                (Scall None
                  (Evar _upd_flag (Tfunction
                                    (Tcons (tptr (Tstruct _jit_state noattr))
                                      (Tcons tuint Tnil)) tvoid cc_default))
                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                   (Econst_int (Int.repr 2) tuint) :: nil))
                (Sreturn None))
              LSnil)))))))
|}.

Definition f_step := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) :: nil);
  fn_vars := nil;
  fn_temps := ((_pc, tuint) :: (_ins, tulong) :: (_op, tuchar) ::
               (_opc, tuchar) :: (_dst, tuint) :: (_dst64, tulong) ::
               (_src64, tulong) :: (_ofs, tint) :: (_imm, tint) ::
               (_src, tuint) :: (_addr, tuint) :: (_t'25, tuint) ::
               (_t'24, tint) :: (_t'23, tulong) :: (_t'22, tuint) ::
               (_t'21, tulong) :: (_t'20, tuint) :: (_t'19, tint) ::
               (_t'18, tint) :: (_t'17, tulong) :: (_t'16, tuint) ::
               (_t'15, tint) :: (_t'14, tulong) :: (_t'13, tuint) ::
               (_t'12, tint) :: (_t'11, tulong) :: (_t'10, tulong) ::
               (_t'9, tint) :: (_t'8, tulong) :: (_t'7, tulong) ::
               (_t'6, tulong) :: (_t'5, tuint) :: (_t'4, tuchar) ::
               (_t'3, tuchar) :: (_t'2, tulong) :: (_t'1, tuint) :: nil);
  fn_body :=
(Ssequence
  (Ssequence
    (Scall (Some _t'1)
      (Evar _eval_pc (Tfunction
                       (Tcons (tptr (Tstruct _jit_state noattr)) Tnil) tuint
                       cc_default))
      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) :: nil))
    (Sset _pc (Etempvar _t'1 tuint)))
  (Ssequence
    (Ssequence
      (Scall (Some _t'2)
        (Evar _eval_ins (Tfunction
                          (Tcons (tptr (Tstruct _jit_state noattr))
                            (Tcons tuint Tnil)) tulong cc_default))
        ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
         (Etempvar _pc tuint) :: nil))
      (Sset _ins (Etempvar _t'2 tulong)))
    (Ssequence
      (Ssequence
        (Scall (Some _t'3)
          (Evar _get_opcode_ins (Tfunction (Tcons tulong Tnil) tuchar
                                  cc_default))
          ((Etempvar _ins tulong) :: nil))
        (Sset _op (Ecast (Etempvar _t'3 tuchar) tuchar)))
      (Ssequence
        (Ssequence
          (Scall (Some _t'4)
            (Evar _get_opcode (Tfunction (Tcons tuchar Tnil) tuchar
                                cc_default)) ((Etempvar _op tuchar) :: nil))
          (Sset _opc (Ecast (Etempvar _t'4 tuchar) tuchar)))
        (Ssequence
          (Ssequence
            (Scall (Some _t'5)
              (Evar _get_dst (Tfunction (Tcons tulong Tnil) tuint cc_default))
              ((Etempvar _ins tulong) :: nil))
            (Sset _dst (Etempvar _t'5 tuint)))
          (Sswitch (Etempvar _opc tuchar)
            (LScons (Some 7)
              (Ssequence
                (Ssequence
                  (Scall (Some _t'6)
                    (Evar _eval_reg (Tfunction
                                      (Tcons
                                        (tptr (Tstruct _jit_state noattr))
                                        (Tcons tuint Tnil)) tulong
                                      cc_default))
                    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                     (Etempvar _dst tuint) :: nil))
                  (Sset _dst64 (Etempvar _t'6 tulong)))
                (Ssequence
                  (Ssequence
                    (Scall (Some _t'7)
                      (Evar _get_src64 (Tfunction
                                         (Tcons
                                           (tptr (Tstruct _jit_state noattr))
                                           (Tcons tuchar (Tcons tulong Tnil)))
                                         tulong cc_default))
                      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                       (Etempvar _op tuchar) :: (Etempvar _ins tulong) ::
                       nil))
                    (Sset _src64 (Etempvar _t'7 tulong)))
                  (Ssequence
                    (Scall None
                      (Evar _step_opcode_alu64 (Tfunction
                                                 (Tcons
                                                   (tptr (Tstruct _jit_state noattr))
                                                   (Tcons tulong
                                                     (Tcons tulong
                                                       (Tcons tuint
                                                         (Tcons tuchar Tnil)))))
                                                 tvoid cc_default))
                      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                       (Etempvar _dst64 tulong) ::
                       (Etempvar _src64 tulong) :: (Etempvar _dst tuint) ::
                       (Etempvar _op tuchar) :: nil))
                    (Sreturn None))))
              (LScons (Some 4)
                (Ssequence
                  (Scall None
                    (Evar _step_opcode_alu32 (Tfunction
                                               (Tcons
                                                 (tptr (Tstruct _jit_state noattr))
                                                 (Tcons tuchar
                                                   (Tcons tuint Tnil))) tvoid
                                               cc_default))
                    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                     (Etempvar _op tuchar) :: (Etempvar _pc tuint) :: nil))
                  (Sreturn None))
                (LScons (Some 5)
                  (Ssequence
                    (Ssequence
                      (Scall (Some _t'8)
                        (Evar _eval_reg (Tfunction
                                          (Tcons
                                            (tptr (Tstruct _jit_state noattr))
                                            (Tcons tuint Tnil)) tulong
                                          cc_default))
                        ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                         (Etempvar _dst tuint) :: nil))
                      (Sset _dst64 (Etempvar _t'8 tulong)))
                    (Ssequence
                      (Ssequence
                        (Scall (Some _t'9)
                          (Evar _get_offset (Tfunction (Tcons tulong Tnil)
                                              tint cc_default))
                          ((Etempvar _ins tulong) :: nil))
                        (Sset _ofs (Etempvar _t'9 tint)))
                      (Ssequence
                        (Ssequence
                          (Scall (Some _t'10)
                            (Evar _get_src64 (Tfunction
                                               (Tcons
                                                 (tptr (Tstruct _jit_state noattr))
                                                 (Tcons tuchar
                                                   (Tcons tulong Tnil)))
                                               tulong cc_default))
                            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                             (Etempvar _op tuchar) ::
                             (Etempvar _ins tulong) :: nil))
                          (Sset _src64 (Etempvar _t'10 tulong)))
                        (Ssequence
                          (Scall None
                            (Evar _step_opcode_branch (Tfunction
                                                        (Tcons
                                                          (tptr (Tstruct _jit_state noattr))
                                                          (Tcons tulong
                                                            (Tcons tulong
                                                              (Tcons tuint
                                                                (Tcons tuint
                                                                  (Tcons
                                                                    tuchar
                                                                    Tnil))))))
                                                        tvoid cc_default))
                            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                             (Etempvar _dst64 tulong) ::
                             (Etempvar _src64 tulong) ::
                             (Etempvar _pc tuint) ::
                             (Ecast (Etempvar _ofs tint) tuint) ::
                             (Etempvar _op tuchar) :: nil))
                          (Sreturn None)))))
                  (LScons (Some 0)
                    (Ssequence
                      (Ssequence
                        (Scall (Some _t'11)
                          (Evar _eval_reg (Tfunction
                                            (Tcons
                                              (tptr (Tstruct _jit_state noattr))
                                              (Tcons tuint Tnil)) tulong
                                            cc_default))
                          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                           (Etempvar _dst tuint) :: nil))
                        (Sset _dst64 (Etempvar _t'11 tulong)))
                      (Ssequence
                        (Ssequence
                          (Scall (Some _t'12)
                            (Evar _get_immediate (Tfunction
                                                   (Tcons tulong Tnil) tint
                                                   cc_default))
                            ((Etempvar _ins tulong) :: nil))
                          (Sset _imm (Etempvar _t'12 tint)))
                        (Ssequence
                          (Scall None
                            (Evar _step_opcode_mem_ld_imm (Tfunction
                                                            (Tcons
                                                              (tptr (Tstruct _jit_state noattr))
                                                              (Tcons tint
                                                                (Tcons tulong
                                                                  (Tcons
                                                                    tuint
                                                                    (Tcons
                                                                    tuchar
                                                                    Tnil)))))
                                                            tvoid cc_default))
                            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                             (Etempvar _imm tint) ::
                             (Etempvar _dst64 tulong) ::
                             (Etempvar _dst tuint) ::
                             (Etempvar _op tuchar) :: nil))
                          (Sreturn None))))
                    (LScons (Some 1)
                      (Ssequence
                        (Ssequence
                          (Scall (Some _t'13)
                            (Evar _get_src (Tfunction (Tcons tulong Tnil)
                                             tuint cc_default))
                            ((Etempvar _ins tulong) :: nil))
                          (Sset _src (Etempvar _t'13 tuint)))
                        (Ssequence
                          (Ssequence
                            (Scall (Some _t'14)
                              (Evar _eval_reg (Tfunction
                                                (Tcons
                                                  (tptr (Tstruct _jit_state noattr))
                                                  (Tcons tuint Tnil)) tulong
                                                cc_default))
                              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                               (Etempvar _src tuint) :: nil))
                            (Sset _src64 (Etempvar _t'14 tulong)))
                          (Ssequence
                            (Ssequence
                              (Scall (Some _t'15)
                                (Evar _get_offset (Tfunction
                                                    (Tcons tulong Tnil) tint
                                                    cc_default))
                                ((Etempvar _ins tulong) :: nil))
                              (Sset _ofs (Etempvar _t'15 tint)))
                            (Ssequence
                              (Ssequence
                                (Scall (Some _t'16)
                                  (Evar _get_addr_ofs (Tfunction
                                                        (Tcons tulong
                                                          (Tcons tint Tnil))
                                                        tuint cc_default))
                                  ((Etempvar _src64 tulong) ::
                                   (Etempvar _ofs tint) :: nil))
                                (Sset _addr (Etempvar _t'16 tuint)))
                              (Ssequence
                                (Scall None
                                  (Evar _step_opcode_mem_ld_reg (Tfunction
                                                                  (Tcons
                                                                    (tptr (Tstruct _jit_state noattr))
                                                                    (Tcons
                                                                    tuint
                                                                    (Tcons
                                                                    tuint
                                                                    (Tcons
                                                                    tuchar
                                                                    Tnil))))
                                                                  tvoid
                                                                  cc_default))
                                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                   (Etempvar _addr tuint) ::
                                   (Etempvar _dst tuint) ::
                                   (Etempvar _op tuchar) :: nil))
                                (Sreturn None))))))
                      (LScons (Some 2)
                        (Ssequence
                          (Ssequence
                            (Scall (Some _t'17)
                              (Evar _eval_reg (Tfunction
                                                (Tcons
                                                  (tptr (Tstruct _jit_state noattr))
                                                  (Tcons tuint Tnil)) tulong
                                                cc_default))
                              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                               (Etempvar _dst tuint) :: nil))
                            (Sset _dst64 (Etempvar _t'17 tulong)))
                          (Ssequence
                            (Ssequence
                              (Scall (Some _t'18)
                                (Evar _get_offset (Tfunction
                                                    (Tcons tulong Tnil) tint
                                                    cc_default))
                                ((Etempvar _ins tulong) :: nil))
                              (Sset _ofs (Etempvar _t'18 tint)))
                            (Ssequence
                              (Ssequence
                                (Scall (Some _t'19)
                                  (Evar _get_immediate (Tfunction
                                                         (Tcons tulong Tnil)
                                                         tint cc_default))
                                  ((Etempvar _ins tulong) :: nil))
                                (Sset _imm (Etempvar _t'19 tint)))
                              (Ssequence
                                (Ssequence
                                  (Scall (Some _t'20)
                                    (Evar _get_addr_ofs (Tfunction
                                                          (Tcons tulong
                                                            (Tcons tint Tnil))
                                                          tuint cc_default))
                                    ((Etempvar _dst64 tulong) ::
                                     (Etempvar _ofs tint) :: nil))
                                  (Sset _addr (Etempvar _t'20 tuint)))
                                (Ssequence
                                  (Scall None
                                    (Evar _step_opcode_mem_st_imm (Tfunction
                                                                    (Tcons
                                                                    (tptr (Tstruct _jit_state noattr))
                                                                    (Tcons
                                                                    tint
                                                                    (Tcons
                                                                    tuint
                                                                    (Tcons
                                                                    tuchar
                                                                    Tnil))))
                                                                    tvoid
                                                                    cc_default))
                                    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                     (Etempvar _imm tint) ::
                                     (Etempvar _addr tuint) ::
                                     (Etempvar _op tuchar) :: nil))
                                  (Sreturn None))))))
                        (LScons (Some 3)
                          (Ssequence
                            (Ssequence
                              (Scall (Some _t'21)
                                (Evar _eval_reg (Tfunction
                                                  (Tcons
                                                    (tptr (Tstruct _jit_state noattr))
                                                    (Tcons tuint Tnil))
                                                  tulong cc_default))
                                ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                 (Etempvar _dst tuint) :: nil))
                              (Sset _dst64 (Etempvar _t'21 tulong)))
                            (Ssequence
                              (Ssequence
                                (Scall (Some _t'22)
                                  (Evar _get_src (Tfunction
                                                   (Tcons tulong Tnil) tuint
                                                   cc_default))
                                  ((Etempvar _ins tulong) :: nil))
                                (Sset _src (Etempvar _t'22 tuint)))
                              (Ssequence
                                (Ssequence
                                  (Scall (Some _t'23)
                                    (Evar _eval_reg (Tfunction
                                                      (Tcons
                                                        (tptr (Tstruct _jit_state noattr))
                                                        (Tcons tuint Tnil))
                                                      tulong cc_default))
                                    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                     (Etempvar _src tuint) :: nil))
                                  (Sset _src64 (Etempvar _t'23 tulong)))
                                (Ssequence
                                  (Ssequence
                                    (Scall (Some _t'24)
                                      (Evar _get_offset (Tfunction
                                                          (Tcons tulong Tnil)
                                                          tint cc_default))
                                      ((Etempvar _ins tulong) :: nil))
                                    (Sset _ofs (Etempvar _t'24 tint)))
                                  (Ssequence
                                    (Ssequence
                                      (Scall (Some _t'25)
                                        (Evar _get_addr_ofs (Tfunction
                                                              (Tcons tulong
                                                                (Tcons tint
                                                                  Tnil))
                                                              tuint
                                                              cc_default))
                                        ((Etempvar _dst64 tulong) ::
                                         (Etempvar _ofs tint) :: nil))
                                      (Sset _addr (Etempvar _t'25 tuint)))
                                    (Ssequence
                                      (Scall None
                                        (Evar _step_opcode_mem_st_reg 
                                        (Tfunction
                                          (Tcons
                                            (tptr (Tstruct _jit_state noattr))
                                            (Tcons tulong
                                              (Tcons tuint
                                                (Tcons tuchar Tnil)))) tvoid
                                          cc_default))
                                        ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                         (Etempvar _src64 tulong) ::
                                         (Etempvar _addr tuint) ::
                                         (Etempvar _op tuchar) :: nil))
                                      (Sreturn None)))))))
                          (LScons None
                            (Ssequence
                              (Scall None
                                (Evar _upd_flag (Tfunction
                                                  (Tcons
                                                    (tptr (Tstruct _jit_state noattr))
                                                    (Tcons tuint Tnil)) tvoid
                                                  cc_default))
                                ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                                 (Econst_int (Int.repr 2) tuint) :: nil))
                              (Sreturn None))
                            LSnil))))))))))))))
|}.

Definition f_ibpf_interpreter_aux := {|
  fn_return := tvoid;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) ::
                (_fuel, tuint) :: nil);
  fn_vars := nil;
  fn_temps := ((_fuel0, tuint) :: (_len, tuint) :: (_pc, tuint) ::
               (_f, tuint) :: (_len0, tuint) :: (_pc0, tuint) ::
               (_t'5, tuint) :: (_t'4, tuint) :: (_t'3, tuint) ::
               (_t'2, tuint) :: (_t'1, tuint) :: nil);
  fn_body :=
(Sifthenelse (Ebinop Oeq (Etempvar _fuel tuint)
               (Econst_int (Int.repr 0) tuint) tint)
  (Ssequence
    (Scall None
      (Evar _upd_flag (Tfunction
                        (Tcons (tptr (Tstruct _jit_state noattr))
                          (Tcons tuint Tnil)) tvoid cc_default))
      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
       (Econst_int (Int.repr 6) tuint) :: nil))
    (Sreturn None))
  (Ssequence
    (Sset _fuel0
      (Ebinop Osub (Etempvar _fuel tuint) (Econst_int (Int.repr 1) tuint)
        tuint))
    (Ssequence
      (Ssequence
        (Scall (Some _t'1)
          (Evar _eval_ins_len (Tfunction
                                (Tcons (tptr (Tstruct _jit_state noattr))
                                  Tnil) tuint cc_default))
          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) :: nil))
        (Sset _len (Etempvar _t'1 tuint)))
      (Ssequence
        (Ssequence
          (Scall (Some _t'2)
            (Evar _eval_pc (Tfunction
                             (Tcons (tptr (Tstruct _jit_state noattr)) Tnil)
                             tuint cc_default))
            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) :: nil))
          (Sset _pc (Etempvar _t'2 tuint)))
        (Sifthenelse (Ebinop Olt (Etempvar _pc tuint) (Etempvar _len tuint)
                       tint)
          (Ssequence
            (Scall None
              (Evar _step (Tfunction
                            (Tcons (tptr (Tstruct _jit_state noattr)) Tnil)
                            tvoid cc_default))
              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) :: nil))
            (Ssequence
              (Ssequence
                (Scall (Some _t'3)
                  (Evar _eval_flag (Tfunction
                                     (Tcons
                                       (tptr (Tstruct _jit_state noattr))
                                       Tnil) tuint cc_default))
                  ((Etempvar _st (tptr (Tstruct _jit_state noattr))) :: nil))
                (Sset _f (Etempvar _t'3 tuint)))
              (Sifthenelse (Ebinop Oeq (Etempvar _f tuint)
                             (Econst_int (Int.repr 0) tuint) tint)
                (Ssequence
                  (Ssequence
                    (Scall (Some _t'4)
                      (Evar _eval_ins_len (Tfunction
                                            (Tcons
                                              (tptr (Tstruct _jit_state noattr))
                                              Tnil) tuint cc_default))
                      ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                       nil))
                    (Sset _len0 (Etempvar _t'4 tuint)))
                  (Ssequence
                    (Ssequence
                      (Scall (Some _t'5)
                        (Evar _eval_pc (Tfunction
                                         (Tcons
                                           (tptr (Tstruct _jit_state noattr))
                                           Tnil) tuint cc_default))
                        ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                         nil))
                      (Sset _pc0 (Etempvar _t'5 tuint)))
                    (Sifthenelse (Ebinop Olt
                                   (Ebinop Oadd (Etempvar _pc0 tuint)
                                     (Econst_int (Int.repr 1) tuint) tuint)
                                   (Etempvar _len0 tuint) tint)
                      (Ssequence
                        (Scall None
                          (Evar _upd_pc_incr (Tfunction
                                               (Tcons
                                                 (tptr (Tstruct _jit_state noattr))
                                                 Tnil) tvoid cc_default))
                          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                           nil))
                        (Ssequence
                          (Scall None
                            (Evar _ibpf_interpreter_aux (Tfunction
                                                          (Tcons
                                                            (tptr (Tstruct _jit_state noattr))
                                                            (Tcons tuint
                                                              Tnil)) tvoid
                                                          cc_default))
                            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                             (Etempvar _fuel0 tuint) :: nil))
                          (Sreturn None)))
                      (Ssequence
                        (Scall None
                          (Evar _upd_flag (Tfunction
                                            (Tcons
                                              (tptr (Tstruct _jit_state noattr))
                                              (Tcons tuint Tnil)) tvoid
                                            cc_default))
                          ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
                           (Econst_int (Int.repr 6) tuint) :: nil))
                        (Sreturn None)))))
                (Sreturn None))))
          (Ssequence
            (Scall None
              (Evar _upd_flag (Tfunction
                                (Tcons (tptr (Tstruct _jit_state noattr))
                                  (Tcons tuint Tnil)) tvoid cc_default))
              ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
               (Econst_int (Int.repr 6) tuint) :: nil))
            (Sreturn None)))))))
|}.

Definition f_ibpf_interpreter := {|
  fn_return := tulong;
  fn_callconv := cc_default;
  fn_params := ((_st, (tptr (Tstruct _jit_state noattr))) ::
                (_fuel, tuint) :: nil);
  fn_vars := nil;
  fn_temps := ((_f, tuint) :: (_res, tulong) :: (_t'2, tulong) ::
               (_t'1, tuint) :: nil);
  fn_body :=
(Ssequence
  (Scall None
    (Evar _ibpf_interpreter_aux (Tfunction
                                  (Tcons (tptr (Tstruct _jit_state noattr))
                                    (Tcons tuint Tnil)) tvoid cc_default))
    ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
     (Etempvar _fuel tuint) :: nil))
  (Ssequence
    (Ssequence
      (Scall (Some _t'1)
        (Evar _eval_flag (Tfunction
                           (Tcons (tptr (Tstruct _jit_state noattr)) Tnil)
                           tuint cc_default))
        ((Etempvar _st (tptr (Tstruct _jit_state noattr))) :: nil))
      (Sset _f (Etempvar _t'1 tuint)))
    (Sifthenelse (Ebinop Oeq (Etempvar _f tuint)
                   (Econst_int (Int.repr 1) tuint) tint)
      (Ssequence
        (Ssequence
          (Scall (Some _t'2)
            (Evar _eval_reg (Tfunction
                              (Tcons (tptr (Tstruct _jit_state noattr))
                                (Tcons tuint Tnil)) tulong cc_default))
            ((Etempvar _st (tptr (Tstruct _jit_state noattr))) ::
             (Econst_int (Int.repr 0) tuint) :: nil))
          (Sset _res (Etempvar _t'2 tulong)))
        (Sreturn (Some (Etempvar _res tulong))))
      (Sreturn (Some (Econst_long (Int64.repr 0) tulong))))))
|}.

Definition composites : list composite_definition :=
(Composite _key_value2 Struct
   (Member_plain _arm_ofs tuint :: Member_plain _alu32_ofs tuint :: nil)
   noattr ::
 Composite _memory_region Struct
   (Member_plain _start_addr tuint :: Member_plain _block_size tuint ::
    Member_plain _block_perm tuint ::
    Member_plain _block_ptr (tptr tuchar) :: nil)
   noattr ::
 Composite _jit_state Struct
   (Member_plain _pc_loc tuint :: Member_plain _flag (tptr tuint) ::
    Member_plain _regs_st (tptr tulong) :: Member_plain _mrs_num tuint ::
    Member_plain _bpf_mrs (tptr (Tstruct _memory_region noattr)) ::
    Member_plain _ins_len tuint :: Member_plain _jit_ins (tptr tulong) ::
    Member_plain _kv2 (tptr (Tstruct _key_value2 noattr)) ::
    Member_plain _use_IR11 tbool ::
    Member_plain _load_store_regs (tptr tuint) ::
    Member_plain _offset tuint :: Member_plain _thumb_len tuint ::
    Member_plain _thumb (tptr tushort) :: Member_plain _jitted_len tuint ::
    Member_plain _jitted_list (tptr tushort) :: nil)
   noattr :: nil).

Definition global_definitions : list (ident * globdef fundef type) :=
((___compcert_va_int32,
   Gfun(External (EF_runtime "__compcert_va_int32"
                   (mksignature (AST.Tint :: nil) AST.Tint cc_default))
     (Tcons (tptr tvoid) Tnil) tuint cc_default)) ::
 (___compcert_va_int64,
   Gfun(External (EF_runtime "__compcert_va_int64"
                   (mksignature (AST.Tint :: nil) AST.Tlong cc_default))
     (Tcons (tptr tvoid) Tnil) tulong cc_default)) ::
 (___compcert_va_float64,
   Gfun(External (EF_runtime "__compcert_va_float64"
                   (mksignature (AST.Tint :: nil) AST.Tfloat cc_default))
     (Tcons (tptr tvoid) Tnil) tdouble cc_default)) ::
 (___compcert_va_composite,
   Gfun(External (EF_runtime "__compcert_va_composite"
                   (mksignature (AST.Tint :: AST.Tint :: nil) AST.Tint
                     cc_default)) (Tcons (tptr tvoid) (Tcons tuint Tnil))
     (tptr tvoid) cc_default)) ::
 (___compcert_i64_dtos,
   Gfun(External (EF_runtime "__compcert_i64_dtos"
                   (mksignature (AST.Tfloat :: nil) AST.Tlong cc_default))
     (Tcons tdouble Tnil) tlong cc_default)) ::
 (___compcert_i64_dtou,
   Gfun(External (EF_runtime "__compcert_i64_dtou"
                   (mksignature (AST.Tfloat :: nil) AST.Tlong cc_default))
     (Tcons tdouble Tnil) tulong cc_default)) ::
 (___compcert_i64_stod,
   Gfun(External (EF_runtime "__compcert_i64_stod"
                   (mksignature (AST.Tlong :: nil) AST.Tfloat cc_default))
     (Tcons tlong Tnil) tdouble cc_default)) ::
 (___compcert_i64_utod,
   Gfun(External (EF_runtime "__compcert_i64_utod"
                   (mksignature (AST.Tlong :: nil) AST.Tfloat cc_default))
     (Tcons tulong Tnil) tdouble cc_default)) ::
 (___compcert_i64_stof,
   Gfun(External (EF_runtime "__compcert_i64_stof"
                   (mksignature (AST.Tlong :: nil) AST.Tsingle cc_default))
     (Tcons tlong Tnil) tfloat cc_default)) ::
 (___compcert_i64_utof,
   Gfun(External (EF_runtime "__compcert_i64_utof"
                   (mksignature (AST.Tlong :: nil) AST.Tsingle cc_default))
     (Tcons tulong Tnil) tfloat cc_default)) ::
 (___compcert_i64_sdiv,
   Gfun(External (EF_runtime "__compcert_i64_sdiv"
                   (mksignature (AST.Tlong :: AST.Tlong :: nil) AST.Tlong
                     cc_default)) (Tcons tlong (Tcons tlong Tnil)) tlong
     cc_default)) ::
 (___compcert_i64_udiv,
   Gfun(External (EF_runtime "__compcert_i64_udiv"
                   (mksignature (AST.Tlong :: AST.Tlong :: nil) AST.Tlong
                     cc_default)) (Tcons tulong (Tcons tulong Tnil)) tulong
     cc_default)) ::
 (___compcert_i64_smod,
   Gfun(External (EF_runtime "__compcert_i64_smod"
                   (mksignature (AST.Tlong :: AST.Tlong :: nil) AST.Tlong
                     cc_default)) (Tcons tlong (Tcons tlong Tnil)) tlong
     cc_default)) ::
 (___compcert_i64_umod,
   Gfun(External (EF_runtime "__compcert_i64_umod"
                   (mksignature (AST.Tlong :: AST.Tlong :: nil) AST.Tlong
                     cc_default)) (Tcons tulong (Tcons tulong Tnil)) tulong
     cc_default)) ::
 (___compcert_i64_shl,
   Gfun(External (EF_runtime "__compcert_i64_shl"
                   (mksignature (AST.Tlong :: AST.Tint :: nil) AST.Tlong
                     cc_default)) (Tcons tlong (Tcons tint Tnil)) tlong
     cc_default)) ::
 (___compcert_i64_shr,
   Gfun(External (EF_runtime "__compcert_i64_shr"
                   (mksignature (AST.Tlong :: AST.Tint :: nil) AST.Tlong
                     cc_default)) (Tcons tulong (Tcons tint Tnil)) tulong
     cc_default)) ::
 (___compcert_i64_sar,
   Gfun(External (EF_runtime "__compcert_i64_sar"
                   (mksignature (AST.Tlong :: AST.Tint :: nil) AST.Tlong
                     cc_default)) (Tcons tlong (Tcons tint Tnil)) tlong
     cc_default)) ::
 (___compcert_i64_smulh,
   Gfun(External (EF_runtime "__compcert_i64_smulh"
                   (mksignature (AST.Tlong :: AST.Tlong :: nil) AST.Tlong
                     cc_default)) (Tcons tlong (Tcons tlong Tnil)) tlong
     cc_default)) ::
 (___compcert_i64_umulh,
   Gfun(External (EF_runtime "__compcert_i64_umulh"
                   (mksignature (AST.Tlong :: AST.Tlong :: nil) AST.Tlong
                     cc_default)) (Tcons tulong (Tcons tulong Tnil)) tulong
     cc_default)) :: (___stringlit_69, Gvar v___stringlit_69) ::
 (___stringlit_26, Gvar v___stringlit_26) ::
 (___stringlit_77, Gvar v___stringlit_77) ::
 (___stringlit_32, Gvar v___stringlit_32) ::
 (___stringlit_51, Gvar v___stringlit_51) ::
 (___stringlit_63, Gvar v___stringlit_63) ::
 (___stringlit_74, Gvar v___stringlit_74) ::
 (___stringlit_9, Gvar v___stringlit_9) ::
 (___stringlit_72, Gvar v___stringlit_72) ::
 (___stringlit_36, Gvar v___stringlit_36) ::
 (___stringlit_62, Gvar v___stringlit_62) ::
 (___stringlit_66, Gvar v___stringlit_66) ::
 (___stringlit_44, Gvar v___stringlit_44) ::
 (___stringlit_57, Gvar v___stringlit_57) ::
 (___stringlit_90, Gvar v___stringlit_90) ::
 (___stringlit_3, Gvar v___stringlit_3) ::
 (___stringlit_10, Gvar v___stringlit_10) ::
 (___stringlit_16, Gvar v___stringlit_16) ::
 (___stringlit_29, Gvar v___stringlit_29) ::
 (___stringlit_50, Gvar v___stringlit_50) ::
 (___stringlit_54, Gvar v___stringlit_54) ::
 (___stringlit_39, Gvar v___stringlit_39) ::
 (___stringlit_82, Gvar v___stringlit_82) ::
 (___stringlit_13, Gvar v___stringlit_13) ::
 (___stringlit_60, Gvar v___stringlit_60) ::
 (___stringlit_1, Gvar v___stringlit_1) ::
 (___stringlit_64, Gvar v___stringlit_64) ::
 (___stringlit_48, Gvar v___stringlit_48) ::
 (___stringlit_49, Gvar v___stringlit_49) ::
 (___stringlit_24, Gvar v___stringlit_24) ::
 (___stringlit_20, Gvar v___stringlit_20) ::
 (___stringlit_22, Gvar v___stringlit_22) ::
 (___stringlit_6, Gvar v___stringlit_6) ::
 (___stringlit_43, Gvar v___stringlit_43) ::
 (___stringlit_70, Gvar v___stringlit_70) ::
 (___stringlit_15, Gvar v___stringlit_15) ::
 (___stringlit_34, Gvar v___stringlit_34) ::
 (___stringlit_80, Gvar v___stringlit_80) ::
 (___stringlit_2, Gvar v___stringlit_2) ::
 (___stringlit_28, Gvar v___stringlit_28) ::
 (___stringlit_4, Gvar v___stringlit_4) ::
 (___stringlit_21, Gvar v___stringlit_21) ::
 (___stringlit_11, Gvar v___stringlit_11) ::
 (___stringlit_56, Gvar v___stringlit_56) ::
 (___stringlit_46, Gvar v___stringlit_46) ::
 (___stringlit_88, Gvar v___stringlit_88) ::
 (___stringlit_91, Gvar v___stringlit_91) ::
 (___stringlit_19, Gvar v___stringlit_19) ::
 (___stringlit_38, Gvar v___stringlit_38) ::
 (___stringlit_71, Gvar v___stringlit_71) ::
 (___stringlit_86, Gvar v___stringlit_86) ::
 (___stringlit_14, Gvar v___stringlit_14) ::
 (___stringlit_67, Gvar v___stringlit_67) ::
 (___stringlit_75, Gvar v___stringlit_75) ::
 (___stringlit_18, Gvar v___stringlit_18) ::
 (___stringlit_40, Gvar v___stringlit_40) ::
 (___stringlit_35, Gvar v___stringlit_35) ::
 (___stringlit_45, Gvar v___stringlit_45) ::
 (___stringlit_53, Gvar v___stringlit_53) ::
 (___stringlit_5, Gvar v___stringlit_5) ::
 (___stringlit_42, Gvar v___stringlit_42) ::
 (___stringlit_68, Gvar v___stringlit_68) ::
 (___stringlit_12, Gvar v___stringlit_12) ::
 (___stringlit_59, Gvar v___stringlit_59) ::
 (___stringlit_61, Gvar v___stringlit_61) ::
 (___stringlit_55, Gvar v___stringlit_55) ::
 (___stringlit_37, Gvar v___stringlit_37) ::
 (___stringlit_76, Gvar v___stringlit_76) ::
 (___stringlit_85, Gvar v___stringlit_85) ::
 (___stringlit_87, Gvar v___stringlit_87) ::
 (___stringlit_47, Gvar v___stringlit_47) ::
 (___stringlit_84, Gvar v___stringlit_84) ::
 (___stringlit_23, Gvar v___stringlit_23) ::
 (___stringlit_33, Gvar v___stringlit_33) ::
 (___stringlit_89, Gvar v___stringlit_89) ::
 (___stringlit_79, Gvar v___stringlit_79) ::
 (___stringlit_27, Gvar v___stringlit_27) ::
 (___stringlit_31, Gvar v___stringlit_31) ::
 (___stringlit_73, Gvar v___stringlit_73) ::
 (___stringlit_65, Gvar v___stringlit_65) ::
 (___stringlit_58, Gvar v___stringlit_58) ::
 (___stringlit_17, Gvar v___stringlit_17) ::
 (___stringlit_30, Gvar v___stringlit_30) ::
 (___stringlit_25, Gvar v___stringlit_25) ::
 (___stringlit_41, Gvar v___stringlit_41) ::
 (___stringlit_52, Gvar v___stringlit_52) ::
 (___stringlit_81, Gvar v___stringlit_81) ::
 (___stringlit_8, Gvar v___stringlit_8) ::
 (___stringlit_83, Gvar v___stringlit_83) ::
 (___stringlit_7, Gvar v___stringlit_7) ::
 (___stringlit_78, Gvar v___stringlit_78) ::
 (___builtin_ais_annot,
   Gfun(External (EF_builtin "__builtin_ais_annot"
                   (mksignature (AST.Tint :: nil) AST.Tvoid
                     {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
     (Tcons (tptr tuchar) Tnil) tvoid
     {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|})) ::
 (___builtin_bswap64,
   Gfun(External (EF_builtin "__builtin_bswap64"
                   (mksignature (AST.Tlong :: nil) AST.Tlong cc_default))
     (Tcons tulong Tnil) tulong cc_default)) ::
 (___builtin_bswap,
   Gfun(External (EF_builtin "__builtin_bswap"
                   (mksignature (AST.Tint :: nil) AST.Tint cc_default))
     (Tcons tuint Tnil) tuint cc_default)) ::
 (___builtin_bswap32,
   Gfun(External (EF_builtin "__builtin_bswap32"
                   (mksignature (AST.Tint :: nil) AST.Tint cc_default))
     (Tcons tuint Tnil) tuint cc_default)) ::
 (___builtin_bswap16,
   Gfun(External (EF_builtin "__builtin_bswap16"
                   (mksignature (AST.Tint :: nil) AST.Tint16unsigned
                     cc_default)) (Tcons tushort Tnil) tushort cc_default)) ::
 (___builtin_clz,
   Gfun(External (EF_builtin "__builtin_clz"
                   (mksignature (AST.Tint :: nil) AST.Tint cc_default))
     (Tcons tuint Tnil) tint cc_default)) ::
 (___builtin_clzl,
   Gfun(External (EF_builtin "__builtin_clzl"
                   (mksignature (AST.Tint :: nil) AST.Tint cc_default))
     (Tcons tuint Tnil) tint cc_default)) ::
 (___builtin_clzll,
   Gfun(External (EF_builtin "__builtin_clzll"
                   (mksignature (AST.Tlong :: nil) AST.Tint cc_default))
     (Tcons tulong Tnil) tint cc_default)) ::
 (___builtin_ctz,
   Gfun(External (EF_builtin "__builtin_ctz"
                   (mksignature (AST.Tint :: nil) AST.Tint cc_default))
     (Tcons tuint Tnil) tint cc_default)) ::
 (___builtin_ctzl,
   Gfun(External (EF_builtin "__builtin_ctzl"
                   (mksignature (AST.Tint :: nil) AST.Tint cc_default))
     (Tcons tuint Tnil) tint cc_default)) ::
 (___builtin_ctzll,
   Gfun(External (EF_builtin "__builtin_ctzll"
                   (mksignature (AST.Tlong :: nil) AST.Tint cc_default))
     (Tcons tulong Tnil) tint cc_default)) ::
 (___builtin_fabs,
   Gfun(External (EF_builtin "__builtin_fabs"
                   (mksignature (AST.Tfloat :: nil) AST.Tfloat cc_default))
     (Tcons tdouble Tnil) tdouble cc_default)) ::
 (___builtin_fabsf,
   Gfun(External (EF_builtin "__builtin_fabsf"
                   (mksignature (AST.Tsingle :: nil) AST.Tsingle cc_default))
     (Tcons tfloat Tnil) tfloat cc_default)) ::
 (___builtin_fsqrt,
   Gfun(External (EF_builtin "__builtin_fsqrt"
                   (mksignature (AST.Tfloat :: nil) AST.Tfloat cc_default))
     (Tcons tdouble Tnil) tdouble cc_default)) ::
 (___builtin_sqrt,
   Gfun(External (EF_builtin "__builtin_sqrt"
                   (mksignature (AST.Tfloat :: nil) AST.Tfloat cc_default))
     (Tcons tdouble Tnil) tdouble cc_default)) ::
 (___builtin_memcpy_aligned,
   Gfun(External (EF_builtin "__builtin_memcpy_aligned"
                   (mksignature
                     (AST.Tint :: AST.Tint :: AST.Tint :: AST.Tint :: nil)
                     AST.Tvoid cc_default))
     (Tcons (tptr tvoid)
       (Tcons (tptr tvoid) (Tcons tuint (Tcons tuint Tnil)))) tvoid
     cc_default)) ::
 (___builtin_sel,
   Gfun(External (EF_builtin "__builtin_sel"
                   (mksignature (AST.Tint :: nil) AST.Tvoid
                     {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
     (Tcons tbool Tnil) tvoid
     {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|})) ::
 (___builtin_annot,
   Gfun(External (EF_builtin "__builtin_annot"
                   (mksignature (AST.Tint :: nil) AST.Tvoid
                     {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
     (Tcons (tptr tuchar) Tnil) tvoid
     {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|})) ::
 (___builtin_annot_intval,
   Gfun(External (EF_builtin "__builtin_annot_intval"
                   (mksignature (AST.Tint :: AST.Tint :: nil) AST.Tint
                     cc_default)) (Tcons (tptr tuchar) (Tcons tint Tnil))
     tint cc_default)) ::
 (___builtin_membar,
   Gfun(External (EF_builtin "__builtin_membar"
                   (mksignature nil AST.Tvoid cc_default)) Tnil tvoid
     cc_default)) ::
 (___builtin_va_start,
   Gfun(External (EF_builtin "__builtin_va_start"
                   (mksignature (AST.Tint :: nil) AST.Tvoid cc_default))
     (Tcons (tptr tvoid) Tnil) tvoid cc_default)) ::
 (___builtin_va_arg,
   Gfun(External (EF_builtin "__builtin_va_arg"
                   (mksignature (AST.Tint :: AST.Tint :: nil) AST.Tvoid
                     cc_default)) (Tcons (tptr tvoid) (Tcons tuint Tnil))
     tvoid cc_default)) ::
 (___builtin_va_copy,
   Gfun(External (EF_builtin "__builtin_va_copy"
                   (mksignature (AST.Tint :: AST.Tint :: nil) AST.Tvoid
                     cc_default))
     (Tcons (tptr tvoid) (Tcons (tptr tvoid) Tnil)) tvoid cc_default)) ::
 (___builtin_va_end,
   Gfun(External (EF_builtin "__builtin_va_end"
                   (mksignature (AST.Tint :: nil) AST.Tvoid cc_default))
     (Tcons (tptr tvoid) Tnil) tvoid cc_default)) ::
 (___builtin_unreachable,
   Gfun(External (EF_builtin "__builtin_unreachable"
                   (mksignature nil AST.Tvoid cc_default)) Tnil tvoid
     cc_default)) ::
 (___builtin_expect,
   Gfun(External (EF_builtin "__builtin_expect"
                   (mksignature (AST.Tint :: AST.Tint :: nil) AST.Tint
                     cc_default)) (Tcons tint (Tcons tint Tnil)) tint
     cc_default)) ::
 (___builtin_read16_reversed,
   Gfun(External (EF_builtin "__builtin_read16_reversed"
                   (mksignature (AST.Tint :: nil) AST.Tint16unsigned
                     cc_default)) (Tcons (tptr tushort) Tnil) tushort
     cc_default)) ::
 (___builtin_read32_reversed,
   Gfun(External (EF_builtin "__builtin_read32_reversed"
                   (mksignature (AST.Tint :: nil) AST.Tint cc_default))
     (Tcons (tptr tuint) Tnil) tuint cc_default)) ::
 (___builtin_write16_reversed,
   Gfun(External (EF_builtin "__builtin_write16_reversed"
                   (mksignature (AST.Tint :: AST.Tint :: nil) AST.Tvoid
                     cc_default)) (Tcons (tptr tushort) (Tcons tushort Tnil))
     tvoid cc_default)) ::
 (___builtin_write32_reversed,
   Gfun(External (EF_builtin "__builtin_write32_reversed"
                   (mksignature (AST.Tint :: AST.Tint :: nil) AST.Tvoid
                     cc_default)) (Tcons (tptr tuint) (Tcons tuint Tnil))
     tvoid cc_default)) ::
 (___builtin_dmb,
   Gfun(External (EF_builtin "__builtin_dmb"
                   (mksignature nil AST.Tvoid cc_default)) Tnil tvoid
     cc_default)) ::
 (___builtin_dsb,
   Gfun(External (EF_builtin "__builtin_dsb"
                   (mksignature nil AST.Tvoid cc_default)) Tnil tvoid
     cc_default)) ::
 (___builtin_isb,
   Gfun(External (EF_builtin "__builtin_isb"
                   (mksignature nil AST.Tvoid cc_default)) Tnil tvoid
     cc_default)) ::
 (___builtin_debug,
   Gfun(External (EF_external "__builtin_debug"
                   (mksignature (AST.Tint :: nil) AST.Tvoid
                     {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
     (Tcons tint Tnil) tvoid
     {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|})) ::
 (_printf,
   Gfun(External (EF_external "printf"
                   (mksignature (AST.Tint :: nil) AST.Tint
                     {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|}))
     (Tcons (tptr tuchar) Tnil) tint
     {|cc_vararg:=(Some 1); cc_unproto:=false; cc_structret:=false|})) ::
 (__magic_function,
   Gfun(External (EF_external "_magic_function"
                   (mksignature (AST.Tint :: AST.Tint :: nil) AST.Tvoid
                     cc_default))
     (Tcons tuint (Tcons (tptr (Tstruct _jit_state noattr)) Tnil)) tvoid
     cc_default)) :: (_print_reg, Gfun(Internal f_print_reg)) ::
 (_print_bpf_insstruction, Gfun(Internal f_print_bpf_insstruction)) ::
 (_print_u64_dec,
   Gfun(External (EF_external "print_u64_dec"
                   (mksignature nil AST.Tint
                     {|cc_vararg:=None; cc_unproto:=true; cc_structret:=false|}))
     Tnil tint {|cc_vararg:=None; cc_unproto:=true; cc_structret:=false|})) ::
 (_print_jit_state, Gfun(Internal f_print_jit_state)) ::
 (_print_load_store_regs, Gfun(Internal f_print_load_store_regs)) ::
 (_print_thumb, Gfun(Internal f_print_thumb)) ::
 (_print_ibpf, Gfun(Internal f_print_ibpf)) ::
 (_print_jitted_arm, Gfun(Internal f_print_jitted_arm)) ::
 (_print_jit_state_all, Gfun(Internal f_print_jit_state_all)) ::
 (_eval_pc, Gfun(Internal f_eval_pc)) ::
 (_upd_pc, Gfun(Internal f_upd_pc)) ::
 (_upd_pc_incr, Gfun(Internal f_upd_pc_incr)) ::
 (_eval_reg, Gfun(Internal f_eval_reg)) ::
 (_upd_reg, Gfun(Internal f_upd_reg)) ::
 (_eval_flag, Gfun(Internal f_eval_flag)) ::
 (_upd_flag, Gfun(Internal f_upd_flag)) ::
 (_eval_mrs_num, Gfun(Internal f_eval_mrs_num)) ::
 (_eval_mrs_regions, Gfun(Internal f_eval_mrs_regions)) ::
 (_load_mem, Gfun(Internal f_load_mem)) ::
 (_store_mem_reg, Gfun(Internal f_store_mem_reg)) ::
 (_store_mem_imm, Gfun(Internal f_store_mem_imm)) ::
 (_eval_ins_len, Gfun(Internal f_eval_ins_len)) ::
 (_eval_ins, Gfun(Internal f_eval_ins)) ::
 (_cmp_ptr32_nullM, Gfun(Internal f_cmp_ptr32_nullM)) ::
 (_get_dst, Gfun(Internal f_get_dst)) ::
 (_get_src, Gfun(Internal f_get_src)) ::
 (_get_mem_region, Gfun(Internal f_get_mem_region)) ::
 (__bpf_get_call, Gfun(Internal f__bpf_get_call)) ::
 (_exec_function, Gfun(Internal f_exec_function)) ::
 (_upd_IR11_jittedthumb, Gfun(Internal f_upd_IR11_jittedthumb)) ::
 (_add_ins_jittedthumb, Gfun(Internal f_add_ins_jittedthumb)) ::
 (_upd_bpf_offset_jittedthumb, Gfun(Internal f_upd_bpf_offset_jittedthumb)) ::
 (_upd_load_store_regs_jittedthumb, Gfun(Internal f_upd_load_store_regs_jittedthumb)) ::
 (_upd_thumb_jittedthumb, Gfun(Internal f_upd_thumb_jittedthumb)) ::
 (_upd_jitted_list, Gfun(Internal f_upd_jitted_list)) ::
 (_magic_function, Gfun(Internal f_magic_function)) ::
 (_eval_use_IR11, Gfun(Internal f_eval_use_IR11)) ::
 (_eval_offset, Gfun(Internal f_eval_offset)) ::
 (_eval_thumb_len, Gfun(Internal f_eval_thumb_len)) ::
 (_eval_jitted_len, Gfun(Internal f_eval_jitted_len)) ::
 (_is_non_reg, Gfun(Internal f_is_non_reg)) ::
 (_is_load_reg, Gfun(Internal f_is_load_reg)) ::
 (_is_store_reg, Gfun(Internal f_is_store_reg)) ::
 (_power2, Gfun(Internal f_power2)) ::
 (_decode_thumb, Gfun(Internal f_decode_thumb)) ::
 (_encode_thumb, Gfun(Internal f_encode_thumb)) ::
 (_reg_of_ireg, Gfun(Internal f_reg_of_ireg)) ::
 (_opcode_reg_of_imm, Gfun(Internal f_opcode_reg_of_imm)) ::
 (_eval_thumb_ins, Gfun(Internal f_eval_thumb_ins)) ::
 (_ins_is_bpf_alu32, Gfun(Internal f_ins_is_bpf_alu32)) ::
 (_ins_is_bpf_jump, Gfun(Internal f_ins_is_bpf_jump)) ::
 (_reset_init_jittedthumb, Gfun(Internal f_reset_init_jittedthumb)) ::
 (_eval_key_value2_arm_ofs, Gfun(Internal f_eval_key_value2_arm_ofs)) ::
 (_eval_key_value2_alu32_ofs, Gfun(Internal f_eval_key_value2_alu32_ofs)) ::
 (_add_key_value2, Gfun(Internal f_add_key_value2)) ::
 (_construct_thumb_b, Gfun(Internal f_construct_thumb_b)) ::
 (_construct_thumb2_shift_rd_rm, Gfun(Internal f_construct_thumb2_shift_rd_rm)) ::
 (_jit_alu32_thumb_store_template_ins, Gfun(Internal f_jit_alu32_thumb_store_template_ins)) ::
 (_jit_alu32_thumb_load_template_ins, Gfun(Internal f_jit_alu32_thumb_load_template_ins)) ::
 (_jit_alu32_thumb_store_template_jit, Gfun(Internal f_jit_alu32_thumb_store_template_jit)) ::
 (_jit_alu32_thumb_load_template_jit, Gfun(Internal f_jit_alu32_thumb_load_template_jit)) ::
 (_jit_alu32_store_flag, Gfun(Internal f_jit_alu32_store_flag)) ::
 (_get_offset, Gfun(Internal f_get_offset)) ::
 (_jit_alu32_pre, Gfun(Internal f_jit_alu32_pre)) ::
 (_jit_alu32_thumb_upd_save, Gfun(Internal f_jit_alu32_thumb_upd_save)) ::
 (_jit_alu32_thumb_save, Gfun(Internal f_jit_alu32_thumb_save)) ::
 (_jit_alu32_thumb_upd_load, Gfun(Internal f_jit_alu32_thumb_upd_load)) ::
 (_no_reg_load, Gfun(Internal f_no_reg_load)) ::
 (_jit_alu32_thumb_load, Gfun(Internal f_jit_alu32_thumb_load)) ::
 (_bpf_alu32_to_thumb_reg, Gfun(Internal f_bpf_alu32_to_thumb_reg)) ::
 (_bpf_alu32_to_thumb_imm, Gfun(Internal f_bpf_alu32_to_thumb_imm)) ::
 (_mov_int_to_reg_binary, Gfun(Internal f_mov_int_to_reg_binary)) ::
 (_get_immediate, Gfun(Internal f_get_immediate)) ::
 (_get_opcode_ins, Gfun(Internal f_get_opcode_ins)) ::
 (_nat_to_opcode_alu32, Gfun(Internal f_nat_to_opcode_alu32)) ::
 (_nat_to_opcode_alu32_reg, Gfun(Internal f_nat_to_opcode_alu32_reg)) ::
 (_nat_to_opcode_alu32_imm, Gfun(Internal f_nat_to_opcode_alu32_imm)) ::
 (_bpf_alu32_to_thumb, Gfun(Internal f_bpf_alu32_to_thumb)) ::
 (_get_store_ins_num, Gfun(Internal f_get_store_ins_num)) ::
 (_jit_alu32_to_thumb_pass2_aux, Gfun(Internal f_jit_alu32_to_thumb_pass2_aux)) ::
 (_jit_alu32_to_thumb_pass2, Gfun(Internal f_jit_alu32_to_thumb_pass2)) ::
 (_jit_alu32_to_thumb_pass1, Gfun(Internal f_jit_alu32_to_thumb_pass1)) ::
 (_jit_alu32_thumb_upd_store, Gfun(Internal f_jit_alu32_thumb_upd_store)) ::
 (_jit_alu32_thumb_store, Gfun(Internal f_jit_alu32_thumb_store)) ::
 (_jit_alu32_thumb_upd_reset, Gfun(Internal f_jit_alu32_thumb_upd_reset)) ::
 (_jit_alu32_thumb_reset, Gfun(Internal f_jit_alu32_thumb_reset)) ::
 (_jit_alu32_post, Gfun(Internal f_jit_alu32_post)) ::
 (_copy_thumb_list_from_to_aux, Gfun(Internal f_copy_thumb_list_from_to_aux)) ::
 (_copy_thumb_list_from_to, Gfun(Internal f_copy_thumb_list_from_to)) ::
 (_jit_alu32_to_thumb, Gfun(Internal f_jit_alu32_to_thumb)) ::
 (_jit_alu32_aux, Gfun(Internal f_jit_alu32_aux)) ::
 (_jit_alu32, Gfun(Internal f_jit_alu32)) ::
 (_reg64_to_reg32, Gfun(Internal f_reg64_to_reg32)) ::
 (_eval_immediate, Gfun(Internal f_eval_immediate)) ::
 (_get_src64, Gfun(Internal f_get_src64)) ::
 (_get_opcode_alu64, Gfun(Internal f_get_opcode_alu64)) ::
 (_get_opcode_alu32, Gfun(Internal f_get_opcode_alu32)) ::
 (_get_opcode_branch, Gfun(Internal f_get_opcode_branch)) ::
 (_get_opcode_mem_ld_imm, Gfun(Internal f_get_opcode_mem_ld_imm)) ::
 (_get_opcode_mem_ld_reg, Gfun(Internal f_get_opcode_mem_ld_reg)) ::
 (_get_opcode_mem_st_imm, Gfun(Internal f_get_opcode_mem_st_imm)) ::
 (_get_opcode_mem_st_reg, Gfun(Internal f_get_opcode_mem_st_reg)) ::
 (_get_opcode, Gfun(Internal f_get_opcode)) ::
 (_get_add, Gfun(Internal f_get_add)) ::
 (_get_sub, Gfun(Internal f_get_sub)) ::
 (_get_addr_ofs, Gfun(Internal f_get_addr_ofs)) ::
 (_get_start_addr, Gfun(Internal f_get_start_addr)) ::
 (_get_block_size, Gfun(Internal f_get_block_size)) ::
 (_get_block_perm, Gfun(Internal f_get_block_perm)) ::
 (_is_well_chunk_bool, Gfun(Internal f_is_well_chunk_bool)) ::
 (_check_mem_aux2, Gfun(Internal f_check_mem_aux2)) ::
 (_check_mem_aux, Gfun(Internal f_check_mem_aux)) ::
 (_check_mem, Gfun(Internal f_check_mem)) ::
 (_step_opcode_alu64, Gfun(Internal f_step_opcode_alu64)) ::
 (_step_opcode_alu32, Gfun(Internal f_step_opcode_alu32)) ::
 (_step_opcode_branch, Gfun(Internal f_step_opcode_branch)) ::
 (_step_opcode_mem_ld_imm, Gfun(Internal f_step_opcode_mem_ld_imm)) ::
 (_step_opcode_mem_ld_reg, Gfun(Internal f_step_opcode_mem_ld_reg)) ::
 (_step_opcode_mem_st_imm, Gfun(Internal f_step_opcode_mem_st_imm)) ::
 (_step_opcode_mem_st_reg, Gfun(Internal f_step_opcode_mem_st_reg)) ::
 (_step, Gfun(Internal f_step)) ::
 (_ibpf_interpreter_aux, Gfun(Internal f_ibpf_interpreter_aux)) ::
 (_ibpf_interpreter, Gfun(Internal f_ibpf_interpreter)) :: nil).

Definition public_idents : list ident :=
(_ibpf_interpreter :: _check_mem :: _jit_alu32 :: _print_jit_state_all ::
 _print_jitted_arm :: _print_ibpf :: _print_thumb ::
 _print_load_store_regs :: _print_jit_state :: _print_u64_dec ::
 _print_bpf_insstruction :: _print_reg :: __magic_function :: _printf ::
 ___builtin_debug :: ___builtin_isb :: ___builtin_dsb :: ___builtin_dmb ::
 ___builtin_write32_reversed :: ___builtin_write16_reversed ::
 ___builtin_read32_reversed :: ___builtin_read16_reversed ::
 ___builtin_expect :: ___builtin_unreachable :: ___builtin_va_end ::
 ___builtin_va_copy :: ___builtin_va_arg :: ___builtin_va_start ::
 ___builtin_membar :: ___builtin_annot_intval :: ___builtin_annot ::
 ___builtin_sel :: ___builtin_memcpy_aligned :: ___builtin_sqrt ::
 ___builtin_fsqrt :: ___builtin_fabsf :: ___builtin_fabs ::
 ___builtin_ctzll :: ___builtin_ctzl :: ___builtin_ctz :: ___builtin_clzll ::
 ___builtin_clzl :: ___builtin_clz :: ___builtin_bswap16 ::
 ___builtin_bswap32 :: ___builtin_bswap :: ___builtin_bswap64 ::
 ___builtin_ais_annot :: ___compcert_i64_umulh :: ___compcert_i64_smulh ::
 ___compcert_i64_sar :: ___compcert_i64_shr :: ___compcert_i64_shl ::
 ___compcert_i64_umod :: ___compcert_i64_smod :: ___compcert_i64_udiv ::
 ___compcert_i64_sdiv :: ___compcert_i64_utof :: ___compcert_i64_stof ::
 ___compcert_i64_utod :: ___compcert_i64_stod :: ___compcert_i64_dtou ::
 ___compcert_i64_dtos :: ___compcert_va_composite ::
 ___compcert_va_float64 :: ___compcert_va_int64 :: ___compcert_va_int32 ::
 nil).

Definition prog : Clight.program := 
  mkprogram composites global_definitions public_idents _main Logic.I.


