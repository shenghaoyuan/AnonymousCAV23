/**************************************************************************/
/*  This file is part of CertrBPF,                                        */
/*  a formally verified rBPF verifier + interpreter + JIT in Coq.         */
/*                                                                        */
/*  Copyright (C) 2022 Inria                                              */
/*                                                                        */
/*  This program is free software; you can redistribute it and/or modify  */
/*  it under the terms of the GNU General Public License as published by  */
/*  the Free Software Foundation; either version 2 of the License, or     */
/*  (at your option) any later version.                                   */
/*                                                                        */
/*  This program is distributed in the hope that it will be useful,       */
/*  but WITHOUT ANY WARRANTY; without even the implied warranty of        */
/*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         */
/*  GNU General Public License for more details.                          */
/*                                                                        */
/**************************************************************************/

/**
 * 1. deleting all lines before `void reset_init_jittedthumb`
 * 2. deleting `\n\n`.
 * 2. deleting all `extern` lines
 * 3. adding `st` to all possible places
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 2000
#define CNT 2000

/* Function declaration */
void replaceAll(char *str, const char *oldWord, const char *newWord);


const char start_point[] = "void reset_init_jittedthumb";


const char old_words[][200] = {
	"void jit_alu32_pre(void)",
	"upd_jitted_list(",
	"unsigned int jit_alu32_save_register(",
	
	"void jit_alu32_thumb_upd_save(",
	"is_non_reg(",
	"= jit_alu32_save_register(",
	
	"void jit_alu32_thumb_save(void)",
	"  jit_alu32_thumb_upd_save(",
	"eval_use_IR11()",
	"unsigned int jit_alu32_load_register(",
	
	"void jit_alu32_thumb_upd_load(",
	"is_load_reg(",
	"= jit_alu32_load_register(",
	"void jit_alu32_thumb_load(void)",
	"  jit_alu32_thumb_upd_load(",
	
	"void bpf_alu32_to_thumb_reg(",
	"add_ins_jittedthumb(",
	"upd_load_store_regs_jittedthumb(",
	"upd_IR11_jittedthumb(",
	"upd_flag(",
	
	"void bpf_alu32_to_thumb_imm(",
	"void mov_int_to_reg_binary(",
	"void bpf_alu32_to_thumb(",
	"bpf_alu32_to_thumb_reg(op",
	"unsigned int get_store_ins_num(void)",
	
	"is_store_reg(",
	"void jit_alu32_to_thumb_pass2_aux(",
	"= eval_thumb_ins(",
	"get_store_ins_num()",
	"upd_thumb_jittedthumb(",
	
	"  jit_alu32_to_thumb_pass2_aux(",
	"void jit_alu32_to_thumb_pass2(void)",
	"eval_thumb_len()",
	"void jit_alu32_to_thumb_pass1(",
	"jit_alu32_to_thumb_pass2()",
	
	"eval_ins(",
	"  bpf_alu32_to_thumb(",
	"upd_bpf_offset_jittedthumb()",
	"  jit_alu32_to_thumb_pass1(",
	
	"void jit_alu32_thumb_upd_store(",
	"void jit_alu32_thumb_store(void)",
	
	"  jit_alu32_thumb_upd_store(",
	"void jit_alu32_store_flag(",
	"void jit_alu32_thumb_store_succ_R0(void)",
	"  jit_alu32_store_flag(",
	"unsigned int jit_alu32_reset(",
	
	"  bpf_alu32_to_thumb_imm(",
	"void jit_alu32_thumb_upd_reset(",
	"= jit_alu32_reset(",
	"  add_ins_to_pop_stack(",
	
	"void jit_alu32_thumb_reset(void)",
	"  jit_alu32_thumb_upd_reset(",
	"void jit_alu32_post(void)",
	
	"void copy_thumb_list_from_to_aux(",
	"  copy_thumb_list_from_to_aux(",
	"void copy_thumb_list_from_to(void)",
	"  mov_int_to_reg_binary(",
	
	"eval_jitted_len()",
	"void jit_alu32_aux(",
	"reset_init_jittedthumb()",
	"eval_ins_len()",
	
	"eval_offset()",
	"jit_alu32_pre()",
	"jit_alu32_thumb_save()",
	"jit_alu32_thumb_load()",
	
	"copy_thumb_list_from_to()",
	"jit_alu32_thumb_store()",
	"jit_alu32_thumb_reset()",
	"jit_alu32_post()",
	
	"  jit_alu32_aux(",
	"void jit_alu32(void)",
	"reset_init_entry_point()",
	"eval_entry_len()",
	"jit_alu32_thumb_store_succ_R0()",
	
	"int get_offset",
	"int get_immediate",
	"unsigned char get_opcode_ins",
	"unsigned char nat_to_opcode_alu32",
	"unsigned int jit_alu32_store_register",
	
	"  magic_function(",
	"unsigned short construct_thumb_b",
	"unsigned short construct_thumb2_shift_rd_rm",
	"void jit_alu32_thumb_store_template_ins(",
	"void jit_alu32_thumb_load_template_ins(",
	"void jit_alu32_thumb_store_template_jit(",
	"void jit_alu32_thumb_load_template_jit(",
	"void jit_alu32_store_flag_jit(",
	"_Bool no_reg_load(void)",
	
	"  jit_alu32_thumb_store_template_ins(",
	"  jit_alu32_thumb_load_template_ins(",
	"  jit_alu32_thumb_store_template_jit(",
	"  jit_alu32_thumb_load_template_jit(",
	"  jit_alu32_store_flag_jit(",
	"no_reg_load()",
	
	"void jit_alu32_to_thumb(",
	"  jit_alu32_to_thumb(",
	"  add_key_value2(",
	"= eval_key_value2_arm_ofs(",
	"= eval_key_value2_alu32_ofs(",
	
	//...
	
	"eval_pc()",
	"upd_pc(pc",
	"upd_pc_incr()",
	"  upd_reg(",
	"= eval_reg(",
	"eval_flag()",
	"= check_mem(",
	
	"eval_mrs_regions()",
	"void step_opcode_alu64(",
	"  step_opcode_alu64(",
	"void step_opcode_alu32(",
	"  step_opcode_alu32(",
	"void step_opcode_branch(",
	"  step_opcode_branch(",
	"void step_opcode_mem_ld_imm(",
	"  step_opcode_mem_ld_imm(",
	"void step_opcode_mem_ld_reg(",
	
	"  step_opcode_mem_ld_reg(",
	"void step_opcode_mem_st_imm(",
	"  step_opcode_mem_st_imm(",
	"void step_opcode_mem_st_reg(",
	"  step_opcode_mem_st_reg(",
	"= load_mem(",
	"  store_mem_imm(",
	"  store_mem_reg(",
	
	"unsigned char *check_mem_aux(",
	"return check_mem_aux(",
	"unsigned char *check_mem(",
	
	"void step(void)",
	"step();",
	"void ibpf_interpreter_aux(",
	"  ibpf_interpreter_aux(",	
	"unsigned long long ibpf_interpreter(",
	"struct memory_region *get_mem_region(",
	"eval_mrs_num()",
	"check_mem = check_mem_aux(",
	"check_mem_aux(mem_reg_num",
	
	"unsigned int get_dst(",
	"unsigned int reg64_to_reg32(",
	"unsigned int get_src(",
	"long long eval_immediate(",
	"unsigned long long get_src64(",
	"unsigned int get_src32(",
	"= get_src64(",
	"= get_src32(",
	"unsigned char get_opcode_alu64(",
	"unsigned char get_opcode_alu32(",
	"unsigned char get_opcode_branch(",
	"unsigned char get_opcode_mem_ld_imm(",
	"unsigned char get_opcode_mem_ld_reg(",
	"unsigned char get_opcode_mem_st_imm(",
	"unsigned char get_opcode_mem_st_reg(",
	"unsigned char get_opcode(",
	"unsigned int get_add(",
	"unsigned int get_sub(",
	"unsigned int get_addr_ofs(",
	"_Bool is_well_chunk_bool(",
	"unsigned char *check_mem_aux2(",
	"unsigned char *get_block_ptr",
	"unsigned int get_start_addr",
	"unsigned int get_block_size",
	"unsigned int get_block_perm",
	
	"unsigned long long *l",
	"exec_function(",
	
	"opi == 36U"
	};

const char new_words[][200] = {
	"static __attribute__((always_inline)) inline void jit_alu32_pre(struct jit_state* st)",
	"upd_jitted_list(st, ",
	"static __attribute__((always_inline)) inline unsigned int jit_alu32_save_register(struct jit_state* st, ",
	
	"static __attribute__((always_inline)) inline void jit_alu32_thumb_upd_save(struct jit_state* st, ",
	"is_non_reg(st, ",
	"= jit_alu32_save_register(st, ",
	
	"static __attribute__((always_inline)) inline void jit_alu32_thumb_save(struct jit_state* st)",
	"  jit_alu32_thumb_upd_save(st, ",
	"eval_use_IR11(st)",
	"static __attribute__((always_inline)) inline unsigned int jit_alu32_load_register(struct jit_state* st, ",
	
	"static __attribute__((always_inline)) inline void jit_alu32_thumb_upd_load(struct jit_state* st, ",
	"is_load_reg(st, ",
	"= jit_alu32_load_register(st, ",
	"static __attribute__((always_inline)) inline void jit_alu32_thumb_load(struct jit_state* st)",
	"  jit_alu32_thumb_upd_load(st, ",
	
	"static __attribute__((always_inline)) inline void bpf_alu32_to_thumb_reg(struct jit_state* st, ",
	"add_ins_jittedthumb(st, ",
	"upd_load_store_regs_jittedthumb(st, ",
	"upd_IR11_jittedthumb(st, ",
	"upd_flag(st, ",
	
	"static __attribute__((always_inline)) inline void bpf_alu32_to_thumb_imm(struct jit_state* st, ",
	"static __attribute__((always_inline)) inline void mov_int_to_reg_binary(struct jit_state* st, ",
	"static __attribute__((always_inline)) inline void bpf_alu32_to_thumb(struct jit_state* st, ",
	"bpf_alu32_to_thumb_reg(st, op",
	"static __attribute__((always_inline)) inline unsigned int get_store_ins_num(struct jit_state* st)",
	
	"is_store_reg(st, ",
	"static __attribute__((always_inline)) inline void jit_alu32_to_thumb_pass2_aux(struct jit_state* st, ",
	"= eval_thumb_ins(st, ",
	"get_store_ins_num(st)",
	"upd_thumb_jittedthumb(st, ",
	
	"  jit_alu32_to_thumb_pass2_aux(st, ",
	"static __attribute__((always_inline)) inline void jit_alu32_to_thumb_pass2(struct jit_state* st)",
	"eval_thumb_len(st)",
	"static __attribute__((always_inline)) inline void jit_alu32_to_thumb_pass1(struct jit_state* st, ",
	"jit_alu32_to_thumb_pass2(st)",
	
	"eval_ins(st, ",
	"  bpf_alu32_to_thumb(st, ",
	"upd_bpf_offset_jittedthumb(st)",
	"  jit_alu32_to_thumb_pass1(st, ",
	
	"static __attribute__((always_inline)) inline void jit_alu32_thumb_upd_store(struct jit_state* st, ",
	"static __attribute__((always_inline)) inline void jit_alu32_thumb_store(struct jit_state* st)",
	
	"  jit_alu32_thumb_upd_store(st, ",
	"static __attribute__((always_inline)) inline void jit_alu32_store_flag(struct jit_state* st, ",
	"static __attribute__((always_inline)) inline void jit_alu32_thumb_store_succ_R0(struct jit_state* st)",
	"  jit_alu32_store_flag(st, ",
	"static __attribute__((always_inline)) inline unsigned int jit_alu32_reset(struct jit_state* st, ",
	
	"  bpf_alu32_to_thumb_imm(st, ",
	"static __attribute__((always_inline)) inline void jit_alu32_thumb_upd_reset(struct jit_state* st, ",
	"= jit_alu32_reset(st, ",
	"  add_ins_to_pop_stack(st, ",
	
	"static __attribute__((always_inline)) inline void jit_alu32_thumb_reset(struct jit_state* st)",
	"  jit_alu32_thumb_upd_reset(st, ",
	"static __attribute__((always_inline)) inline void jit_alu32_post(struct jit_state* st)",
	
	"static __attribute__((always_inline)) inline void copy_thumb_list_from_to_aux(struct jit_state* st, ",
	"  copy_thumb_list_from_to_aux(st, ",
	"static __attribute__((always_inline)) inline void copy_thumb_list_from_to(struct jit_state* st)",
	"  mov_int_to_reg_binary(st, ",
	
	"eval_jitted_len(st)",
	"static __attribute__((always_inline)) inline void jit_alu32_aux(struct jit_state* st, ",
	"reset_init_jittedthumb(st)",
	"eval_ins_len(st)",
	
	"eval_offset(st)",
	"jit_alu32_pre(st)",
	"jit_alu32_thumb_save(st)",
	"jit_alu32_thumb_load(st)",
	
	"copy_thumb_list_from_to(st)",
	"jit_alu32_thumb_store(st)",
	"jit_alu32_thumb_reset(st)",
	"jit_alu32_post(st)",
	
	"  jit_alu32_aux(st, ",
	"void jit_alu32(struct jit_state* st)",
	"reset_init_entry_point(st)",
	"eval_entry_len(st)",
	"jit_alu32_thumb_store_succ_R0(st)",
	
	"static __attribute__((always_inline)) inline int get_offset",
	"static __attribute__((always_inline)) inline int get_immediate",
	"static __attribute__((always_inline)) inline unsigned char get_opcode_ins",
	"static __attribute__((always_inline)) inline unsigned char nat_to_opcode_alu32",
	"static __attribute__((always_inline)) inline unsigned int jit_alu32_store_register",
	
	"  magic_function(st, ",
	"static __attribute__((always_inline)) inline unsigned short construct_thumb_b",
	"static __attribute__((always_inline)) inline unsigned short construct_thumb2_shift_rd_rm",
	"static __attribute__((always_inline)) inline void jit_alu32_thumb_store_template_ins(struct jit_state* st, ",
	"static __attribute__((always_inline)) inline void jit_alu32_thumb_load_template_ins(struct jit_state* st, ",
	"static __attribute__((always_inline)) inline void jit_alu32_thumb_store_template_jit(struct jit_state* st, ",
	"static __attribute__((always_inline)) inline void jit_alu32_thumb_load_template_jit(struct jit_state* st, ",
	"static __attribute__((always_inline)) inline void jit_alu32_store_flag_jit(struct jit_state* st, ",	
	"static __attribute__((always_inline)) inline _Bool no_reg_load(struct jit_state* st)",
	
	"  jit_alu32_thumb_store_template_ins(st, ",
	"  jit_alu32_thumb_load_template_ins(st, ",
	"  jit_alu32_thumb_store_template_jit(st, ",
	"  jit_alu32_thumb_load_template_jit(st, ",
	"  jit_alu32_store_flag_jit(st, ",
	"no_reg_load(st)",
	
	"static __attribute__((always_inline)) inline void jit_alu32_to_thumb(struct jit_state* st, ",
	"  jit_alu32_to_thumb(st, ",
	"  add_key_value2(st, ",
	"= eval_key_value2_arm_ofs(st, ",
	"= eval_key_value2_alu32_ofs(st, ",
	
	//...
	
	"eval_pc(st)",
	"upd_pc(st, pc",
	"upd_pc_incr(st)",
	"  upd_reg(st, ",
	"= eval_reg(st, ",
	"eval_flag(st)",
	"= check_mem(st, ",
	
	"eval_mrs_regions(st)",
	"static __attribute__((always_inline)) inline void step_opcode_alu64(struct jit_state* st, ",
	"  step_opcode_alu64(st, ",
	"static __attribute__((always_inline)) inline void step_opcode_alu32(struct jit_state* st, ",
	"  step_opcode_alu32(st, ",
	"static __attribute__((always_inline)) inline void step_opcode_branch(struct jit_state* st, ",
	"  step_opcode_branch(st, ",
	"static __attribute__((always_inline)) inline void step_opcode_mem_ld_imm(struct jit_state* st, ",
	"  step_opcode_mem_ld_imm(st, ",
	"static __attribute__((always_inline)) inline void step_opcode_mem_ld_reg(struct jit_state* st, ",
	
	"  step_opcode_mem_ld_reg(st, ",
	"static __attribute__((always_inline)) inline void step_opcode_mem_st_imm(struct jit_state* st, ",
	"  step_opcode_mem_st_imm(st, ",
	"static __attribute__((always_inline)) inline void step_opcode_mem_st_reg(struct jit_state* st, ",
	"  step_opcode_mem_st_reg(st, ",
	"= load_mem(st, ",
	"  store_mem_imm(st, ",
	"  store_mem_reg(st, ",
	
	"static __attribute__((always_inline)) inline unsigned char *check_mem_aux(struct jit_state* st, ",
	"return check_mem_aux(st, ",
	"unsigned char *check_mem(struct jit_state* st, ",
	
	"static __attribute__((always_inline)) inline void step(struct jit_state* st)",
	"step(st); //print_jit_state(st);",
	"static __attribute__((always_inline)) inline void ibpf_interpreter_aux(struct jit_state* st, ",
	"  ibpf_interpreter_aux(st, ",
	"unsigned long long ibpf_interpreter(struct jit_state* st, ",
	"static __attribute__((always_inline)) inline struct memory_region *get_mem_region(",
	"eval_mrs_num(st)",
	"check_mem = check_mem_aux(st, ",
	"check_mem_aux(st, mem_reg_num",
	
	"static __attribute__((always_inline)) inline unsigned int get_dst(",
	"static __attribute__((always_inline)) inline unsigned int reg64_to_reg32(",
	"static __attribute__((always_inline)) inline unsigned int get_src(",
	"static __attribute__((always_inline)) inline long long eval_immediate(",
	"static __attribute__((always_inline)) inline unsigned long long get_src64(struct jit_state* st, ",
	"static __attribute__((always_inline)) inline unsigned int get_src32(struct jit_state* st, ",
	"= get_src64(st, ",
	"= get_src32(st, ",
	"static __attribute__((always_inline)) inline unsigned char get_opcode_alu64(",
	"static __attribute__((always_inline)) inline unsigned char get_opcode_alu32(",
	"static __attribute__((always_inline)) inline unsigned char get_opcode_branch(",
	"static __attribute__((always_inline)) inline unsigned char get_opcode_mem_ld_imm(",
	"static __attribute__((always_inline)) inline unsigned char get_opcode_mem_ld_reg(",
	"static __attribute__((always_inline)) inline unsigned char get_opcode_mem_st_imm(",
	"static __attribute__((always_inline)) inline unsigned char get_opcode_mem_st_reg(",
	"static __attribute__((always_inline)) inline unsigned char get_opcode(",
	"static __attribute__((always_inline)) inline unsigned int get_add(",
	"static __attribute__((always_inline)) inline unsigned int get_sub(",
	"static __attribute__((always_inline)) inline unsigned int get_addr_ofs(",
	"static __attribute__((always_inline)) inline _Bool is_well_chunk_bool(",
	"static __attribute__((always_inline)) inline unsigned char *check_mem_aux2(",
	"static __attribute__((always_inline)) inline unsigned char *get_block_ptr",
	"static __attribute__((always_inline)) inline unsigned int get_start_addr",
	"static __attribute__((always_inline)) inline unsigned int get_block_size",
	"static __attribute__((always_inline)) inline unsigned int get_block_perm",
	
	"const unsigned long long *l",
	"exec_function(st, ",
	
	"(opi == 36U)"
	
	};
	


const char delete_lines[] ="extern ";

int main(int argc, char *argv[])
{
    /* File pointer to hold reference of input file */
    FILE * ptr_r;
    FILE * ptr_w;
    int counter = CNT;
    int index;
    int before_start_point;
    int two_blanks;
    
    char buffer[BUFFER_SIZE];



    /*  Open all required files */
  
    if (argc != 3) {
      printf("invaild argument%d: expect only two filenames `obj` and `output` \n", argc);
    }
  
    ptr_r = fopen(argv[1], "r");
    ptr_w = fopen(argv[2], "w+");

    /* fopen() return NULL if unable to open file in given mode. */
    if (ptr_r == NULL || ptr_w == NULL)
    {
        /* Unable to open file hence exit */
        printf("\nUnable to open file.\n");
        printf("Please check whether file exists and you have read/write privilege.\n");
        exit(EXIT_SUCCESS);
    }

    before_start_point = 0;
    two_blanks = 0;
    while ((fgets(buffer, BUFFER_SIZE, ptr_r)) != NULL)
    {  //printf("%d\n", CNT-counter);
    	//if ((counter --) == 0) { break; }
    	/* deleting all lines before `struct memory_region *get_mem_region` */
    	if (before_start_point == 0 && strstr(buffer, start_point) == NULL){
    	  /* we just skip this line and don't write it */
    	  continue;
    	}
    	else {
    	  before_start_point = 1;
    	}
    	
    	if (strcmp(buffer, "\n") == 0){
    	  if(two_blanks == 0){
    	    two_blanks = 1;
    	  }
    	  else {//two_blanks == 1
    	    //printf("skip\n");
    	    continue;
    	  }
    	}
    	else if(strcmp(buffer, "}\n") == 0) {
    	  /* we just skip this line and don't write it */
    	  two_blanks = 0;
    	}
    	
    	/* Delete all lines starting by `extern  ` */
    	if (strstr(buffer, delete_lines) != NULL){
    	  /* we just skip this line and don't write it */
    	  continue;
    	}
    	
    	if(strcmp(buffer,"\n") == 0) { fputs(buffer, ptr_w); continue; }
    
    	//printf("readline: %s\n", buffer);
        // Replace all occurrence of word from current line
        for (index = 0; index < sizeof(old_words)/200; index ++){
          replaceAll(buffer, old_words[index], new_words[index]);
        }

        // After replacing write it to temp file.
        fputs(buffer, ptr_w);
    }

    //printf("repatch2 done!\n");
    /* Close all files to release resource */
    fclose(ptr_r);
    fclose(ptr_w);

    return 0;
}



/**
 * Replace all occurrences of a given a word in string.
 */
void replaceAll(char *str, const char *oldWord, const char *newWord)
{
    char *pos, temp[BUFFER_SIZE];
    int index = 0;
    int owlen;

    owlen = strlen(oldWord);

    // Fix: If oldWord and newWord are same it goes to infinite loop
    if (!strcmp(oldWord, newWord)) {
        return;
    }

    if ((pos = strstr(str, oldWord)) == NULL) {return ;}
    /*
     * Repeat till all occurrences are replaced. 
     */
    //while ((pos = strstr(str, oldWord)) != NULL)
    //{
        // Backup current line
        strcpy(temp, str);

        // Index of current found word
        index = pos - str;

        // Terminate str after word found index
        str[index] = '\0';

        // Concatenate str with new word 
        strcat(str, newWord);
        
        // Concatenate str with remaining words after 
        // oldword found index.
        strcat(str, temp + index + owlen);
    //}
}
