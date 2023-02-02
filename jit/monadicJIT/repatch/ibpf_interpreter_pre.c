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

#include "ibpf_interpreter.h"


void print_reg (unsigned int r) {
  printf("R%d ", r);
  return ;
}

void print_bpf_insstruction (unsigned long long ins){
  unsigned int op, dst, src;
  int imm, ofs;
  op  = (unsigned int) ins & 255LLU;
  dst = (unsigned int) ((ins & 4095LLU) >> 8LLU);
  src = (unsigned int) ((ins & 65535LLU) >> 12LLU);
  imm = (int) (ins >> 32LLU);
  ofs = (int) (short) (ins << 32LLU >> 48LLU);
  switch (op) {
    //alu64
    case 0x07:
      printf("bpf_add64 "); print_reg(dst); printf("%d", imm); return ;
    case 0x17:
      printf("bpf_sub64 "); print_reg(dst); printf("%d", imm); return ;
    case 0x27:
      printf("bpf_mul64 "); print_reg(dst); printf("%d", imm); return ;
    case 0x37:
      printf("bpf_div64 "); print_reg(dst); printf("%d", imm); return ;
    case 0x47:
      printf("bpf_or64  "); print_reg(dst); printf("%d", imm); return ;
    case 0x57:
      printf("bpf_and64 "); print_reg(dst); printf("%d", imm); return ;
    case 0x67:
      printf("bpf_lsh64 "); print_reg(dst); printf("%d", imm); return ;
    case 0x77:
      printf("bpf_rsh64 "); print_reg(dst); printf("%d", imm); return ;
    case 0x87:
      printf("bpf_neg64 "); print_reg(dst); printf("%d", imm); return ;
    case 0x97:
      printf("bpf_mod64 "); print_reg(dst); printf("%d", imm); return ;
    case 0xa7:
      printf("bpf_xor64 "); print_reg(dst); printf("%d", imm); return ;
    case 0xb7:
      printf("bpf_mov64 "); print_reg(dst); printf("%d", imm); return ;
    case 0xc7:
      printf("bpf_arsh64 "); print_reg(dst); printf("%d", imm); return ;
      
    case 0x0f:
      printf("bpf_add64 "); print_reg(dst); print_reg(src); return ;
    case 0x1f:
      printf("bpf_sub64 "); print_reg(dst); print_reg(src); return ;
    case 0x2f:
      printf("bpf_mul64 "); print_reg(dst); print_reg(src); return ;
    case 0x3f:
      printf("bpf_div64 "); print_reg(dst); print_reg(src); return ;
    case 0x4f:
      printf("bpf_or64  "); print_reg(dst); print_reg(src); return ;
    case 0x5f:
      printf("bpf_and64 "); print_reg(dst); print_reg(src); return ;
    case 0x6f:
      printf("bpf_lsh64 "); print_reg(dst); print_reg(src); return ;
    case 0x7f:
      printf("bpf_rsh64 "); print_reg(dst); print_reg(src); return ;
    case 0x9f:
      printf("bpf_mod64 "); print_reg(dst); print_reg(src); return ;
    case 0xaf:
      printf("bpf_xor64 "); print_reg(dst); print_reg(src); return ;
    case 0xbf:
      printf("bpf_mov64 "); print_reg(dst); print_reg(src); return ;
    case 0xcf:
      printf("bpf_arsh64 "); print_reg(dst); print_reg(src); return ;
      
    //alu32  
    case 0x04:
      printf("bpf_add32 "); print_reg(dst); printf("%d", imm); return ;
    case 0x14:
      printf("bpf_sub32 "); print_reg(dst); printf("%d", imm); return ;
    case 0x24:
      printf("bpf_mul32 "); print_reg(dst); printf("%d", imm); return ;
    case 0x34:
      printf("bpf_div32 "); print_reg(dst); printf("%d", imm); return ;
    case 0x44:
      printf("bpf_or32  "); print_reg(dst); printf("%d", imm); return ;
    case 0x54:
      printf("bpf_and32 "); print_reg(dst); printf("%d", imm); return ;
    case 0x64:
      printf("bpf_lsh32 "); print_reg(dst); printf("%d", imm); return ;
    case 0x74:
      printf("bpf_rsh32 "); print_reg(dst); printf("%d", imm); return ;
    case 0x84:
      printf("bpf_neg32 "); print_reg(dst); printf("%d", imm); return ;
    case 0x94:
      printf("bpf_mod32 "); print_reg(dst); printf("%d", imm); return ;
    case 0xa4:
      printf("bpf_xor32 "); print_reg(dst); printf("%d", imm); return ;
    case 0xb4:
      printf("bpf_mov32 "); print_reg(dst); printf("%d", imm); return ;
    case 0xc4:
      printf("bpf_arsh32 "); print_reg(dst); printf("%d", imm); return ;
    case 0xd4:
      printf("bpf_jit "); printf("%d", ofs); printf(", %d", imm); return ;
      
    case 0x0c:
      printf("bpf_add32 "); print_reg(dst); print_reg(src); return ;
    case 0x1c:
      printf("bpf_sub32 "); print_reg(dst); print_reg(src); return ;
    case 0x2c:
      printf("bpf_mul32 "); print_reg(dst); print_reg(src); return ;
    case 0x3c:
      printf("bpf_div32 "); print_reg(dst); print_reg(src); return ;
    case 0x4c:
      printf("bpf_or32  "); print_reg(dst); print_reg(src); return ;
    case 0x5c:
      printf("bpf_and32 "); print_reg(dst); print_reg(src); return ;
    case 0x6c:
      printf("bpf_lsh32 "); print_reg(dst); print_reg(src); return ;
    case 0x7c:
      printf("bpf_rsh32 "); print_reg(dst); print_reg(src); return ;
    case 0x9c:
      printf("bpf_mod32 "); print_reg(dst); print_reg(src); return ;
    case 0xac:
      printf("bpf_xor32 "); print_reg(dst); print_reg(src); return ;
    case 0xbc:
      printf("bpf_mov32 "); print_reg(dst); print_reg(src); return ;
    case 0xcc:
      printf("bpf_arsh32 "); print_reg(dst); print_reg(src); return ;
      
    //memory  
    case 0x10:
      printf("bpf_lddw_low "); print_reg(dst); printf("%d", imm); return ;
    case 0x18:
      printf("bpf_lddw_high "); print_reg(dst); printf("%d", imm); return ;
      
    case 0x61:
      printf("bpf_ldxw  "); print_reg(dst); printf(", ["); print_reg(src); printf("+ %d]", ofs); return ;
    case 0x69:
      printf("bpf_ldxh  "); print_reg(dst); printf(", ["); print_reg(src); printf("+ %d]", ofs); return ;
    case 0x71:
      printf("bpf_ldxb  "); print_reg(dst); printf(", ["); print_reg(src); printf("+ %d]", ofs); return ;
    case 0x79:
      printf("bpf_ldxdw "); print_reg(dst); printf(", ["); print_reg(src); printf("+ %d]", ofs); return ;
      
    case 0x62:
      printf("bpf_stw  "); printf("["); print_reg(dst); printf("+ %d]", ofs); printf(", %d", imm); return ;
    case 0x6a:
      printf("bpf_sth  "); printf("["); print_reg(dst); printf("+ %d]", ofs); printf(", %d", imm); return ;
    case 0x72:
      printf("bpf_stb  "); printf("["); print_reg(dst); printf("+ %d]", ofs); printf(", %d", imm); return ;
    case 0x7a:
      printf("bpf_stdw "); printf("["); print_reg(dst); printf("+ %d]", ofs); printf(", %d", imm); return ;
      
    case 0x63:
      printf("bpf_stxw  "); printf("["); print_reg(dst); printf("+ %d]", ofs); printf(", %d", imm); return ;
    case 0x6b:
      printf("bpf_stxh  "); printf("["); print_reg(dst); printf("+ %d]", ofs); printf(", %d", imm); return ;
    case 0x73:
      printf("bpf_stxb  "); printf("["); print_reg(dst); printf("+ %d]", ofs); printf(", %d", imm); return ;
    case 0x7b:
      printf("bpf_stxdw "); printf("["); print_reg(dst); printf("+ %d]", ofs); printf(", %d", imm); return ;
    
    //branch
    case 0x05:
      printf("bpf_ja "); printf(" +%d]", ofs); return ;
      
    case 0x15:
      printf("bpf_jeq "); print_reg(dst); printf(", %d", imm);  printf(", +%d", ofs); return ;
    case 0x25:
      printf("bpf_jgt "); print_reg(dst); printf(", %d", imm);  printf(", +%d", ofs); return ;
    case 0x35:
      printf("bpf_jge "); print_reg(dst); printf(", %d", imm);  printf(", +%d", ofs); return ;
    case 0xa5:
      printf("bpf_jlt "); print_reg(dst); printf(", %d", imm);  printf(", +%d", ofs); return ;
    case 0xb5:
      printf("bpf_jle "); print_reg(dst); printf(", %d", imm);  printf(", +%d", ofs); return ;
    case 0x45:
      printf("bpf_jset "); print_reg(dst); printf(", %d", imm);  printf(", +%d", ofs); return ;
    case 0x55:
      printf("bpf_jne "); print_reg(dst); printf(", %d", imm);  printf(", +%d", ofs); return ;
    case 0x65:
      printf("bpf_jsgt "); print_reg(dst); printf(", %d", imm);  printf(", +%d", ofs); return ;
    case 0x75:
      printf("bpf_jsge "); print_reg(dst); printf(", %d", imm);  printf(", +%d", ofs); return ;
    case 0xc5:
      printf("bpf_jslt "); print_reg(dst); printf(", %d", imm);  printf(", +%d", ofs); return ;
    case 0xd5:
      printf("bpf_jsle "); print_reg(dst); printf(", %d", imm);  printf(", +%d", ofs); return ;
      
    case 0x1d:
      printf("bpf_jeq "); print_reg(dst); printf(", "); print_reg(src);  printf(", +%d", ofs); return ;
    case 0x2d:
      printf("bpf_jgt "); print_reg(dst); printf(", "); print_reg(src);  printf(", +%d", ofs); return ;
    case 0x3d:
      printf("bpf_jge "); print_reg(dst); printf(", "); print_reg(src);  printf(", +%d", ofs); return ;
    case 0xad:
      printf("bpf_jlt "); print_reg(dst); printf(", "); print_reg(src);  printf(", +%d", ofs); return ;
    case 0xbd:
      printf("bpf_jle "); print_reg(dst); printf(", "); print_reg(src);  printf(", +%d", ofs); return ;
    case 0x4d:
      printf("bpf_jset "); print_reg(dst); printf(", "); print_reg(src);  printf(", +%d", ofs); return ;
    case 0x5d:
      printf("bpf_jne "); print_reg(dst); printf(", "); print_reg(src);  printf(", +%d", ofs); return ;
    case 0x6d:
      printf("bpf_jsgt "); print_reg(dst); printf(", "); print_reg(src);  printf(", +%d", ofs); return ;
    case 0x7d:
      printf("bpf_jsge "); print_reg(dst); printf(", "); print_reg(src);  printf(", +%d", ofs); return ;
    case 0xcd:
      printf("bpf_jslt "); print_reg(dst); printf(", "); print_reg(src);  printf(", +%d", ofs); return ;
    case 0xdd:
      printf("bpf_jsle "); print_reg(dst); printf(", "); print_reg(src);  printf(", +%d", ofs); return ;
      
    case 0x85:
      printf("bpf_call "); printf(" %d", imm); return ;
    case 0x95:
      printf("bpf_exit "); return ;
    default: printf("error: op = %x", op);
      return;
      
  }
}

void print_jit_state(struct jit_state* st){
  printf("pc= %02d flag= %d\n",  (*st).pc_loc, *((*st).flag));
    print_u64_dec((*st).regs_st[0]);
    printf("(R0)\n");
    print_u64_dec((*st).regs_st[1]);
    printf("(R1)\n");
    print_u64_dec((*st).regs_st[2]);
    printf("(R2)\n");
    print_u64_dec((*st).regs_st[3]);
    printf("(R3)\n");
    print_u64_dec((*st).regs_st[4]);
    printf("(R4)\n");
    print_u64_dec((*st).regs_st[5]);
    printf("(R5)\n");
    print_u64_dec((*st).regs_st[6]);
    printf("(R6)\n");
    print_u64_dec((*st).regs_st[7]);
    printf("(R7)\n");
    print_u64_dec((*st).regs_st[8]);
    printf("(R8)\n");
    print_u64_dec((*st).regs_st[9]);
    printf("(R9)\n");
    print_u64_dec((*st).regs_st[10]);
    printf("(R10)\n");
  return ;
}


void print_load_store_regs(struct jit_state* st){
  for(unsigned i = 0; i < 11; i++){
    printf("R%d",i);
    if ((*st).load_store_regs[i] == 0) {
      printf("_perm = NonPerm; ");
    } else if ((*st).load_store_regs[i] == 1) {
      printf("_perm = LoadPerm; ");
    } else if ((*st).load_store_regs[i] == 2) {
      printf("_perm = StorePerm; ");
    } else if ((*st).load_store_regs[i] == 3) {
      printf("_perm = LoadStorePerm; ");
    } else {
      printf("_perm = Undef; ");
    }
  }
  printf("\n");
  
  return ;
}

void print_thumb(struct jit_state* st){
  printf("thumb list: ");
  for(unsigned i = 0; i < (*st).thumb_len; i++) {
    printf("%x: %u; ", i, (*st).thumb[i]);
    if ((i+1)%8 == 0) { printf("\n"); }
  }
  printf("\n");
  return ;
}

void print_ibpf(struct jit_state* st){
  printf("ibpf list: ");
  for(unsigned i = 0; i < (*st).ins_len; i++) {
    print_bpf_insstruction((*st).jit_ins[i]);
    printf("(%d)\n", i);
  }
  printf("\n");
  return ;
}

void print_jitted_arm(struct jit_state* st){
  printf("jitted thumb list: ");
  for(unsigned i = 0; i < (*st).jitted_len; i++) {
    printf("0x%x: 0x%x\n ", i, (*st).jitted_list[i]);
    //if ((i+1)%8 == 0) { printf("\n"); }
  }
  printf("\n");
  return ;
}

void print_jit_state_all(struct jit_state* st){
  print_jit_state(st);
  print_ibpf(st);
  print_load_store_regs(st);
  print_jitted_arm(st);
  return ;
}

static __attribute__((always_inline)) inline unsigned int eval_pc (struct jit_state* st) {
  return (*st).pc_loc;
}

static __attribute__((always_inline)) inline void upd_pc(struct jit_state* st, unsigned int pc) {
  (*st).pc_loc = pc;
  return ;
}
static __attribute__((always_inline)) inline void upd_pc_incr(struct jit_state* st) {
  (*st).pc_loc = (*st).pc_loc+1;
  return ;
}


static __attribute__((always_inline)) inline unsigned long long eval_reg(struct jit_state* st, unsigned int i){
  return (*st).regs_st[i];
}

static __attribute__((always_inline)) inline void upd_reg (struct jit_state* st, unsigned int i, unsigned long long v){
  (*st).regs_st[i] = v;
  return ;
}

static __attribute__((always_inline)) inline unsigned eval_flag(struct jit_state* st){
  return *((*st).flag);
}

static __attribute__((always_inline)) inline void upd_flag(struct jit_state* st, unsigned f){
  *((*st).flag) = f;
  return ;
}

static __attribute__((always_inline)) inline unsigned int eval_mrs_num(struct jit_state* st){
  return (*st).mrs_num;
}

static __attribute__((always_inline)) inline struct memory_region *eval_mrs_regions(struct jit_state* st){
  return (*st).bpf_mrs;
}


static __attribute__((always_inline)) inline unsigned long long load_mem(struct jit_state* st, unsigned int chunk, unsigned char* addr){
  switch (chunk) {
    case 1: return *(unsigned char *) addr;
    case 2: return *(unsigned short *) addr;
    case 4: return *(unsigned int *) addr;
    case 8: return *(unsigned long long *) addr;
    default: /*printf ("load:addr = %" PRIu64 "\n", v); (*st).flag = BPF_ILLEGAL_MEM;*/ return 0LLU;
  }
}

static __attribute__((always_inline)) inline void store_mem_reg(struct jit_state* st, unsigned char* addr, unsigned int chunk, unsigned long long v){
  switch (chunk) {
    case 1: *(unsigned char *) addr = v; return ;
    case 2: *(unsigned short *) addr = v; return ;
    case 4: *(unsigned int *) addr = v; return ;
    case 8: *(unsigned long long *) addr = v; return ;
    default: /*printf ("store_reg:addr = %" PRIu64 "\n", addr); (*st).flag = BPF_ILLEGAL_MEM;*/ return ;
  }
}

static __attribute__((always_inline)) inline void store_mem_imm(struct jit_state* st, unsigned char* addr, unsigned int chunk, int v){
  switch (chunk) {
    case 1: *(unsigned char *) addr = v; return ;
    case 2: *(unsigned short *) addr = v; return ;
    case 4: *(unsigned int *) addr = v; return ;
    case 8: *(unsigned long long *) addr = v; return ;
    default: /*printf ("store_imm:addr = %" PRIu64 "\n", addr); (*st).flag = BPF_ILLEGAL_MEM;*/ return ;
  }
}

static __attribute__((always_inline)) inline unsigned int eval_ins_len(struct jit_state* st)
{
  return (*st).ins_len;
}

static __attribute__((always_inline)) inline unsigned long long eval_ins(struct jit_state* st, unsigned int idx)
{ //print_jit_state(st);
  return *((*st).jit_ins + idx);
}

static __attribute__((always_inline)) inline _Bool cmp_ptr32_nullM(unsigned char* addr){
   return (addr == 0);
}

static __attribute__((always_inline)) inline unsigned int get_dst(unsigned long long ins)
{
  return (unsigned int) ((ins & 4095LLU) >> 8LLU);
}

static __attribute__((always_inline)) inline unsigned int get_src(unsigned long long ins)
{
  return (unsigned int) ((ins & 65535LLU) >> 12LLU);
}

static __attribute__((always_inline)) inline struct memory_region *get_mem_region(unsigned int n, struct memory_region *mrs)
{
  return mrs + n;
}

static __attribute__((always_inline)) inline unsigned char *_bpf_get_call(int imm) {
  /* deleting `return NULL;` and adding your system APIs
  switch (imm) {
    default: return ...
  }
  */
  return NULL;
}

static __attribute__((always_inline)) inline unsigned int exec_function(struct jit_state* st, unsigned char * ptr){
  if (ptr == 0){
    *((*st).flag) = vBPF_ILLEGAL_CALL;
    return 0U;
  }
  else {
    /**do something e.g. print; */
    return 0U;
  }
}

static __attribute__((always_inline)) inline void upd_IR11_jittedthumb(struct jit_state* st, _Bool f){
  (*st).use_IR11 = f;
  return ;
}

static __attribute__((always_inline)) inline void add_ins_jittedthumb(struct jit_state* st, unsigned int ins){
  if ((*st).ins_len < JITTED_LIST_MAX_LENGTH){
    (*st).thumb[(*st).thumb_len] = ins;
    (*st).thumb_len = (*st).thumb_len + 1U;
    return ;
  }
  else {
    *((*st).flag) = vBPF_ILLEGAL_ARM_LEN; return ;
  }
}

static __attribute__((always_inline)) inline void upd_bpf_offset_jittedthumb(struct jit_state* st){
  (*st).offset = (*st).offset + 1U;
  return ;
}

static __attribute__((always_inline)) inline void upd_load_store_regs_jittedthumb(struct jit_state* st, unsigned int r, unsigned int ls){
  unsigned int history;
  history = (*st).load_store_regs[r];
  if (ls == LoadPerm) {
    if ((history == NonPerm) || (history == LoadPerm)) {
      (*st).load_store_regs[r] = LoadPerm;
    }
    else if (history == StorePerm) {
      (*st).load_store_regs[r] = StorePerm;
    }
    else if (history == LoadAndStore) {
      (*st).load_store_regs[r] = LoadAndStore;
    }
  }
  else if (ls == StorePerm) {
    if (history == NonPerm) {
      (*st).load_store_regs[r] = StorePerm;
    }
    else if (history == LoadPerm) {
      (*st).load_store_regs[r] = LoadAndStore;
    }
    else if (history == StorePerm) {
      (*st).load_store_regs[r] = StorePerm;
    }
    else if (history == LoadAndStore) {
      (*st).load_store_regs[r] = LoadAndStore;
    }  
  }
  else if (ls == LoadAndStore) {
    if (history == NonPerm) {
      (*st).load_store_regs[r] = LoadAndStore;
    }
    else if (history == LoadPerm) {
      (*st).load_store_regs[r] = LoadAndStore;
    }
    else if (history == StorePerm) {
      (*st).load_store_regs[r] = StorePerm;
    }
    else if (history == LoadAndStore) {
      (*st).load_store_regs[r] = LoadAndStore;
    } 
  }
  return ;
}

static __attribute__((always_inline)) inline void upd_thumb_jittedthumb(struct jit_state* st, unsigned int ins, unsigned int pc){
  (*st).thumb[pc] = ins;
  return ;
}

static __attribute__((always_inline)) inline void upd_jitted_list(struct jit_state* st, unsigned int ins){
  (*st).jitted_list[(*st).jitted_len] = ins;
  (*st).jitted_len = (*st).jitted_len + 1U;
  return ;
}


static __attribute__((always_inline)) inline void magic_function(struct jit_state* st, unsigned int ofs){
  //_magic_function is user-defined or compcert build-in
  // for user-defined, we swapped the order to make sure r0 is the start address of jitted_list while r1 is the start address of jit_state.
  _magic_function(ofs, st);
  return ;
}

static __attribute__((always_inline)) inline _Bool eval_use_IR11(struct jit_state* st){
  return (*st).use_IR11;
}

static __attribute__((always_inline)) inline unsigned int eval_offset(struct jit_state* st){
  return (*st).offset;
}

static __attribute__((always_inline)) inline unsigned int eval_thumb_len(struct jit_state* st){
  return (*st).thumb_len;
}

static __attribute__((always_inline)) inline unsigned int eval_jitted_len(struct jit_state* st){
  return (*st).jitted_len;
}

static __attribute__((always_inline)) inline _Bool is_non_reg(struct jit_state* st, unsigned int r){
  return (*st).load_store_regs[r] == 0U;
}

static __attribute__((always_inline)) inline _Bool is_load_reg(struct jit_state* st, unsigned int r){
  return ((*st).load_store_regs[r] == 1U) || ((*st).load_store_regs[r] == 3U);
}

static __attribute__((always_inline)) inline _Bool is_store_reg(struct jit_state* st, unsigned int r){
  return ((*st).load_store_regs[r] == 2U) || ((*st).load_store_regs[r] == 3U);
}

// a recursion implementation of power2 to replace pow(2, _) from math.h because CompCert doesn't support math.h
static __attribute__((always_inline)) inline unsigned int power2(unsigned int width){
  if (width == 0U) {
    return 1U;
  }
  else {
    return 2U * power2(width - 1U);
  }
}

static __attribute__((always_inline)) inline unsigned int decode_thumb(unsigned int ins, unsigned int from, unsigned int size){
  return ( (ins >> from) & (power2(size) - 1U) );
}

static __attribute__((always_inline)) inline unsigned int encode_thumb(unsigned int v, unsigned int ins, unsigned int from, unsigned int size){
  unsigned int mask;
  mask = (power2(size) - 1U) << from;
  return ( ((v & (power2(size) - 1U)) << from) | (ins & (~mask)) );
}

static __attribute__((always_inline)) inline unsigned int reg_of_ireg(unsigned int ir){
  return ir;
}

static __attribute__((always_inline)) inline unsigned char opcode_reg_of_imm(unsigned char op){
  switch (op) {
    case 4:
      return 12;
    case 20:
      return 28;
    case 36:
      return 44;
    case 68:
      return 76;
    case 84:
      return 92;
    case 164:
      return 172;
    case 180:
      return 188;
    default:
      return 0;
  }
}

static __attribute__((always_inline)) inline unsigned int eval_thumb_ins(struct jit_state* st, unsigned int idx){
  return *((*st).thumb + idx);
}

static __attribute__((always_inline)) inline _Bool ins_is_bpf_alu32(unsigned long long ins){
  unsigned char op;
  op = (unsigned char) (ins & 255LLU);
  return (op == 4) || (op == 12) ||
  	 (op == 20) || (op == 28) ||
  	 (op == 36) || (op == 44) ||
  	 (op == 60) ||
  	 (op == 68) || (op == 76) ||
  	 (op == 84) || (op == 92) ||
  	 (op == 108) || (op == 124) ||
  	 (op == 132) ||
  	 (op == 164) || (op == 172) ||
  	 (op == 180) || (op == 188) ||
  	 (op == 204);
}
static __attribute__((always_inline)) inline _Bool ins_is_bpf_jump(unsigned long long ins){
  unsigned char op;
  op = (unsigned char) (ins & 255LLU);
  return (op == 5) ||
  	 (op == 21) || (op == 29) ||
  	 (op == 37) || (op == 45) ||
  	 (op == 53) || (op == 61) ||
  	 (op == 69) || (op == 77) ||
  	 (op == 85) || (op == 93) ||
  	 (op == 101) || (op == 109) ||
  	 (op == 117) || (op == 125) ||
  	 (op == 165) || (op == 173) ||
  	 (op == 181) || (op == 189) ||
  	 (op == 197) || (op == 205) ||
  	 (op == 213) || (op == 221);
  
}

static __attribute__((always_inline)) inline void reset_init_jittedthumb(struct jit_state* st){
  (*st).use_IR11 = 0;
  for (int i = 0; i < 11; i ++) { (*st).load_store_regs[i] = NonPerm; }
  (*st).offset = 0U;
  (*st).thumb_len = 0U;
  return ;
}

static __attribute__((always_inline)) inline unsigned int eval_key_value2_arm_ofs(struct jit_state* st, unsigned int key){
  return (*st).kv2[key].arm_ofs;
}

static __attribute__((always_inline)) inline unsigned int eval_key_value2_alu32_ofs(struct jit_state* st, unsigned int key){
  return (*st).kv2[key].alu32_ofs;
}

static __attribute__((always_inline)) inline void add_key_value2(struct jit_state* st, unsigned int pc, unsigned int ofs0, unsigned int ofs1){
  (*st).kv2[pc].arm_ofs = ofs0;
  (*st).kv2[pc].alu32_ofs = ofs1;
  return ;
}

/*******************below code are automatically generated by dx (after repatch) ***************************/
