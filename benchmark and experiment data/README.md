# Benchmark

The following experiments are only tested on `nrf52840dk` (+ host OS: ubuntu).

- `bench_bpf_jit_coq`: test our jit compiler + ibpf interpreter using fletcher32 algorithm
- `bench_bpf_jit_coq_unit`: unit test

# Experiments

Firstly, copy the folder `bench_*` to your RIOT-OS's directory `tests`.

After the support board is connceted to you labtop by USB,
You need two shells:

- One for observing the output;
```shell
/YOUR-PATH/RIOT/dist/tools/pyterm/pyterm -p "/dev/ttyACM0" -b "115200"
```

- Another for compiling/debugging RIOT-OS + target program

```shell
BOARD=nrf52840dk make -C tests/bench_bpf_jit_coq WERROR=0 flash debug # debug could be removed
```

# How to build your benchmarks using HAVM
0. including the head file of the ibpf interpereter (i.e. `#include "ibpf_interpreter.h"`)

1. including your rbpf binary list (i.e. `#include "fletcher32_compcert_bpf.h"`) which must satisfy the following constraints:
  - No alu-32 shift-by-imm, div-by-imm and mod instructions
  - div32 must be div r0 r0 r1
  - the lddw instruction must be splitted into two instructions: i.e. `lddw dst imm next_imm` (opcode := 0x18) -> `lddw_low dst imm` (opcode := 0x18) + `lddw_high dst next_imm` (opcode := 0x10)
  
2. declaring the following global data structures (Just copy it into your benchmark):
```C
// required by rBPF
static uint8_t _bpf_stack[512];

// defining a flag that our jit_state will point to it because
//   when exeucting the jitted code, it may modify the flag
//   (e.g. jitted code does a div-by-zero)
static unsigned int bpf_flag = vBPF_OK;

// defining a bpf register map, and the jit_state will also point to it
unsigned long long bpf_regs_map[11] = {0LLU};

// our jit compiler need an array to recode all entry points of your rBPF binary list.
static unsigned int entry_point_list[ENTRY_POINT_MAX_LENGTH] = {0U};

// a temporary array to store jitted code of each alu32 segment
static unsigned short thumb_list[JITTED_LIST_MAX_LENGTH] = {0U};

// the final artifact: jitted alu32 binary
__attribute((aligned(4))) static unsigned short jitted_thumb_list[JITTED_LIST_MAX_LENGTH] = {0U};

// a temporary array to recode that if a bpf register should be loaded into an arm register before jit or be stored after jit
static unsigned int bpf_load_store_regs[11] = {0U};
```

3. we need the following function to tell the ibpf interpreter how to execute the jitted code. (Just copy it)
```C
 __attribute__ ((noinline)) void _magic_function(unsigned int ofs, struct jit_state* st){
  int res = 0;
  // disables some compiler optimizations
  __asm volatile (
    "orr %[input_0], #0x1\n\t"
    "mov r12, sp\n\t"
    "sub sp, sp, #48\n\t"
    "str r12, [sp, #0]\n\t"
    "mov pc, %[input_0]\n\t"
    : [result] "=r" (res)
    : [input_1] "r" (st), [input_0] "r" (jitted_thumb_list + ofs)
    : "cc" //The instructions may modify the condition code flags
  );
  return ;
}
```

4. declaring your jit state
```C
static struct jit_state st = {
    .pc_loc    	= 0U,
    .flag      	= &bpf_flag,
    .regs_st   	= bpf_regs_map,
    .mrs_num   	= 2U, // the number of your memory regions
    .bpf_mrs   	= 0,
    .ins_len   	= sizeof(your-bin)/8, // your application
    .entry_len 	= 0U,
    .ep_list   	= entry_point_list,
    .use_IR11   	= 0,
    .load_store_regs 	= bpf_load_store_regs,
    .offset		= 0U,
    .thumb_len		= 0U,
    .thumb		= thumb_list,
    .ibpf       	= (unsigned long long *) your-bin, // your application
    .jitted_len	= 0U,
    .jitted_list	= jitted_thumb_list
  };
```

5. declaring your memory regions as global variables
```C
//the default value is all 0
static struct memory_region mr_stk = {
  	.start_addr = 0,
  	.block_size = 0,
  	.block_perm = 0,
  	.block_ptr  = 0
  };
```

6. initializing your memory regions and register map
```C
int main(void){ 
  ...

  mr_stk.start_addr = (uintptr_t) _bpf_stack;
  mr_stk.block_size = 512;
  mr_stk.block_perm = Writable; // set Wrtiable when store and Readable when only load
  mr_stk.block_ptr  = (unsigned char *) (uintptr_t) _bpf_stack;

  struct memory_region my_memory_regions[] = { mr_stk, ...};
  st.bpf_mrs = my_memory_regions; // initialze your memory regions
  
  bpf_regs_map[1] = (unsigned long long) (uintptr_t) (const uint16_t *) wrap_around_data; // input value
  bpf_regs_map[2] = (unsigned long long) sizeof(wrap_around_data)/2; // input value
  bpf_regs_map[10] = (unsigned long long) (uintptr_t) (_bpf_stack+512); // point to the top of the bpf stack  
```

7. calling jit and then interpreter
```C
jit_alu32(&st);
result = ibpf_interpreter(&st, 10000); // the second argument ensures that the interpreter always terminates.
```


