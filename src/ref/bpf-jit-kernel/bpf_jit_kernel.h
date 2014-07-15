#ifndef _BPF_JIT_KERNEL_H_
#define _BPF_JIT_KERNEL_H_

#include "hack.h"

#define BJK_BPF_MAX_NUM_INSTR    64

struct bjk_bpf_info {
   u16 bpf_program_num_elem;
   struct sock_filter bpf_program[BJK_BPF_MAX_NUM_INSTR];
   struct sk_filter *filter __attribute__((aligned(8)));
};

#endif
