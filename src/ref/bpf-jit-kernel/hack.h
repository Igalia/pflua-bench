#ifndef _HACK_H_
#define _HACK_H_

#include <stdio.h>
#include <string.h>

#define KERNEL_DS 0
#define GFP_KERNEL 0
#define BUILD_BUG_ON(condition) (0)

/* XXX: hardwired */
#define PAGE_SIZE 4096

#define SKF_LL_OFF    (-0x200000)

#define __read_mostly

#define pr_err printf
#define pr_err_once printf

#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)

#define max(x, y) ({                 \
   typeof(x) _max1 = (x);            \
   typeof(y) _max2 = (y);            \
   (void) (&_max1 == &_max2);        \
   _max1 > _max2 ? _max1 : _max2; })

#define unlikely
#define __user

#define sk_filter_proglen(fprog) (fprog->len * sizeof(fprog->filter[0]))
#define SK_RUN_FILTER(filter, ctx) (*filter->bpf_func)(ctx, filter->insnsi)

typedef signed char s8;
typedef unsigned char u8;
typedef signed short s16;
typedef unsigned short u16;
typedef signed int s32;
typedef unsigned int u32;
typedef signed long s64;
typedef unsigned long u64;

#ifdef __CHECKER__
#define __bitwise__ __attribute__((bitwise))
#else
#define __bitwise__
#endif
#ifdef __CHECK_ENDIAN__
#define __bitwise __bitwise__
#else
#define __bitwise
#endif

typedef u16 __bitwise __le16;
typedef u16 __bitwise __be16;
typedef u32 __bitwise __le32;
typedef u32 __bitwise __be32;
typedef u64 __bitwise __le64;
typedef u64 __bitwise __be64;

typedef int bool;

typedef long unsigned int size_t;

struct net_device {
   int ifindex;
};

struct sk_buff {
   struct net_device *dev;
   unsigned int len,
		data_len;
   u32 hash;
   u16 queue_mapping;
   u16 vlan_tci;
   u8 pkt_type:3,
      fclone:2,
      ipvs_property:1,
      peeked:1,
      nf_trace:1;
   __be16 protocol;
   union {
      u32 mark;
      u32 dropcount;
      u32 reserved_tailroom;
   };
   unsigned char *data;
};

struct sock_filter {    /* filter block */
   u16   code;   /* actual filter code */
   u8    jt;     /* jump true */
   u8    jf;     /* jump false */
   u32   k;      /* generic multiuse field */
};

struct sock_filter_int {
   u8    code;           /* opcode */
   u8    a_reg:4;        /* dest register */
   u8    x_reg:4;        /* source register */
   s16   off;            /* signed offset */
   s32   imm;            /* signed immediate constant */
};

struct sock_fprog {      /* Required for SO_ATTACH_FILTER. */
   unsigned short len;   /* Number of filter blocks */
   struct sock_filter __user *filter;
};

struct sk_filter {
   //atomic_t                refcnt;
   u32                     jited:1,        /* Is our filter JIT'ed? */
			   len:31;         /* Number of filter blocks */
   struct sock_fprog_kern  *orig_prog;     /* Original BPF program */
   //struct rcu_head         rcu;
   unsigned int            (*bpf_func)(const struct sk_buff *skb,
	                               const struct sock_filter_int *filter);
   union {
      struct sock_filter      insns[0];
      struct sock_filter_int  insnsi[0];
      //struct work_struct      work;
   };
};

static inline unsigned int sk_filter_size(unsigned int proglen)
{
   return max(sizeof(struct sk_filter),
	      offsetof(struct sk_filter, insns[proglen]));
}

enum {
	BPF_S_RET_K = 1,
	BPF_S_RET_A,
	BPF_S_ALU_ADD_K,
	BPF_S_ALU_ADD_X,
	BPF_S_ALU_SUB_K,
	BPF_S_ALU_SUB_X,
	BPF_S_ALU_MUL_K,
	BPF_S_ALU_MUL_X,
	BPF_S_ALU_DIV_X,
	BPF_S_ALU_MOD_K,
	BPF_S_ALU_MOD_X,
	BPF_S_ALU_AND_K,
	BPF_S_ALU_AND_X,
	BPF_S_ALU_OR_K,
	BPF_S_ALU_OR_X,
	BPF_S_ALU_XOR_K,
	BPF_S_ALU_XOR_X,
	BPF_S_ALU_LSH_K,
	BPF_S_ALU_LSH_X,
	BPF_S_ALU_RSH_K,
	BPF_S_ALU_RSH_X,
	BPF_S_ALU_NEG,
	BPF_S_LD_W_ABS,
	BPF_S_LD_H_ABS,
	BPF_S_LD_B_ABS,
	BPF_S_LD_W_LEN,
	BPF_S_LD_W_IND,
	BPF_S_LD_H_IND,
	BPF_S_LD_B_IND,
	BPF_S_LD_IMM,
	BPF_S_LDX_W_LEN,
	BPF_S_LDX_B_MSH,
	BPF_S_LDX_IMM,
	BPF_S_MISC_TAX,
	BPF_S_MISC_TXA,
	BPF_S_ALU_DIV_K,
	BPF_S_LD_MEM,
	BPF_S_LDX_MEM,
	BPF_S_ST,
	BPF_S_STX,
	BPF_S_JMP_JA,
	BPF_S_JMP_JEQ_K,
	BPF_S_JMP_JEQ_X,
	BPF_S_JMP_JGE_K,
	BPF_S_JMP_JGE_X,
	BPF_S_JMP_JGT_K,
	BPF_S_JMP_JGT_X,
	BPF_S_JMP_JSET_K,
	BPF_S_JMP_JSET_X,
	/* Ancillary data */
	BPF_S_ANC_PROTOCOL,
	BPF_S_ANC_PKTTYPE,
	BPF_S_ANC_IFINDEX,
	BPF_S_ANC_NLATTR,
	BPF_S_ANC_NLATTR_NEST,
	BPF_S_ANC_MARK,
	BPF_S_ANC_QUEUE,
	BPF_S_ANC_HATYPE,
	BPF_S_ANC_RXHASH,
	BPF_S_ANC_CPU,
	BPF_S_ANC_ALU_XOR_X,
	BPF_S_ANC_VLAN_TAG,
	BPF_S_ANC_VLAN_TAG_PRESENT,
	BPF_S_ANC_PAY_OFFSET,
};

void * kmalloc(size_t size, int flags);
void kfree(const void *ptr);

void bpf_jit_compile(struct sk_filter *fp);
void bpf_jit_free(struct sk_filter *fp);

#endif
