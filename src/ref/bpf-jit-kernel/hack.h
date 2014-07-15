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

#define ENOMEM 12
#define EINVAL 22

#define __read_mostly

#define pr_err printf
#define pr_err_once printf

#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)
#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))

#define max(x, y) ({                 \
   typeof(x) _max1 = (x);            \
   typeof(y) _max2 = (y);            \
   (void) (&_max1 == &_max2);        \
   _max1 > _max2 ? _max1 : _max2; })

#define min(x, y) ({                 \
   typeof(x) _min1 = (x);            \
   typeof(y) _min2 = (y);            \
   (void) (&_min1 == &_min2);        \
   _min1 < _min2 ? _min1 : _min2; })

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
#define true 1
#define false 0

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

/*
 * Current version of the filter code architecture.
 */
#define BPF_MAJOR_VERSION 1
#define BPF_MINOR_VERSION 1

/*
 * Instruction classes
 */

#define BPF_CLASS(code) ((code) & 0x07)
#define         BPF_LD          0x00
#define         BPF_LDX         0x01
#define         BPF_ST          0x02
#define         BPF_STX         0x03
#define         BPF_ALU         0x04
#define         BPF_JMP         0x05
#define         BPF_RET         0x06
#define         BPF_MISC        0x07

/* ld/ldx fields */
#define BPF_SIZE(code)  ((code) & 0x18)
#define         BPF_W           0x00
#define         BPF_H           0x08
#define         BPF_B           0x10
#define BPF_MODE(code)  ((code) & 0xe0)
#define         BPF_IMM         0x00
#define         BPF_ABS         0x20
#define         BPF_IND         0x40
#define         BPF_MEM         0x60
#define         BPF_LEN         0x80
#define         BPF_MSH         0xa0

/* alu/jmp fields */
#define BPF_OP(code)    ((code) & 0xf0)
#define         BPF_ADD         0x00
#define         BPF_SUB         0x10
#define         BPF_MUL         0x20
#define         BPF_DIV         0x30
#define         BPF_OR          0x40
#define         BPF_AND         0x50
#define         BPF_LSH         0x60
#define         BPF_RSH         0x70
#define         BPF_NEG         0x80
#define		BPF_MOD		0x90
#define		BPF_XOR		0xa0

#define         BPF_JA          0x00
#define         BPF_JEQ         0x10
#define         BPF_JGT         0x20
#define         BPF_JGE         0x30
#define         BPF_JSET        0x40
#define BPF_SRC(code)   ((code) & 0x08)
#define         BPF_K           0x00
#define         BPF_X           0x08

/* ret - BPF_K and BPF_X also apply */
#define BPF_RVAL(code)  ((code) & 0x18)
#define         BPF_A           0x10

/* misc */
#define BPF_MISCOP(code) ((code) & 0xf8)
#define         BPF_TAX         0x00
#define         BPF_TXA         0x80

#ifndef BPF_MAXINSNS
#define BPF_MAXINSNS 4096
#endif

/*
 * Macros for filter block array initializers.
 */
#ifndef BPF_STMT
#define BPF_STMT(code, k) { (unsigned short)(code), 0, 0, k }
#endif
#ifndef BPF_JUMP
#define BPF_JUMP(code, k, jt, jf) { (unsigned short)(code), jt, jf, k }
#endif

/*
 * Number of scratch memory words for: BPF_ST and BPF_STX
 */
#define BPF_MEMWORDS 16

/* RATIONALE. Negative offsets are invalid in BPF.
   We use them to reference ancillary data.
   Unlike introduction new instructions, it does not break
   existing compilers/optimizers.
 */
#define SKF_AD_OFF    (-0x1000)
#define SKF_AD_PROTOCOL 0
#define SKF_AD_PKTTYPE	4
#define SKF_AD_IFINDEX	8
#define SKF_AD_NLATTR	12
#define SKF_AD_NLATTR_NEST	16
#define SKF_AD_MARK	20
#define SKF_AD_QUEUE	24
#define SKF_AD_HATYPE	28
#define SKF_AD_RXHASH	32
#define SKF_AD_CPU	36
#define SKF_AD_ALU_XOR_X	40
#define SKF_AD_VLAN_TAG	44
#define SKF_AD_VLAN_TAG_PRESENT 48
#define SKF_AD_PAY_OFFSET	52
#define SKF_AD_MAX	56
#define SKF_NET_OFF   (-0x100000)
#define SKF_LL_OFF    (-0x200000)

void *kmalloc(size_t size, int flags);
void kfree(void *ptr);

void bpf_jit_compile(struct sk_filter *fp);
void bpf_jit_free(struct sk_filter *fp);

#endif


