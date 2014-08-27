#ifndef _HACK_H_
#define _HACK_H_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define CONFIG_BPF_JIT 1

#define KERNEL_DS 0
#define GFP_KERNEL 0
#define BUG_ON(condition) do { if (condition) abort(); } while (0)
#define BUILD_BUG_ON(condition) BUG_ON(condition)

/* XXX: hardwired */
#define PAGE_SIZE 4096

#define BIT(nr)                  (1UL << (nr))

#define SKF_LL_OFF    (-0x200000)

#define ENOMEM 12
#define EINVAL 22

#define ERR_PTR(err)    ((void *)((long)(err)))
#define PTR_ERR(ptr)    ((long)(ptr))
#define IS_ERR(ptr)     ((unsigned long)(ptr) > (unsigned long)(-1000))

#define __read_mostly

#define pr_err printf
#define pr_err_once printf

#define EXPORT_SYMBOL(sym)
#define EXPORT_SYMBOL_GPL(sym)

static inline void barrier(void) {}

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

typedef signed char s8;
typedef unsigned char u8;
typedef signed short s16;
typedef unsigned short u16;
typedef signed int s32;
typedef unsigned int u32;
typedef signed long s64;
typedef unsigned long u64;

#define noinline __attribute__((noinline))

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
   u16 protocol;
   union {
      u32 mark;
      u32 dropcount;
      u32 reserved_tailroom;
   };
   unsigned char *data;
};

static inline unsigned int skb_headlen(const struct sk_buff *skb)
{
	return skb->len - skb->data_len;
}

static inline void *skb_header_pointer(const struct sk_buff *skb, int offset,
				       int len, void *buffer)
{
	int hlen = skb_headlen(skb);

	if (hlen - offset >= len)
		return skb->data + offset;

/*
	if (skb_copy_bits(skb, offset, buffer, len) < 0)
		return NULL;

	return buffer;
*/
	return NULL;
}

void *kcalloc(size_t count, size_t size, int flags);
void *kmalloc(size_t size, int flags);
void *kmemdup(void *p, size_t size, int flags);
void *krealloc(void *p, size_t size, int flags);
#define kmalloc_array(count,size,flags) kcalloc(count,size,flags)
void kfree(void *ptr);

#endif


