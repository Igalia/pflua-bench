#include <stdlib.h>

#include "hack.h"

extern void* _skb_copy_bits;
extern void* _bpf_internal_load_pointer_neg_helper;

int skb_copy_bits(const struct sk_buff *skb, int offset, void *to, int len)
{
#ifdef DBG
   printf("skb_copy_bits here!\n");
   fflush(0);
#endif
   abort();
   return 0;
}

void * kmalloc(size_t size, int flags) {
	void *p;
	if ((p = malloc(size)) == NULL) {
		printf("kmalloc failing!\n");
		fflush(0);
		exit(-1);
	}
	return p;
}

void * kcalloc(size_t len, size_t size, int flags) {
	void *p;
	if ((p = calloc(len, size)) == NULL) {
		printf("kcalloc failing!\n");
		fflush(0);
		exit(-1);
	}
	return p;
}

void * kmemdup(void *src, size_t len, int flags) {
	void *dst;
	if ((dst = malloc(len)) == NULL) {
		printf("kcalloc failing!\n");
		fflush(0);
		exit(-1);
	}
	memcpy(dst, src, len);
	return dst;
}

void * krealloc(void *p, size_t len, int flags) {
	void *ret;
	if ((ret = realloc(p, len)) == NULL) {
		printf("kcalloc failing!\n");
		fflush(0);
		exit(-1);
	}
	return ret;
}

void kfree(void *ptr) {
	if (ptr == NULL) {
		printf("kfree error!\n");
		fflush(0);
		exit(-1);
	} else
		free(ptr);
}

void *bpf_internal_load_pointer_neg_helper(const struct sk_buff *skb, int k, unsigned int size);

__attribute__((constructor)) void init(void) {
   _skb_copy_bits = skb_copy_bits;
   _bpf_internal_load_pointer_neg_helper = bpf_internal_load_pointer_neg_helper;
}
