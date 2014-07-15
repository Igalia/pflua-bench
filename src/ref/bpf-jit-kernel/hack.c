#include <stdlib.h>

#include "hack.h"

int skb_copy_bits(const struct sk_buff *skb, int offset, void *to, int len)
{
#ifdef DBG
   printf("skb_copy_bits here!\n");
   fflush(0);
#endif
}

void *bpf_internal_load_pointer_neg_helper(const struct sk_buff *skb, int k, unsigned int size)
{
#ifdef DBG
   printf("bpf_internal_load_pointer_neg_helper here!\n");
   fflush(0);
#endif
}

void bpf_jit_dump(unsigned int flen, unsigned int proglen, u32 pass, void *image)
{
   int i;
   pr_err("flen=%u proglen=%u pass=%u image=%pK\n", flen, proglen, pass, image);
   //if (image)
   //   print_hex_dump(KERN_ERR, "JIT code: ", DUMP_PREFIX_OFFSET, 16, 1, image, proglen, false);
   if (image) {
      for (i = 1; i < (proglen+1); i++)
      {
         printf("%02X ", ((unsigned char *)image)[i-1]);
	 if (i%16 == 0)
	    printf("\n");

      }
      printf("\n");
   }
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

void kfree(void *ptr) {
   if (ptr == NULL) {
      printf("kfree error!\n");
      fflush(0);
      exit(-1);
   } else
      free(ptr);
}
