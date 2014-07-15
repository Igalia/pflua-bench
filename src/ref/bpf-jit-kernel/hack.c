#include <stdlib.h>

#include "hack.h"

void *module_alloc(unsigned int sz)
{
   printf("module_alloc here!\n");
}

void module_free(void *mod, void *module_region)
{
   printf("module_free here!\n");
}

int skb_copy_bits(const struct sk_buff *skb, int offset, void *to, int len)
{
   printf("skb_copy_bits here!\n");
}

void *bpf_internal_load_pointer_neg_helper(const struct sk_buff *skb, int k, unsigned int size)
{
   printf("bpf_internal_load_pointer_neg_helper here!\n");
}

void bpf_jit_dump(unsigned int flen, unsigned int proglen, u32 pass, void *image)
{
   /* TODO: clone dmesg dumping feature here
   /*
   pr_err("flen=%u proglen=%u pass=%u image=%pK\n", flen, proglen, pass, image);
   if (image)
      print_hex_dump(KERN_ERR, "JIT code: ", DUMP_PREFIX_OFFSET, 16, 1, image, proglen, false);
   */
}

void * kmalloc(size_t size, int flags) {
   void *p;
   if ((p = malloc(size)) == NULL) {
      printf("kmalloc failing!\n");
      exit(-1);
   }
   return p;
}

void kfree(void *ptr) {
   if (ptr == NULL) {
      printf("kfree error!\n");
      exit(-1);
   } else
      free(ptr);
}
