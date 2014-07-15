#include <stdio.h>
#include <stdlib.h>

#include "hack.h"

struct sk_filter *__sk_prepare_filter(struct sk_filter *fp /* , struct sock *sk*/ )
{
   int err;

   fp->bpf_func = NULL;
   fp->jited = 0;

   /*
   err = sk_chk_filter(fp->insns, fp->len);
   if (err) {
      if (sk != NULL)
         sk_filter_uncharge(sk, fp);
      else
         kfree(fp);
      return ERR_PTR(err);
   }
   */

   /* Probe if we can JIT compile the filter and if so, do
    * the compilation of the filter.
    */
   bpf_jit_compile(fp);

   /* JIT compiler couldn't process this filter, so do the
    * internal BPF translation for the optimized interpreter.
    */
   /*
   if (!fp->jited)
      fp = __sk_migrate_filter(fp, sk);
   */
   if (!fp->jited)
   {
      printf("__sk_prepare_filter: error jitting filter! stopping...\n");
      exit(-1);
   }

   return fp;
}

/* test should build on this iface */
//void bpf_jit_compile(struct sk_filter *fp);
//void bpf_jit_free(struct sk_filter *fp);

int main()
{
   printf("linking test\n");
   return 0;
}
