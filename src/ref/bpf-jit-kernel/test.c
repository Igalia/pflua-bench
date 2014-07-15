#include <stdio.h>
#include <stdlib.h>

#include "hack.h"

void show_error_and_die(char *e)
{
   printf("%s stopping...", e);
   exit(-1);
}

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
      show_error_and_die("__sk_prepare_filter: error jitting filter!\n");

   return fp;
}

int sk_unattached_filter_create(struct sk_filter **pfp, struct sock_fprog *fprog)
{
   unsigned int fsize = sk_filter_proglen(fprog);
   struct sk_filter *fp;

   /* Make sure new filter is there and in the right amounts. */
   //if (fprog->filter == NULL)
   //   return -EINVAL;
   if (fprog->filter == NULL)
      show_error_and_die("sk_unattached_filter_create: assert fprog->filter == NULL fails!");

   fp = kmalloc(sk_filter_size(fprog->len), GFP_KERNEL);
   //if (!fp)
   //   return -ENOMEM;
   if (!fp)
      show_error_and_die("sk_unattached_filter_create: kmalloc failed!");

   memcpy(fp->insns, fprog->filter, fsize);

   //atomic_set(&fp->refcnt, 1);
   fp->len = fprog->len;
   /* Since unattached filters are not copied back to user
    * space through sk_get_filter(), we do not need to hold
    * a copy here, and can spare us the work.
    */
   fp->orig_prog = NULL;

   /* __sk_prepare_filter() already takes care of uncharging
    * memory in case something goes wrong.
    */
   //fp = __sk_prepare_filter(fp, NULL);
   fp = __sk_prepare_filter(fp);
   //if (IS_ERR(fp))
   //   return PTR_ERR(fp);
   show_error_and_die("sk_unattached_filter_create: __sk_prepare_filter failed!\n");
   *pfp = fp;
   return 0;
}

/* test should build on this iface */
//void bpf_jit_compile(struct sk_filter *fp);
//void bpf_jit_free(struct sk_filter *fp);

int main()
{
   printf("linking test\n");
   return 0;
}
