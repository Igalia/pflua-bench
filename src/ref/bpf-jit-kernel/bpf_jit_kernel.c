#include <stdio.h>
#include <stdlib.h>

#include "hack.h"

#include "bpf_jit_kernel.h"

static struct bjk_bpf_info info;

void show_error_and_die(char *e)
{
   printf("%s stopping...\n", e);
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
      show_error_and_die("__sk_prepare_filter: error jitting filter!");

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
   if (fp == NULL)
      show_error_and_die("sk_unattached_filter_create: __sk_prepare_filter failed!\n");
   *pfp = fp;
   return 0;
}

void compile_jit_filter(struct bjk_bpf_info *info)
{
   struct sock_fprog program;

   program.len = info->bpf_program_num_elem;
   program.filter = (struct sock_filter __user *) info->bpf_program;

   if (sk_unattached_filter_create(&info->filter, &program))
      show_error_and_die("compile_jit_filter: bpf: check failed: parse error");
}

bool run_jit_filter(struct bjk_bpf_info *info, struct sk_buff *skb)
{
   return SK_RUN_FILTER(info->filter, skb);
}

void load_bpf(struct bjk_bpf_info *info, char *bpf_string)
{
	char sp, *token, separator = ',';
	unsigned short bpf_len, i = 0;
	struct sock_filter tmp;

	info->bpf_program_num_elem = 0;
	memset(info->bpf_program, 0, sizeof(info->bpf_program));

	if (sscanf(bpf_string, "%hu%c", &bpf_len, &sp) != 2 ||
	    sp != separator || bpf_len > BJK_BPF_MAX_NUM_INSTR || bpf_len == 0) {
		show_error_and_die("cmd_load_bpf: syntax error in head length encoding!");
	}

	token = bpf_string;
	while ((token = strchr(token, separator)) && (++token)[0]) {

		if (i >= bpf_len)
			show_error_and_die("cmd_load_bpf: program exceeds encoded length!");

		if (sscanf(token, "%hu %hhu %hhu %u,", &tmp.code, &tmp.jt, &tmp.jf, &tmp.k) != 4) {
			printf("cmd_load_bpf: syntax error at instruction %d!", i);
			show_error_and_die("");

		}

		info->bpf_program[i].code = tmp.code;
		info->bpf_program[i].jt = tmp.jt;
		info->bpf_program[i].jf = tmp.jf;
		info->bpf_program[i].k = tmp.k;

		i++;
	}

	if (i != bpf_len)
		show_error_and_die("cmd_load_bpf: syntax error exceeding encoded length!");
	else
		info->bpf_program_num_elem = bpf_len;
}

void test_load_bpf(struct bjk_bpf_info *info)
{
   if((info->bpf_program[4].k == 65535) &&
      (info->bpf_program[5].code == 6))
      printf("test ok\n");
   else
      printf("test failed\n");
}

int main()
{
   // load bpf bytecode
   char *test_str = "6,40 0 0 12,21 0 3 2048,48 0 0 23,21 0 1 1,6 0 0 65535,6 0 0 0";
   load_bpf(&info, test_str);

   // quick test
   test_load_bpf(&info);

   // jit compile now
   compile_jit_filter(&info);

   // jit run now
   struct sk_buff *skb = kmalloc(sizeof(struct sk_buff), GFP_KERNEL);
   if (skb == NULL)
      show_error_and_die("main: kmalloc failing!");
   run_jit_filter(&info, skb);

   printf("OK\n");
   return 0;
}
