#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "hack.h"

#include "bpf_jit_kernel.h"

static struct bjk_bpf_info info;

void show_error_and_die(char *e)
{
   printf("%s stopping...\n", e);
   exit(-1);
}

static int check_load_and_stores(struct sock_filter *filter, int flen)
{
	u16 *masks, memvalid = 0; /* one bit per cell, 16 cells */
	int pc, ret = 0;

	BUILD_BUG_ON(BPF_MEMWORDS > 16);
	masks = kmalloc(flen * sizeof(*masks), GFP_KERNEL);
	if (!masks)
		return -ENOMEM;
	memset(masks, 0xff, flen * sizeof(*masks));

	for (pc = 0; pc < flen; pc++) {
		memvalid &= masks[pc];

		switch (filter[pc].code) {
		case BPF_S_ST:
		case BPF_S_STX:
			memvalid |= (1 << filter[pc].k);
			break;
		case BPF_S_LD_MEM:
		case BPF_S_LDX_MEM:
			if (!(memvalid & (1 << filter[pc].k))) {
				ret = -EINVAL;
				goto error;
			}
			break;
		case BPF_S_JMP_JA:
			/* a jump must set masks on target */
			masks[pc + 1 + filter[pc].k] &= memvalid;
			memvalid = ~0;
			break;
		case BPF_S_JMP_JEQ_K:
		case BPF_S_JMP_JEQ_X:
		case BPF_S_JMP_JGE_K:
		case BPF_S_JMP_JGE_X:
		case BPF_S_JMP_JGT_K:
		case BPF_S_JMP_JGT_X:
		case BPF_S_JMP_JSET_X:
		case BPF_S_JMP_JSET_K:
			/* a jump must set masks on targets */
			masks[pc + 1 + filter[pc].jt] &= memvalid;
			masks[pc + 1 + filter[pc].jf] &= memvalid;
			memvalid = ~0;
			break;
		}
	}
error:
	kfree(masks);
	return ret;
}

int sk_chk_filter(struct sock_filter *filter, unsigned int flen)
{
	/*
	 * Valid instructions are initialized to non-0.
	 * Invalid instructions are initialized to 0.
	 */
	static const u8 codes[] = {
		[BPF_ALU|BPF_ADD|BPF_K]  = BPF_S_ALU_ADD_K,
		[BPF_ALU|BPF_ADD|BPF_X]  = BPF_S_ALU_ADD_X,
		[BPF_ALU|BPF_SUB|BPF_K]  = BPF_S_ALU_SUB_K,
		[BPF_ALU|BPF_SUB|BPF_X]  = BPF_S_ALU_SUB_X,
		[BPF_ALU|BPF_MUL|BPF_K]  = BPF_S_ALU_MUL_K,
		[BPF_ALU|BPF_MUL|BPF_X]  = BPF_S_ALU_MUL_X,
		[BPF_ALU|BPF_DIV|BPF_X]  = BPF_S_ALU_DIV_X,
		[BPF_ALU|BPF_MOD|BPF_K]  = BPF_S_ALU_MOD_K,
		[BPF_ALU|BPF_MOD|BPF_X]  = BPF_S_ALU_MOD_X,
		[BPF_ALU|BPF_AND|BPF_K]  = BPF_S_ALU_AND_K,
		[BPF_ALU|BPF_AND|BPF_X]  = BPF_S_ALU_AND_X,
		[BPF_ALU|BPF_OR|BPF_K]   = BPF_S_ALU_OR_K,
		[BPF_ALU|BPF_OR|BPF_X]   = BPF_S_ALU_OR_X,
		[BPF_ALU|BPF_XOR|BPF_K]  = BPF_S_ALU_XOR_K,
		[BPF_ALU|BPF_XOR|BPF_X]  = BPF_S_ALU_XOR_X,
		[BPF_ALU|BPF_LSH|BPF_K]  = BPF_S_ALU_LSH_K,
		[BPF_ALU|BPF_LSH|BPF_X]  = BPF_S_ALU_LSH_X,
		[BPF_ALU|BPF_RSH|BPF_K]  = BPF_S_ALU_RSH_K,
		[BPF_ALU|BPF_RSH|BPF_X]  = BPF_S_ALU_RSH_X,
		[BPF_ALU|BPF_NEG]        = BPF_S_ALU_NEG,
		[BPF_LD|BPF_W|BPF_ABS]   = BPF_S_LD_W_ABS,
		[BPF_LD|BPF_H|BPF_ABS]   = BPF_S_LD_H_ABS,
		[BPF_LD|BPF_B|BPF_ABS]   = BPF_S_LD_B_ABS,
		[BPF_LD|BPF_W|BPF_LEN]   = BPF_S_LD_W_LEN,
		[BPF_LD|BPF_W|BPF_IND]   = BPF_S_LD_W_IND,
		[BPF_LD|BPF_H|BPF_IND]   = BPF_S_LD_H_IND,
		[BPF_LD|BPF_B|BPF_IND]   = BPF_S_LD_B_IND,
		[BPF_LD|BPF_IMM]         = BPF_S_LD_IMM,
		[BPF_LDX|BPF_W|BPF_LEN]  = BPF_S_LDX_W_LEN,
		[BPF_LDX|BPF_B|BPF_MSH]  = BPF_S_LDX_B_MSH,
		[BPF_LDX|BPF_IMM]        = BPF_S_LDX_IMM,
		[BPF_MISC|BPF_TAX]       = BPF_S_MISC_TAX,
		[BPF_MISC|BPF_TXA]       = BPF_S_MISC_TXA,
		[BPF_RET|BPF_K]          = BPF_S_RET_K,
		[BPF_RET|BPF_A]          = BPF_S_RET_A,
		[BPF_ALU|BPF_DIV|BPF_K]  = BPF_S_ALU_DIV_K,
		[BPF_LD|BPF_MEM]         = BPF_S_LD_MEM,
		[BPF_LDX|BPF_MEM]        = BPF_S_LDX_MEM,
		[BPF_ST]                 = BPF_S_ST,
		[BPF_STX]                = BPF_S_STX,
		[BPF_JMP|BPF_JA]         = BPF_S_JMP_JA,
		[BPF_JMP|BPF_JEQ|BPF_K]  = BPF_S_JMP_JEQ_K,
		[BPF_JMP|BPF_JEQ|BPF_X]  = BPF_S_JMP_JEQ_X,
		[BPF_JMP|BPF_JGE|BPF_K]  = BPF_S_JMP_JGE_K,
		[BPF_JMP|BPF_JGE|BPF_X]  = BPF_S_JMP_JGE_X,
		[BPF_JMP|BPF_JGT|BPF_K]  = BPF_S_JMP_JGT_K,
		[BPF_JMP|BPF_JGT|BPF_X]  = BPF_S_JMP_JGT_X,
		[BPF_JMP|BPF_JSET|BPF_K] = BPF_S_JMP_JSET_K,
		[BPF_JMP|BPF_JSET|BPF_X] = BPF_S_JMP_JSET_X,
	};
	int pc;
	bool anc_found;

	if (flen == 0 || flen > BPF_MAXINSNS)
		return -EINVAL;

	/* check the filter code now */
	for (pc = 0; pc < flen; pc++) {
		struct sock_filter *ftest = &filter[pc];
		u16 code = ftest->code;

		if (code >= ARRAY_SIZE(codes))
			return -EINVAL;
		code = codes[code];
		if (!code)
			return -EINVAL;
		/* Some instructions need special checks */
		switch (code) {
		case BPF_S_ALU_DIV_K:
		case BPF_S_ALU_MOD_K:
			/* check for division by zero */
			if (ftest->k == 0)
				return -EINVAL;
			break;
		case BPF_S_LD_MEM:
		case BPF_S_LDX_MEM:
		case BPF_S_ST:
		case BPF_S_STX:
			/* check for invalid memory addresses */
			if (ftest->k >= BPF_MEMWORDS)
				return -EINVAL;
			break;
		case BPF_S_JMP_JA:
			/*
			 * Note, the large ftest->k might cause loops.
			 * Compare this with conditional jumps below,
			 * where offsets are limited. --ANK (981016)
			 */
			if (ftest->k >= (unsigned int)(flen-pc-1))
				return -EINVAL;
			break;
		case BPF_S_JMP_JEQ_K:
		case BPF_S_JMP_JEQ_X:
		case BPF_S_JMP_JGE_K:
		case BPF_S_JMP_JGE_X:
		case BPF_S_JMP_JGT_K:
		case BPF_S_JMP_JGT_X:
		case BPF_S_JMP_JSET_X:
		case BPF_S_JMP_JSET_K:
			/* for conditionals both must be safe */
			if (pc + ftest->jt + 1 >= flen ||
			    pc + ftest->jf + 1 >= flen)
				return -EINVAL;
			break;
		case BPF_S_LD_W_ABS:
		case BPF_S_LD_H_ABS:
		case BPF_S_LD_B_ABS:
			anc_found = false;
#define ANCILLARY(CODE) case SKF_AD_OFF + SKF_AD_##CODE:	\
				code = BPF_S_ANC_##CODE;	\
				anc_found = true;		\
				break
			switch (ftest->k) {
			ANCILLARY(PROTOCOL);
			ANCILLARY(PKTTYPE);
			ANCILLARY(IFINDEX);
			ANCILLARY(NLATTR);
			ANCILLARY(NLATTR_NEST);
			ANCILLARY(MARK);
			ANCILLARY(QUEUE);
			ANCILLARY(HATYPE);
			ANCILLARY(RXHASH);
			ANCILLARY(CPU);
			ANCILLARY(ALU_XOR_X);
			ANCILLARY(VLAN_TAG);
			ANCILLARY(VLAN_TAG_PRESENT);
			ANCILLARY(PAY_OFFSET);
			}

			/* ancillary operation unknown or unsupported */
			if (anc_found == false && ftest->k >= SKF_AD_OFF)
				return -EINVAL;
		}
		ftest->code = code;
	}

	/* last instruction must be a RET code */
	switch (filter[flen - 1].code) {
	case BPF_S_RET_K:
	case BPF_S_RET_A:
		return check_load_and_stores(filter, flen);
	}
	return -EINVAL;
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
   err = sk_chk_filter(fp->insns, fp->len);
   if (err)
      show_error_and_die("jpf_jit_kernel: sk_chk_filter failed!");

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
   if((info->bpf_program[0].k == 65535) &&
      (info->bpf_program[0].code == 6))
      printf("test load bpf ok\n");
   else
      printf("test failed\n");
}

void wrap_pkt_with_sk_buff(struct sk_buff *skb)
{
   skb->data_len = 10;
   skb->data = kmalloc(sizeof(struct sk_buff), GFP_KERNEL);
}

int offline_filter(char *f, uint32_t pkt_len, const uint8_t *pkt)
{
   printf("%s\n", f);
}

int main()
{
   int success;
   // load bpf bytecode
   //char *test_str = "6,40 0 0 12,21 0 3 2048,48 0 0 23,21 0 1 1,6 0 0 65535,6 0 0 0";
   char *test_str = "1,6 0 0 65535";
   load_bpf(&info, test_str);

   // quick test
   test_load_bpf(&info);

   // jit compile now
   compile_jit_filter(&info);

   // wrap with sk_buff
   struct sk_buff *skb = kmalloc(sizeof(struct sk_buff), GFP_KERNEL);
   wrap_pkt_with_sk_buff(skb);
   if (skb == NULL)
      show_error_and_die("main: kmalloc failing!");

   // jit run now
   success = run_jit_filter(&info, skb);
   if (success != 0)
      printf("match!\n");
   else
      printf("fail!\n");

   printf("OK\n");
   return 0;
}
