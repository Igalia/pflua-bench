#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#define TEST_PKT_LEN 1

int main() {
   //char *filter = "6,40 0 0 12,21 0 3 2048,48 0 0 23,21 0 1 1,6 0 0 65535,6 0 0 0";
   char *filter = "1,6 0 0 65535";
   int (*offline_filter)(char *f, uint32_t pkt_len, const uint8_t *pkt);
   char *error;

   unsigned char *pkt = malloc(TEST_PKT_LEN);

   void *h = dlopen("./libbpf_jit_kernel.so.1.0.0", RTLD_LAZY);

   if (!h) {
      fprintf(stderr, "%s\n", dlerror());
      exit(EXIT_FAILURE);
   }

   offline_filter = dlsym(h, "offline_filter");

   error = dlerror();
   if (error != NULL) {
      fprintf(stderr, "%s\n", error);
      exit(EXIT_FAILURE);
   }

   (*offline_filter)(filter, TEST_PKT_LEN, pkt);

   dlclose(h);

   printf("OK!\n");

   return 0;
}
