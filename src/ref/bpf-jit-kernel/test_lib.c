#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#define TEST_PKT_LEN 1

int main() {
   //char *filter = "6,40 0 0 12,21 0 3 2048,48 0 0 23,21 0 1 1,6 0 0 65535,6 0 0 0";
   //char *filter = "4,40 0 0 12,21 0 1 2048,6 0 0 65535,6 0 0 0";
   char *filter = "1,6 0 0 65535";
   void (*compile_filter)(char *f);
   int  (*run_filter_on_packet)(uint32_t pkt_len, const uint8_t *pkt);
   char *error;
   int ret = -1;

   unsigned char *pkt = malloc(TEST_PKT_LEN);

   void *h = dlopen("./libbpf_jit_kernel.so.1.0.0", RTLD_LAZY);

   if (!h) {
      fprintf(stderr, "%s\n", dlerror());
      exit(EXIT_FAILURE);
   }

   compile_filter = dlsym(h, "compile_filter");

   error = dlerror();
   if (error != NULL) {
      fprintf(stderr, "%s\n", error);
      exit(EXIT_FAILURE);
   }

   run_filter_on_packet = dlsym(h, "run_filter_on_packet");

   error = dlerror();
   if (error != NULL) {
      fprintf(stderr, "%s\n", error);
      exit(EXIT_FAILURE);
   }

   (*compile_filter)(filter);

   ret = (*run_filter_on_packet)(TEST_PKT_LEN, pkt);

   dlclose(h);

   printf("%d\nOK!\n", ret);

   return 0;
}
