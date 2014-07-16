#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

int main() {
   int (*offline_filter)(char *f, uint32_t pkt_len, const uint8_t *pkt);
   char *error;

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

   (*offline_filter)(NULL, 0, NULL);

   dlclose(h);

   return 0;
}
