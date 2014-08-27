#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>


typedef unsigned int uint_t;
typedef int bool_t;

#define TRUE  0
#define FALSE 1

#define DBG_DUMP_S(s) ({ \
      printf("%s\n", s.filter); \
      printf("%s\n", s.pcap_file); \
      printf("%d\n", s.exp_result); \
      printf("%d\n", s.stat.pkt_seen); \
      printf("%f\n", s.stat.et); \
})

typedef struct {
   uint_t pkt_seen;
   uint_t pkt_matched;
   double  et;
} stat_t;

struct {
   char   *filter;
   char   *pcap_file;
   uint_t exp_result;
   stat_t stat;
} s;

bool_t print_error_and_die(char *s) {
   fprintf(stderr, "%s", s);
   exit(-1);
}

char *clone_str_or_die(char *s) {
   char *t = strdup(s);
   if (t==NULL)
      print_error_and_die("clone_str_or_die failed\n");
   return t;
}

void load_args_or_die(int argc, char **argv) {
   char *aux;

   /* format: filter pcap_file exp_result */
   if (argc != 4)
      print_error_and_die("Invalid syntax. Use ./pf_test_native filter pcap_file exp_result\n");

   /* load args */
   s.filter     = clone_str_or_die(argv[1]);
   s.pcap_file  = clone_str_or_die(argv[2]);
   aux          = clone_str_or_die(argv[3]);
   s.exp_result = strtol(aux, (char **)NULL, 10);
}

struct pcap_record {
  unsigned int ts_sec;
  unsigned int ts_usec;
  unsigned int caplen;
  unsigned int len;
};

void map_pcap_file(char *file, unsigned char **start, unsigned char **end) {
   unsigned char *ptr, *ptr_end;
   int fd;
   off_t size;

   fd = open(file, O_RDONLY);
   if (fd < 0) print_error_and_die(strerror(errno));

   size = lseek(fd, 0, SEEK_END);
   if (errno) print_error_and_die(strerror(errno));
   lseek(fd, 0, SEEK_SET);
   if (errno) print_error_and_die(strerror(errno));

   ptr = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
   if (ptr == MAP_FAILED) print_error_and_die(strerror(errno));

   ptr_end = ptr + size;
   {
     struct pcap_file_header *header = (struct pcap_file_header *)ptr;
     if (header->magic == 0xD4C3B2A1)
       print_error_and_die("endian mismatch in pcap file");
     else if (header->magic != 0xA1B2C3D4)
       print_error_and_die("bad pcap magic number");
     ptr += sizeof *header;
   }

   *start = ptr;
   *end = ptr_end;
}

void run_filter(char *filter, unsigned char *ptr, unsigned char *ptr_end) {
   struct bpf_program fp;
   pcap_t *handle;
   unsigned int seen, matched;
   struct timeval start, end;

   handle = pcap_open_dead(DLT_EN10MB, 65535);
   if (handle == NULL)
      print_error_and_die("pcap_open_offline failed\n");

   if (pcap_compile(handle, &fp, filter, 1, -1) == -1)
      print_error_and_die("pcap_compile failed\n");

   seen = matched = 0;

   gettimeofday(&start, NULL);

   while (ptr < ptr_end)
     {
       struct pcap_record *record = (struct pcap_record *)ptr;
       struct pcap_pkthdr header = {
         { record->ts_sec, record->ts_usec },
         record->caplen,
         record->len
       };
       unsigned char *packet = ptr + sizeof(*record);
       if (pcap_offline_filter(&fp, &header, packet))
         matched++;
       seen++;
       ptr = packet + record->caplen;
     }

   gettimeofday(&end, NULL);

   s.stat.et = end.tv_sec - start.tv_sec;
   s.stat.et += (end.tv_usec - start.tv_usec) * 1.0e-6;
   s.stat.pkt_seen = seen;
   s.stat.pkt_matched = matched;
}

int main(int argc, char **argv) {
   unsigned char *ptr, *ptr_end;

   /* check and load args */
   load_args_or_die(argc, argv);

   map_pcap_file(s.pcap_file, &ptr, &ptr_end);

   /* warmup */
   run_filter(s.filter, ptr, ptr_end);

   /* run filter and gather stats */
   run_filter(s.filter, ptr, ptr_end);

   if (s.stat.pkt_matched != s.exp_result)
     {
       fprintf(stderr, "Error: Expected to see %u packets, got %u packets\n",
               s.exp_result, s.stat.pkt_matched);
       return 1;
     }
   
   fprintf(stdout, "\"%s\" on %s: %.1f MPPS\n",
           s.filter, s.pcap_file, s.stat.pkt_seen / s.stat.et / 1.0e6);

   return 0;
}
