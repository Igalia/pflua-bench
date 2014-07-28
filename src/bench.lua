module("bench",package.seeall)

package.path = package.path .. ";../deps/pflua/src/?.lua"

local savefile = require("pf.savefile")
local pf = require("pf")
local ffi = require("ffi")

local capture, engine, iterations = ...

assert(engine, "usage: bench.lua PATH/TO/CAPTURE.PCAP ENGINE [ITERATIONS]")
iterations = tonumber(iterations) or 50

local libpcap = require("pf.libpcap")
local bpf = require("pf.bpf")
local parse = require('pf.parse')
local expand = require('pf.expand')
local codegen = require('pf.codegen')

ffi.cdef[[
typedef long time_t;
typedef uint32_t suseconds_t;
struct timeval {
  time_t      tv_sec;     /* seconds */
  suseconds_t tv_usec;    /* microseconds */
};
int gettimeofday(struct timeval *tv, struct timezone *tz);
]]

ffi.cdef[[
typedef void (*compile_filter_t)(char *f);
typedef int (*run_filter_on_packet_t)(uint32_t pkt_len, const uint8_t *pkt);
void *dlopen(const char *filename, int flag);
void *dlsym(void *handle, const char *symbol);
char *dlerror(void);
]]

local lib_handle
-- void compile_filter(char *f);
local kernel_compile_filter
-- int run_filter_on_packet(uint32_t pkt_len, const uint8_t *pkt);
local kernel_run_filter_on_packet

local zero_sec, zero_usec

function load_dyn_funcs()
   local RTLD_LAZY = 0x0001
   lib_handle = ffi.C.dlopen("./ref/bpf-jit-kernel/libbpf_jit_kernel.so.1.0.0", RTLD_LAZY)
   if lib_handle == nil then
      print(ffi.C.dlerror())
      print("did you compile .so library? it should be at ./ref/bpf-jit-kernel/libbpf_jit_kernel.so.1.0.0 ...")
      print("try 'make -C ref/bpf-jit-kernel lib'")
      os.exit(-1)
   end
   kernel_compile_filter = ffi.cast("compile_filter_t", ffi.C.dlsym(lib_handle, "compile_filter"));
   kernel_run_filter_on_packet = ffi.cast("run_filter_on_packet_t", ffi.C.dlsym(lib_handle, "run_filter_on_packet"));
end

function convert_filter_to_dec_numbers(str)
   local line = ""
   local cmd = "/usr/sbin/tcpdump -ddd -r ts/pcaps/igalia/empty.pcap '" .. str .. "' 2> /dev/null | tr '\n' ','"
   local io = assert(io.popen(cmd, 'r'))
   line = io:read()
   line = line:sub(1,#line-1)
   io.close()
   return ffi.new("char[?]", #line, line)
end

local function now()
   local tv = ffi.new("struct timeval")
   assert(ffi.C.gettimeofday(tv, nil) == 0)
   if not zero_sec then
      zero_sec = tv.tv_sec
      zero_usec = tv.tv_usec
   end
   return tonumber(tv.tv_sec - zero_sec) + (tv.tv_usec - zero_usec) * 1e-6
end

local function compile_filter(filter_str, opts)
   local opts = opts or {}
   local dlt = opts.dlt or "EN10MB"
   if opts.pcap_offline_filter then
      local bytecode = libpcap.compile(filter_str, dlt)
      return function(P, header, len)
         return libpcap.offline_filter(bytecode, header, P) ~= 0
      end
   elseif opts.bpf then
      local bytecode = libpcap.compile(filter_str, dlt)
      local bpf_prog = bpf.compile(bytecode)
      return function(P, header, len) return bpf_prog(P, len) ~= 0 end
   elseif opts.linux_jit then
      return function(P, header, len)
         return kernel_run_filter_on_packet(len, P) ~= 0 end
   else
      local expr = parse.parse(filter_str)
      expr = expand.expand(expr, dlt)
      local pred = codegen.compile(expr)
      return function(P, header, len) return pred(P, len) end
   end
end

load_dyn_funcs()
tests = {}
for line in io.lines(capture..'.tests') do
   local description, count, filter = line:match("^([^:]+): (%d+):(.*)$")
   assert(filter, "failed to parse line "..line)
   if #tests > 0 then io.write('\t') end
   io.write(description)
   local test = {
      description=description,
      count=assert(tonumber(count)),
      filter=filter,
      libpcap=compile_filter(filter, {pcap_offline_filter=true}),
      bpf=compile_filter(filter, {bpf=true}),
      linuxjit=compile_filter(filter, {linux_jit=true}),
      pflua=compile_filter(filter)
   }
   table.insert(tests, test)
end
io.write('\n')
io.flush()

function map_captured_packets(filename)
   local fd = savefile.open(filename, O_RDONLY)
   if fd == -1 then
      error("Error opening " .. filename)
   end

   local size = savefile.size(fd)
   local ptr = savefile.mmap(fd, size)
   ffi.C.close(fd)

   if ptr == ffi.cast("void *", -1) then
      error("Error mmapping " .. filename)
   end

   ptr = ffi.cast("unsigned char *", ptr)
   local ptr_end = ptr + size
   local header = ffi.cast("struct pcap_file *", ptr)
   if header.magic_number == 0xD4C3B2A1 then
      error("Endian mismatch in " .. filename)
   elseif header.magic_number ~= 0xA1B2C3D4 then
      error("Bad PCAP magic number in " .. filename)
   end
   ptr = ptr + ffi.sizeof("struct pcap_file")
   return ptr, ptr_end
end

local capture_start, capture_end = map_captured_packets(capture)

local function filter_time(pred, file, expected)
   local total_count = 0
   local match_count = 0
   collectgarbage("stop")
   local start = now()
   local ptr = capture_start
   while ptr < capture_end do
      local record = ffi.cast("struct pcap_record *", ptr)
      local packet = ffi.cast("unsigned char *", record + 1)
      if pred(packet, record, record.incl_len) then
         match_count = match_count + 1
      end
      total_count = total_count + 1
      ptr = packet + record.incl_len
   end
   local lapse = now() - start
   collectgarbage()
   if match_count ~= expected then
      error("expected "..expected.." matching packets, but got "..match_count)
   end
   return total_count / lapse / 1e6
end

function run_filters(engine)
   local results = {}
   for i, test in ipairs(tests) do
      if engine == "linuxjit" then
         local bytecode = convert_filter_to_dec_numbers(test.filter)
         kernel_compile_filter(bytecode)
      end
      results[i] = filter_time(test[engine], capture, test.count)
   end
   return results
end

function run_tests(engine)
   run_filters(engine) -- Warmup
   for i=1,iterations do
      print(table.concat(run_filters(engine), '\t'))
      io.flush()
   end
end

run_tests(engine)
