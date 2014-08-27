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
local optimize = require('pf.optimize')
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

-- For the Linux JIT
ffi.cdef[[
struct sock_fprog {
   uint16_t len;
   // Our struct bpf_insn is the same as struct sock_filter.
   struct bpf_insn *code;
};

struct sk_filter;

struct sk_filter* compile_filter(struct sock_fprog *prog);
int run_filter(struct sk_filter *filter, const uint8_t *pkt, uint32_t pkt_len);
]]

local linux_bpf_jit = ffi.load("./ref/bpf-jit-kernel/libbpf_jit_kernel.so.1.0.0")
local linux_ebpf_jit = ffi.load("./ref/bpfe-jit-kernel/libbpfe_jit_kernel.so.1.0.0")

local zero_sec, zero_usec

local function compile_linux_jit(lib, bpf_program)
   assert(bpf_program.bf_len < 2^16)
   local prog = ffi.new("struct sock_fprog")
   prog.len = bpf_program.bf_len
   -- FIXME: need to keep insns alive?
   prog.code = bpf_program.bf_insns
   return lib.compile_filter(prog)
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
   elseif opts.linux_bpf then
      local bytecode = libpcap.compile(filter_str, dlt)
      local filter = compile_linux_jit(linux_bpf_jit, bytecode)
      local run_filter = linux_bpf_jit.run_filter
      return function(P, header, len)
         return run_filter(filter, P, len) ~= 0
      end
   elseif opts.linux_ebpf then
      local bytecode = libpcap.compile(filter_str, dlt)
      local filter = compile_linux_jit(linux_ebpf_jit, bytecode)
      local run_filter = linux_ebpf_jit.run_filter
      return function(P, header, len)
         return run_filter(filter, P, len) ~= 0
      end
   else
      local expr = parse.parse(filter_str)
      expr = expand.expand(expr, dlt)
      expr = optimize.optimize(expr)
      local pred = codegen.compile(expr)
      return function(P, header, len) return pred(P, len) end
   end
end

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
      linux_bpf=compile_filter(filter, {linux_bpf=true}),
      linux_ebpf=compile_filter(filter, {linux_ebpf=true}),
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
   if match_count ~= expected then
      error("expected "..expected.." matching packets, but got "..match_count)
   end
   return total_count / lapse / 1e6
end

function run_filters(engine)
   local results = {}
   for i, test in ipairs(tests) do
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
