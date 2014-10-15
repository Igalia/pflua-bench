module("bench",package.seeall)

local function dirname(s)
   local slash = s:find("/()[^/]+$")
   if slash then return s:sub(1, slash - 1) end
   return "."
end
local dot = dirname(arg[0])

package.path = package.path .. ";" .. dot .. "/deps/pflua/src/?.lua"

local ffi = require("ffi")
local pf = require("pf")
local savefile = require("pf.savefile")
local libpcap = require("pf.libpcap")
local now = require('pf.utils').now

-- For the Linux JIT
ffi.cdef[[
struct sock_fprog {
   uint16_t len;
   // Our struct bpf_insn is the same as struct sock_filter.
   struct bpf_insn *code;
};

void* compile_filter(struct sock_fprog *prog);
int run_filter(void *filter, const uint8_t *pkt, uint32_t pkt_len);
]]

local linux_bpf_jit = ffi.load(dot .. "/linux-bpf-jit/linux-bpf-jit.so")
local linux_ebpf_jit = ffi.load(dot .. "/linux-ebpf-jit/linux-ebpf-jit.so")

local function compile_linux_jit_filter(filter_str, jit_lib)
   local dlt = "EN10MB"
   local bytecode = libpcap.compile(filter_str, dlt)
   assert(bytecode.bf_len < 2^16)
   local prog = ffi.new("struct sock_fprog")
   prog.len = bytecode.bf_len
   -- FIXME: need to keep insns alive?
   prog.code = bytecode.bf_insns
   local filter = jit_lib.compile_filter(prog)
   return function(P, len)
      return jit_lib.run_filter(filter, P, len) ~= 0
   end
end

local compilers = {
   libpcap = function (filter)
      return pf.compile_filter(filter, {pcap_offline_filter=true})
   end,
   ["linux-bpf"] = function (filter)
      return compile_linux_jit_filter(filter, linux_bpf_jit)
   end,
   ["linux-ebpf"] = function (filter)
      return compile_linux_jit_filter(filter, linux_ebpf_jit)
   end,
   ["bpf-lua"] = function (filter)
      return pf.compile_filter(filter, {bpf=true})
   end,
   pflua = function (filter)
      return pf.compile_filter(filter)
   end
}

local function load_tests(filters, engine)
   local tests = {}
   local compile = assert(compilers[engine])
   for line in io.lines(filters) do
      local description, count, filter = line:match("^([^:]+): (%d+):(.*)$")
      assert(filter, "failed to parse line "..line)
      if #tests > 0 then io.write('\t') end
      io.write(description)
      local test = {
         description=description,
         count=assert(tonumber(count)),
         filter=filter,
         pred=compile(filter)
      }
      table.insert(tests, test)
   end
   io.write('\n')
   io.flush()
   return tests
end

local function filter_time(pred, ptr, ptr_end, expected)
   local total_count = 0
   local match_count = 0
   local offset = 0
   local max_offset = ptr_end - ptr
   local pcap_record_size = ffi.sizeof("struct pcap_record")
   local start = now()
   while offset < max_offset do
      local cur_ptr = ptr + offset
      local record = ffi.cast("struct pcap_record *", cur_ptr)
      local packet = ffi.cast("unsigned char *", record + 1)
      if pred(packet, record.incl_len) then
         match_count = match_count + 1
      end
      total_count = total_count + 1
      offset = offset + pcap_record_size + record.incl_len
   end
   local lapse = now() - start
   if match_count ~= expected then
      error("expected "..expected.." matching packets, but got "..match_count)
   end
   return total_count / lapse / 1e6
end

function run_filters(tests, ptr, ptr_end)
   local results = {}
   for i, test in ipairs(tests) do
      results[i] = filter_time(test.pred, ptr, ptr_end, test.count)
   end
   return results
end

function run_tests(tests, capture_start, capture_end, iterations)
   run_filters(tests, capture_start, capture_end) -- Warmup
   for i=1,iterations do
      local scores = run_filters(tests, capture_start, capture_end)
      print(table.concat(scores, '\t'))
      io.flush()
   end
end

function main(...)
   local capture, filters, engine, iterations = ...
   assert(engine,
          "usage: bench.lua PATH/TO/CAPTURE.PCAP FILTERS ENGINE [ITERATIONS]")
   iterations = tonumber(iterations) or 50
   local tests = load_tests(filters, engine)
   local header, capture_start, capture_end = savefile.open_and_mmap(capture)
   run_tests(tests, capture_start, capture_end, iterations)
end

main(...)
