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
      return pf.compile_filter(filter, {libpcap=true})
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

local function run_filter(min_time, packets, pred)
   local start = now()
   local finish = start
   local seen, matched
   local iterations = 0
   while finish - start < min_time do
      seen, matched = 0, 0
      for i = 1,#packets do
         seen = seen + 1
         if pred(packets[i].packet, packets[i].len) then
            matched = matched + 1
         end
      end
      iterations = iterations + 1
      finish = now()
   end
   return seen, matched, (finish - start), iterations
end

-- The total time for the test is # of tests * # of samples * # of
-- scenarios * test_time.  So about 500 times the run_filter number.  I
-- set it to 100ms so that we finish in under a minute.
local function filter_time(pred, packets, expected)
   local total, matched, lapse, iterations = run_filter(0.1, packets, pred)
   if matched ~= expected then
      error("expected "..expected.." matching packets, but got "..matched)
   end
   return total * iterations / lapse / 1e6
end

function run_filters(tests, packets)
   local results = {}
   for i, test in ipairs(tests) do
      results[i] = filter_time(test.pred, packets, test.count)
   end
   return results
end

function run_tests(tests, packets, iterations)
   run_filters(tests, packets) -- Warmup
   for i=1,iterations do
      local scores = run_filters(tests, packets)
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
   local packets = savefile.load_packets(capture)
   run_tests(tests, packets, iterations)
end

main(...)
