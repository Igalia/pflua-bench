module("bench",package.seeall)

package.path = package.path .. ";../deps/pflua/src/?.lua"

local savefile = require("pf.savefile")
local pf = require("pf")

local capture, engine, iterations = ...

assert(engine, "usage: bench.lua PATH/TO/CAPTURE.PCAP ENGINE [ITERATIONS]")
iterations = tonumber(iterations) or 20

local libpcap = require("pf.libpcap")
local bpf = require("pf.bpf")
local parse = require('pf.parse')
local expand = require('pf.expand')
local codegen = require('pf.codegen')

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
   else
      local expr = parse.parse(filter_str)
      expr = expand.expand(expr, dlt)
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
      pflua=compile_filter(filter)
   }
   table.insert(tests, test)
end
io.write('\n')
io.flush()

local function filter_time(pred, file, expected)
   local total_count = 0
   local match_count = 0
   local start = os.clock()
   for pkt, hdr in savefile.records_mm(file) do
      total_count = total_count + 1
      if pred(pkt, hdr, hdr.incl_len) then
         match_count = match_count + 1
      end
   end
   local lapse = os.clock() - start
   if match_count ~= expected then
      error("expected "..expected.." matching packets, but got "..match_count)
   end
   return total_count / lapse
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
