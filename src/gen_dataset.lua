module("gen_dataset",package.seeall)

function string:split(pat, out)
   if not out then
      out = {}
   end
   local s = 1
   local ss, se = string.find(self, pat, s)
   while ss do
      table.insert(out, string.sub(self, s, ss-1))
      s = se + 1
      ss, se = string.find(self, pat, s)
   end
   table.insert(out, string.sub(self, s))
   return out
end

function get_tab_header(t, o)
   local header = ''
   for i, k in ipairs(o) do
      header = header .. k:sub(2,#k)
      if i ~= #o then
	 header = header .. "\t"
      end
   end
   return header
end

function get_tab_rows(t, o)
   return #t[o[1]]
end

function get_tab_row(t, o, r)
   local row = ''
   for i=1,#o do
      row = row .. t[o[i]][r]
      if i ~= #o then
	 row = row .. "\t"
      end
   end
   return row
end

function save_data_to_file(t, o, f)
   local header = get_tab_header(t, o)
   local file = io.open(f, "w")
   file:write(header .. "\n")
   local rows = get_tab_rows(t, o)
   for i=1,rows do
      local line = get_tab_row(t, o, i)
      file:write(line .. "\n")
   end
   file:close()
   print("data wrote to " .. f)
end

function run_bpf_libpcap(iter, cmd)
   local tab = {}
   local ord = {}
   io.write("grabbing data for " .. iter .. " iterations ")
   for i=1,iter do
      io.write(".")
      local io = assert(io.popen(cmd, 'r'))
      local key
      while true do
         local line = io:read()
	 if line == nil then break end
	 if line:sub(1, #"description:") == "description:" then
	    key = line:sub(#"description:"+1)
	    if tab[key] == nil then
	       tab[key] = {}
	       ord[#ord+1] = key
	    end
	 end
	 if line:match("PPS") ~= nil then
	    local t = line:split(' ')
	    table.insert(tab[key], t[5])
	 end
      end
   end
   io.write("\n")
   return tab, ord
end

function run(iter, cmd, filename)
   local t, o = run_bpf_libpcap(iter, cmd)
   save_data_to_file(t, o, filename)
end

