package.cpath = "/usr/lib/?.so;" .. package.cpath
package.path = "/usr/sbin/scripts/?.lua;" .. package.path
require("global")
local ev = require("ev")
local log = require("log")
local authm = require("auth.authm")
local authv = require("auth.authv") 
local sysinfo, syserr, syscrit = log.sysinfo, log.syserr, log.syscrit

define("pcallf")
function pcallf(f, ...)
	local ret, msg = xpcall(f, function(err)
		local trace = debug.traceback()
		local t = {err}
		for line in trace:gmatch("(.-)\n") do  
			if not line:find("%[C%]:") then 
				table.insert(t, line)
			end
		end 
		return table.concat(t, "\n")
		end)
	if not ret then 
		syscrit("%s", msg)
		os.exit(-1)
	end
end

define("pt")
function pt(t)
	for k, v in pairs(t) do 
		print(k, v)
	end 
	print(string.rep("---", 10))
end


local function watch_signal(loop) 
	local do_sig = function(sig)
		local _, _ = sysinfo("recieve signal", sig), os.exit(0)  
	end
	for _, sig in ipairs({2, 3, 13, 15}) do 
		local sig_wather = ev.Signal.new(function(loop, esig, revs)
				do_sig(sig)
			end, sig)
		sig_wather:start(loop)
	end 
end

local start = os.time()
local function watch_memory(loop)
	local idle_timer
	local interval = 10
	local do_watch = function()
		local d = os.time() - start 
		--print(d, math.floor(collectgarbage("count"))) 
	end

	idle_timer = assert(ev.Timer.new(function(loop, timer, revs)
			local idle = assert(ev.Idle.new(function(loop, idle, revs) 
					idle:stop(loop)
					do_watch()
					idle_timer:again(loop, interval)
				end))
			idle:start(loop) 
		end, interval))
	idle_timer:start(loop)
end

for _, opt in ipairs(arg) do 
	if opt == "-d" then 
		log.setdebug(true)
		print("print debug message")
	end
end  
local loop = ev.Loop.new()
watch_signal(loop)
watch_memory(loop)
authm.start(loop)
authv.start(loop)
loop:loop()


