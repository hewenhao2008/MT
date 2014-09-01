local log = require("log") 
local bs = require("basic")
local sysinfo, syserr = log.sysinfo, log.syserr

local misc = {}

function misc.write_config(path, content)
	if #content >= 4096 then 
		syserr("content size too large %d %d", #content, 4096)
		return false
	end 
	local file = io.open(path, "wb")
	if not file then 
		syserr("open %s fail", path)
		return false
	end 
	file:write(content)
	file:close()
	return true 
end

function misc.config_past_host(action, idx, host) 
	if #host == 0 then 
		return 
	end 
	local content = string.format("%s %02d %02d %s", action, idx, #host, host)
	misc.write_config("/sys/module/auth/pass_host", content)
end 

local function format_notify_cmd(user, action)
	local total = 25
	local t = {}
	table.insert(t, bs.int2bin(total))
	table.insert(t, action)
	table.insert(t, bs.cuser(user))
	local res = table.concat(t)
	return res
end

function misc.notify_kernel_offline(user)
	syserr("offline %d %s %s %s %d", user.Idx, user.Mac, user.Ip, user.Ssid, user.Jf)
	local cmd = format_notify_cmd(user, 'd')
	misc.write_config("/sys/module/auth/online", cmd)
end 

function misc.notify_kernel_online(user)
	local info = debug.getinfo(2, "lS") 
	syserr("online %d %s %s %s %d", user.Idx, user.Mac, user.Ip, user.Ssid, user.Jf)
	local cmd = format_notify_cmd(user, 'a')
	misc.write_config("/sys/module/auth/online", cmd)
end 


-- function misc.monotonic_ns()
-- 	local now = misc.monotonic() 
-- 	if now then 
-- 		return now.tv_sec * 1000000000 + now.tv_nsec
-- 	end 
-- 	return 0
-- end

function misc.set_through(cip)  
	misc.write_config("/sys/module/auth/ip_through", tostring(cip))
end

function misc.countk(t) 
	local c = 0
	for _ in pairs(t) do 
		c = c + 1
	end
	return c
end

return misc

