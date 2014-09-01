local l = require("log")
local maxsize = 1024*100
local logpath = "/tmp/cloud_fail.txt"
local file 

local function check_log()
	if file then 
		local size = file:seek("end")
		if size <= maxsize then 
			return 
		end
		file:close()
	end 
	file = io.open(logpath, "wb")
	if not file then 
		l.syscrit("open fail", logpath)
		os.exit(0)
	end
	local size = file:seek("end")
	if size > maxsize then
		file:seek("set", math.floor(maxsize/2))
		local content = file:read("*all")
		file:close()
		os.remove(logpath)
		file = io.open(logpath, "a")
		if not file then 
			l.syscrit("open fail", logpath)
			os.exit(0)
		end
		file:write(content)
	end
end

local function log(fmt, ...) 
	check_log()
	local s = string.format("%s " .. fmt, os.date(), ...) 
	file:write(s)
	file:flush()
end 

return {log = log}
