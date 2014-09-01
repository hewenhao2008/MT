local bs = require("basic")
local is_debug = false

local function rconcat2(t, n, ...)
	if n == 0 then
		return table.concat(t, ", ")
	end 
	local p = select(1, ...)
	if 'table' ~= type(p) then 
		table.insert(t, tostring(p))
	else
		local tt = {}
		local tmp = rconcat2(tt, select('#', unpack(p)), unpack(p)) 
		table.insert(t, '{' .. tmp .. '}')
	end
	return rconcat2(t, n - 1, select(2, ...))
end

local concat = rconcat2
local print_msg = io.write
local function format(dt, fmt, ...)
	local info = debug.getinfo(3, "lS")
	local t = os.date("*t")
	return string.format("%s %02d%02d.%02d:%02d:%02d %s %d "..fmt, dt, t.month, t.day, t.hour, t.min, t.sec, 
		info.short_src or "none", info.currentline or "none", ...)
end

local function dbg(...)
	local msg = concat({}, select('#', ...), ...)
	print_msg(format('d', "%s\n", msg))
end

local function dbgf(fmt, ...) 
	print_msg(format('d', fmt, ...))
end

local function info(...)
	local msg = concat({}, select('#', ...), ...)
	print_msg(format('i', "%s\n", msg))
end

local function infof(fmt, ...) 
	print_msg(format('i', fmt, ...))
end


local function error(...)
	local msg = concat({}, select('#', ...), ...)
	print_msg(format('e', "%s\n", msg))
end

local function errorf(fmt, ...) 
	print_msg(format('e', fmt, ...))
end

local function fatal(...)
	local msg = concat({}, select('#', ...), ...)
	print_msg(format('f', "%s\n", msg))
	os.exit(-1)
end

local function fatalf(fmt, ...) 
	print_msg(format('f', fmt, ...))
	os.exit(-1)
end

local function sysfmt(fmt, ...)
	local info = debug.getinfo(3, "lS")
	local src = info.short_src:match(".+/(.*.lua)$") or info.short_src 
	if info.currentline == 0 then 
		return string.format(" %s "..fmt, src, ...)
	end
	return string.format(" %s %d "..fmt, src, info.currentline or "none", ...)
end

local function syscrit(fmt, ...) 
	local msg = sysfmt(fmt, ...)
	bs.syslog(2, msg)
	local _ = is_debug and print(os.date() .. msg)
end

local function sysinfo(fmt, ...)
	local msg = sysfmt(fmt, ...)
	bs.syslog(6, msg)
	local _ = is_debug and print(os.date() .. msg)
end

local function syserr(fmt, ...)
	local msg = sysfmt(fmt, ...)
	bs.syslog(3, msg)
	local _ = is_debug and print(os.date() .. msg)
end

local function setdebug(b)
	is_debug = b
end

return {
			dbg = dbg, 
			dbgf = dbgf, 
			info = info, 
			infof = infof, 
			err = error, 
			errf = errorf,
			fatal = fatal, 
			fatalf = fatalf,
			syscrit = syscrit,
			sysinfo = sysinfo,
			syserr = syserr,
			setdebug = setdebug
		}
