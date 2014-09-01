package.cpath = "/usr/lib/?.so;" .. package.cpath
package.path = "/usr/sbin/scripts/?.lua;" .. package.path
require("global")
local ev = require("ev")
local sk = require("socket")
local function main(arg)
	local s = assert(arg[1]) 
	local loop = ev.Loop.new()
	local udp = assert(socket.udp())
	udp:settimeout(0)
	assert(udp:setpeername("127.0.0.1", 9999))
	ev.IO.new(function()
			udp:send(s)
			print("send", s)
			os.exit(0)
		end, udp:getfd(), ev.WRITE):start(loop)
	loop:loop()
end

main(arg)