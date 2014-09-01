package.cpath = "./?.so;" .. package.cpath
local bs = require("basic")
local pt = function(t)
	for k, v in pairs(t) do 
		print(k, v)
	end
	print(string.rep("---", 10))
end 
local function test_htonl()
	assert(bs.htonl(65535) == 4294901760)
end
local function test_monotonic()
	local b, c = bs.monotonic()
	assert(b and c)
end
local function test_ip()
	local s = "192.168.0.1"
	local d = bs.ipstr(bs.ipbin(s))
	assert(s == d)
end
local function test_mac()
	local s = "01:0F:f0:09:ff:F0"
	local b = bs.macbin(s)
	local d = bs.macstr(b)
	assert(string.lower(s) == d)
end
local function test_mask()
	local i = bs.lshift(4294967295, 8) 
	assert(bs.ipstr(bs.htonl(i)) == "255.255.255.0")
end
local function test_user()
	local ouser = {Idx = 1, Jf = 222, Ssid = "ssidx", Mac = "01:02:03:0F:FF:F9", Ip = "192.168.0.2"}
	local cuser = bs.cuser(ouser)
	local luser = bs.luser(cuser) 
	assert(luser.Idx == ouser.Idx)
	assert(luser.Jf == ouser.Jf) 
	assert(luser.Ssid == ouser.Ssid)
	assert(luser.Mac == string.lower(ouser.Mac))
	assert(luser.Ip == ouser.Ip)
end
local function test_int()
	local n = math.random(0, 65536000)
	local b = bs.int2bin(n)
	local n2 = bs.bin2int(b)
	assert(n == n2)
end
pt(basic) 
local test = {test_ip, test_monotonic, test_mac, test_mask, test_user, test_int}
while true do 
	for _, func in ipairs(test) do func() end
	break
end 