local bs = require("basic")
local miniz = require("miniz")

local bsc =  {}
function bsc.ip_mask(ipstr, maskbit)
	local ip = bs.ipbin(ipstr)
	local mask = bs.ipbin(bs.maskbybit(maskbit)) 
	return ip, mask
end

function bsc.subnetbin(t)
	local res = {}
	for _, v in ipairs(t) do 
		table.insert(res, v.ip)
		table.insert(res, v.mask)
	end 
	return table.concat(res)
end

function bsc.deflate(content)
	return miniz.deflate(content, #content)
end

function bsc.ipstr(ip)
	return bs.ipstr(ip) 
end

function bsc.int2bin(bypass)
	return bs.int2bin(bypass)
end

function bsc.monotonic_s()
	return bs.monotonic()
end


function bsc.monotonic_ms()
	local sec, nsec = bs.monotonic() 
	if sec then 
		return math.floor(sec * 1000000 + nsec / 1000)
	end 
	return 0
end


function bsc.parse_user(content, cb) 
	local total  = bs.bin2int(content)
	if total + 4 ~= #content or total % 24 ~= 0 then 
	 	return syserr("error length %d %d", #content, total)
	end
	content = content:sub(1 + 4) 
	while #content > 0 do 
		local user = bs.luser(content)
		cb(user)
		content = content:sub(1 + 24) 
	end 
end

function bsc.ipbin(ip) 
	return bs.ipbin(ip)
end

function bsc.local_ip()
	return bs.localbr0ip()
end

return bsc