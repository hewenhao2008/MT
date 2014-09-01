package.cpath = "/usr/lib/?.so;" .. package.cpath
package.path = "/usr/sbin/scripts/?.lua;" .. package.path
require("global")
local mime = require("mime")
local cjson = require("cjson.safe")
local lz = require("lz4")
local bs = require("basic")
local ehc = require("ehc")
local log = require("log") 
local unb64 = mime.decode("base64")
local function encode_data(content, dtype, ctype)	
	local s = content
	if not (ctype and ctype == "none") then 
		s = lz.compress(s, #s) 
	end 
	if not (dtype and dtype ~= "binary") then 
		s = bs.xor(s, #s) 
	end 
	s = mime.b64(s)
	return s
end

local function decode_data(content, dtype, ctype)
	local s = content  
	s = unb64(s)
	if not dtype or dtype ~= "binary" then 
		s = bs.xor(s, #s) 
	end 
	if not (ctype and ctype == "none") then 
		s = lz.decompress(s, #s)
	end
	return s
end


local function main(path)  
	local file = io.open(path, "rb")
	if not file then 
		os.exit(-1)
	end
	local orig = file:read("*all")
	local content = orig
	file:close() 
	local cmd = cjson.decode(content)
	local url, out, contab, dtype, ctype = assert(cmd.Url), assert(cmd.Out), assert(cmd.Content), cmd.DataType, cmd.Compress

	local check_ads = function(res) 
		if not res:find("^20[12] ") then 
			return
		end 
		io.output(out):write(res)
		os.exit(-1)
	end

	define("response_callback")
	function response_callback(timeout, content) 
		if timeout then 
			log.syserr("post timeout %s", orig)
			os.exit(-1)
		end 

		local _ = contab.Cmd == "ads" and check_ads(content)

		local data = decode_data(content, dtype, ctype) 
		if not data then 
			log.syserr("decode data fail")
			os.exit(-1)
		end  
		local file = io.open(out, "wb")
		file:write(data)
		file:close()
		os.exit(0)	
	end

	content = cjson.encode(contab)  
	content = encode_data(content, dtype, ctype)
	if not content then 
		log.syserr("encode data fail")
		os.exit(-1)
	end
	ehc.start(url, content, tostring(#content), cmd.Timeout)
end

main(assert(arg[1]))