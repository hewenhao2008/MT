
local ev = require("ev")
local cjson = require("cjson.safe")
local misc = require("auth.misc")
local bs = require("auth.lbasic")
local cmdlist = require("auth.cmdlist")
local authm = {}

local function send_command(cmd, user)
	local t = {Cmd = cmd, Data = user}
	local s = cjson.encode(t)
	local dflist = cmdlist.default() 
	dflist:push(s)
end

local function watch_common(path, cmd)
	local file = io.open(path, "rb")
	if not file then 
		return 
	end 
	local content = file:read("*all")
	file:close()
	if #content <= 0 then 
		return
	end
	bs.parse_user(content, function(user)
			send_command(cmd, user)
		end)
end

local watch_items = {
	{func = watch_common, cmd = "chek", file = "/sys/module/auth/verify"},
	{func = watch_common, cmd = "wxlg", file = "/sys/module/auth/weixin_login"},
}

function authm.start(loop)
	ev.Timer.new(function()
			pcallf(function()
				for _, item in ipairs(watch_items) do 
					item.func(item.file, item.cmd)
				end
			end)
		end, 0.05, 0.05):start(loop) 
end

return authm