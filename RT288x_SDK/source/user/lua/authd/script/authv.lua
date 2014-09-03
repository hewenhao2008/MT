local ev = require("ev") 
local log = require("log") 
local socket = require("socket")
local cjson = require("cjson.safe")
local misc = require("auth.misc")
local cmdlist = require("auth.cmdlist")
local bs = require("auth.lbasic")
local lurl = require("socket.url")
local cloudlog = require("auth.cloudlog").log
local sysinfo, syserr = log.sysinfo, log.syserr
local udp_server
local evhttp_prefix = "/tmp/evhttp"

local cfg = {
	account = "",
	apgroup = "",
	password = "",
	ugwid = "",
	ac_ipaddr = "",
	ac_ipaddr_ip = "",
	ac_ipaddr_port = "",
	ads_host = "",
	ads_host_port = "",
	ads_md5sum = "",
	cloud_devname = "",
	local_ip = "",
	ads_status = false, 
	weixin_status = false,
	ssid_cloud = {},
	unautherized = {}, 
	roaming = {},
	subnet = {},
	pass_host = {},
	login_url = {},
	ssid_idx = {},
	check_file = {}
}

local cmd_map = {}

-- ra0,ra1,ra2,ra3
-- local alias = {
-- 	["eth1"] = "eth2", 
-- 	["eth2"] = "eth1",
-- 	["wl0.1"] = "wl1.1",
-- 	["wl1.1"] = "wl0.1",
-- 	["wl0.2"] = "wl1.2",
-- 	["wl1.2"] = "wl0.2",
-- 	["wl0.3"] = "wl1.3",
-- 	["wl1.3"] = "wl0.3"
-- }

local function false_restart(loop, condition, func, msg)
	if condition then return end 
	if msg then sysinfo(msg) end 
	ev.Timer.new(function()  func(loop) end, 10):start(loop)
end 

local function get_alias(lssid)
	-- return alias[lssid]
	return lssid
end 

local function get_cloud_url()
	local _ =  not cfg.ac_ipaddr and syserr("cfg.ac_ipaddr nil")
	return string.format("http://%s:%d/upload", cfg.ac_ipaddr, cfg.ac_ipaddr_port) 
end

local function evhttpclient(loop, t, ext, cb) 
	local common = "" .. bs.monotonic_ms() .. math.random() 
	local from, out = evhttp_prefix .. ".from." .. common, evhttp_prefix .. ".to." .. common
	t.Out = out 
	local file = io.open(from, "wb") 
	if not file then 
		syserr("write fail %s", from)
		return nil
	end
	local sec = bs.monotonic_s()
	table.insert(cfg.check_file, {path = from, time = sec})
	table.insert(cfg.check_file, {path = out, time = sec})
	local s = cjson.encode(t) 
	s = s:gsub("{}", "null") --TODO
	file:write(s)
	file:close()
	local cmd = "lua /usr/sbin/scripts/evhttpclient.lua " .. from .. " &"
	os.execute(cmd) 
	local estat, find = nil, false
	estat = ev.Stat.new(function()
			estat:stop(loop) 
			ev.Timer.new(function()
				find = true
				pcallf(function() 
					if not ext.need_read then  
						os.remove(from)
						return cb({out = out})
					end  
					local file, err = io.open(out, "rb")
					if not file then 
						return syserr("why open %s fail %s", out, err)
					end 
					local content = file:read("*all")
					file:close()
					os.remove(out)
					os.remove(from)
					cb({content = content})
				end)
			end, 0.05):start(loop)
		end, out)
	estat:start(loop)
	ev.Timer.new(function() 
			estat:stop(loop)
			local _ = not find and cb({}, true)
		end, ext.timeout or 10):start(loop)
end

local function new_user(user)
	assert(user.Idx and user.Mac and user.Jf and user.Ip and user.Ssid)
	return {Idx = user.Idx, Mac = user.Mac, Jf = user.Jf, Ip = user.Ip, Ssid = user.Ssid}
end

local function local_ssid(cloud_ssid)
	for k, v in pairs(cfg.ssid_cloud) do 
		if v == cloud_ssid then 
			return k 
		end 
	end 
	return nil 
end

local function exec(cmd)
	local file = io.popen(cmd, "rb")
	if not file then 
		syserr("exec %s fail", cmd)
		return nil
	end
	local content = file:read("*all")
	file:close()
	return content:gsub("[\r\n]$", "")
end

local function nvram_get(key)
	return exec("nvram get " .. key)
end

local function change_exit(old, new, msg)
	if old == "" or not old then return end 
	if old ~= new then
		sysinfo("changed from %s to %s, %s", old, new, msg)
		os.execute("killall -9 vap &")
		os.exit(0)
	end 
end 

local function reset_account_info() 
	local account = nvram_get("cloud_account")
	local password = nvram_get("cloud_password")
	local ugwid = nvram_get("et0macaddr")
	local apgroup = nvram_get("apgroup") or "defaut_group"
	if not account or not password or not ugwid then 
		syserr("nvram get cloud_account or cloud_password or et0macaddr  fail")
		cloudlog("cannot nvram get cloud_account or cloud_password or et0macaddr\n")
		return false
	end
	ugwid = string.lower(ugwid)
	change_exit(cfg.ugwid, ugwid, "ugwid changed")
	change_exit(cfg.account, account, "account changed")
	change_exit(cfg.apgroup, apgroup, "apgroup changed") 
	change_exit(cfg.password, password, "password changed")
	local _ =  cfg.account ~= account and misc.write_config("/sys/module/auth/account", account)  
	local _ =  cfg.apgroup ~= apgroup and misc.write_config("/sys/module/auth/apgroup", apgroup)  
	cfg.account, cfg.password, cfg.ugwid, cfg.apgroup = account, password, ugwid, apgroup or ""
	local ssid = nvram_get("SSID1")
	change_exit(cfg.ssid_cloud["ra0"], ssid, "SSID1 changed")
	if ssid then cfg.ssid_cloud["ra0"], cfg.ssid_cloud[get_alias("ra0")] = ssid, ssid end 
	ssid = nvram_get("SSID2") 	change_exit(cfg.ssid_cloud["ra1"], ssid, "ra1_ssid changed")
	if ssid then cfg.ssid_cloud["ra1"], cfg.ssid_cloud[get_alias("ra1")] = ssid, ssid end 
	ssid = nvram_get("SSID3") 	change_exit(cfg.ssid_cloud["ra2"], ssid, "ra2_ssid changed")
	if ssid then cfg.ssid_cloud["ra2"], cfg.ssid_cloud[get_alias("ra2")] = ssid, ssid end 
	ssid = nvram_get("SSID4") 	change_exit(cfg.ssid_cloud["ra3"], ssid, "ra3_ssid changed")
	if ssid then cfg.ssid_cloud["ra3"], cfg.ssid_cloud[get_alias("ra3")] = ssid, ssid end 
	return true 
end

local function reset_subnet()
	sysinfo("reset_subnet")
	local s = exec("ip addr | grep -E inet.*lan.* | awk '{print $2}'")
	if not s then
		return false
	end
	local new = {}
	for ipstr, maskbit in string.gmatch(s, "(%d+.%d+.%d+.%d+)/(%d+)") do 
		local ip, mask = bs.ip_mask(ipstr, maskbit)
		table.insert(new, {ip = ip, mask = mask})
	end
	table.sort(new, function(a, b) return a.mask > b.mask end)
	local reconfig = function(t)
		if #t == 0 then return end 
		misc.write_config("/sys/module/auth/subnet", bs.subnetbin(t))
		return true
	end
	if #cfg.subnet ~= #new then  
		sysinfo("subnet size changed %d %d", #cfg.subnet, #new)
		cfg.subnet = new
		return reconfig(new)
	end 
	for i, v in ipairs(cfg.subnet) do 
		if new[i].ip ~= v.ip or new[i].mask ~= v.mask then  
			sysinfo("subnet content changed %d %d %d %d", new[i].ip, v.ip, new[i].mask, v.mask)
			cfg.subnet = new
			return reconfig(new)
		end 
	end 
	return true
end

local function reset_ac_host() 
	local ac_ipaddr = nvram_get("ac_ipaddr")
	local ac_ipaddr_port = nvram_get("ac_ipaddr_port")
	if not ac_ipaddr or not ac_ipaddr_port then 
		return false
	end 
	if ac_ipaddr == cfg.ac_ipaddr and ac_ipaddr_port == cfg.ac_ipaddr_port then 
		return true 
	end 
	misc.write_config("/sys/module/auth/ac_host", ac_ipaddr)
	cfg.ac_ipaddr = ac_ipaddr
	cfg.ac_ipaddr_port = ac_ipaddr_port
	cfg.ads_host = ac_ipaddr
	cfg.ads_host_port = "80"
	return true 
end

local reset_ads
local reset_connection
local reset_weixin_host
reset_weixin_host = function(loop)
	sysinfo("reset_weixin_host")
	local weixin_path = "/tmp/weixin.bin"
	local cmd = string.format("wget -O %s -q \"%s\" 2>/dev/null &", weixin_path, "http://dns.weixin.qq.com/cgi-bin/micromsg-bin/newgetdns")
	os.remove(weixin_path)
	os.execute(cmd)
	local reconfig = function(newip)
		cfg.weixin_status = true 
		newip[cfg.ac_ipaddr] = 1
		for _, v in ipairs(cfg.subnet) do 
			newip[bs.ipstr(v.ip)] = 1
		end 
		for ip in pairs(cfg.login_url) do 
			newip[ip] = 1
		end
		if cfg.ac_ipaddr_ip ~= "" then 
			newip[cfg.ac_ipaddr_ip] = 1
		end
		if cfg.local_ip ~= ""  then 
			newip[cfg.local_ip] = 1
		end
		local need_config = false
		if misc.countk(cfg.pass_host) ~= misc.countk(newip) then 
			need_config = true
		end
		if not need_config then 
			for k in pairs(cfg.pass_host) do 
				if not newip[k] then 
					need_config = true 
					break 
				end 
			end 
		end 
		if not need_config then return end  
		cfg.pass_host = newip
		for i = 0, 3 do 
			misc.config_past_host('c', i, '0.0.0.0')
			for h in pairs(cfg.pass_host) do  
				misc.config_past_host('a', i, h)
			end 
		end 
	end

	local estat
	estat = ev.Stat.new(function()
			estat:stop(loop)
			estat = nil
			ev.Timer.new(function()
				pcallf(function()
					local file = io.open(weixin_path, "rb")
					if not file then
						false_restart(loop, cfg.weixin_status, reset_weixin_host, "reset_weixin_host")
						return syserr("why open %s fail", weixin_path) 
					end
					local content = file:read("*all")
					file:close()

					content = bs.deflate(content) 
					if not content then 
						cloudlog("deflate weixin host fail\n")
						false_restart(loop, cfg.weixin_status, reset_weixin_host, "reset_weixin_host")
						return syserr("bs.deflate %s fail", weixin_path)  
					end 
					local newip = {}
					for ip in string.gmatch(content, "<ip>(.-)</ip>") do 
						newip[ip] = 1
					end
					reconfig(newip)
				end)
			end, 0.1):start(loop)
		end, weixin_path)
	estat:start(loop)
	ev.Timer.new(function() 
			if estat then 
				estat:stop(loop) 
				false_restart(loop, cfg.weixin_status, reset_weixin_host, "reset_weixin_host")
			end 
		end, 10):start(loop)
	return true
end

reset_ads = function(loop)
	sysinfo("reset_ads") 
	local get_ads_url = function()
		return string.format("http://%s:%d/admin/ci/ap/adssync", cfg.ads_host, cfg.ads_host_port)
	end
	local reset_login_url = function()
		local login = "/tmp/webui/login.conf"
		local file = io.open(login)
		if not file then 
			return syserr("why open %s fail", login) 
		end 
		local content = file:read("*all")
		file:close()
		local t = cjson.decode(content)
		if not t then 
			return
		end 
		cfg.login_url = {}
		for k, v in ipairs(t.URL) do
			local url = v:gsub("http://", "") 
			local s = url:find("/")
			if s then 
				url = url:sub(1, s - 1)
			end
			cfg.login_url[url] = 1
			url = url:gsub("www.", "")
			cfg.login_url[url] = 1
		end
		for i = 0, 3 do 
			for k in pairs(cfg.login_url) do 
				misc.config_past_host('a', i, k)
			end			
		end 
	end
	local t = {
		Url = get_ads_url(), 
		DataType = "binary",
		Compress = "none",
		Timeout = 120,
		Content = {
			Cmd = "ads",
			Account = cfg.account,
			Ugwid = cfg.ugwid,
			Password = cfg.password,
			Data = {
				Md5 = cfg.ads_md5sum,
				Ugwid = cfg.ugwid,
			}
		}
	}
	evhttpclient(loop, t, {need_read = false, timeout = 120}, function(t, timeout)
			if timeout then 
				cloudlog("download ads timeout\n")
				syserr("download ads timeout")
				return false_restart(loop, cfg.ads_status, reset_ads, "reset_ads")
			end
			sysinfo("fetch ads.tar ok")
			local file = io.open(t.out, "rb")
			local size = file:seek("end")
			if size <= 1024 then  
				file:seek("set")
				local content = file:read("*all")
				file:close()
				if content:find("^202 ") then 
					return cloudlog("download ads fail. msg %s\n", content) 
				end
				if content:find("^201 ") then 
					return sysinfo("%s", content)
				end 
			else 
				file:close()
			end
			local fmt = [[
				rm -rf /tmp/webui.tmp && mkdir /tmp/webui.tmp || exit 1
				tar -zxf %s -C /tmp/webui.tmp || exit 2
				ls /tmp/webui.tmp/index* >/dev/null 2>&1 || exit 3
				rm -rf /tmp/webui.bak
				test -e /tmp/webui && mv /tmp/webui /tmp/webui.bak
				mv /tmp/webui.tmp /tmp/webui
				rm -rf /tmp/webui.bak
				killall -9 httpauth >/dev/null 2>&1
				md5sum %s | awk '{print $1}'
			]]
			local cmd = string.format(fmt, t.out, t.out) 
			local file = io.popen(cmd, "r")  
			if not file then 
				syserr("exec %s fail", cmd)
				os.remove(t.out)
				return false_restart(loop, cfg.ads_status, reset_ads, "reset_ads")
			end
			local md5 = file:read("*all")
			file:close() 
			os.remove(t.out)
			if not md5 then 
				sysinfo("download but uncompress fail") 
				return false_restart(loop, cfg.ads_status, reset_ads, "reset_ads")
			end
			cloudlog("download ads success\n")
			md5 = md5:gsub("[\r\n]", "")
			if cfg.ads_md5sum == md5 then 
				return sysinfo("m5sum stay unchanged") 
			end
			sysinfo("md5 %s to %s", cfg.ads_md5sum, md5);
			cfg.ads_md5sum = md5
			reset_login_url()
			cfg.ads_status = true
		end) 
	return true 
end

reset_connection = function(loop) 
	local res_path = "/tmp/connect_result"
	local cmd = string.format("wget -s \"http://%s\" > %s 2>&1 &", cfg.ac_ipaddr, res_path)
	os.remove(res_path)
	os.execute(cmd) 
	local reconfig = function(bypass) 
		local msg = "success"
		if bypass == 1 then 
			msg = "fail" 
		end
		cloudlog("connect to %s %s\n", cfg.ac_ipaddr, msg) 
		misc.write_config("/sys/module/auth/bypass", bs.int2bin(bypass)) 
	end 

	local estat
	estat = ev.Stat.new(function(lp, stat, revs)
			estat:stop(loop) estat = nil
			ev.Timer.new(function()
				pcallf(function()
					local fp = io.open(res_path, "rb")
					if not fp then 
						syserr("error open %s", res_path)
						return reconfig(1)
					end
					local content = fp:read("*all") 
					fp:close()

					local host_ip = content:match("Connecting.-%((%d+.%d+.%d+.%d+).*%)") 
					if host_ip then
						if cfg.ac_ipaddr_ip ~= host_ip then 
							cfg.ac_ipaddr_ip = host_ip
							for i = 0, 3 do misc.config_past_host("a", i, host_ip) end 
						end
						return reconfig(0) 
					end
					reconfig(1)
					return false_restart(loop, false, reset_connection, "reset_connection 2")
				end)
			end, 1):start(loop)
		end, res_path)
	estat:start(loop)
	ev.Timer.new(function() 
		if estat then 
			estat:stop(loop)	estat = nil
			false_restart(loop, false, reset_connection, "reset_connection 1")
		end
		end, 60):start(loop)
end

local function init()
	os.execute(string.format("rm %s.* >/dev/null 2>&1 &", evhttp_prefix))
	if not reset_account_info() or not reset_subnet() then 
		os.exit(0)
	end 
	cfg.ssid_idx["ra0"], 	cfg.ssid_idx["ra5"] = 0, 0
	cfg.ssid_idx["ra1"], 	cfg.ssid_idx["ra6"] = 1, 1
	cfg.ssid_idx["ra2"], 	cfg.ssid_idx["ra7"] = 2, 2
	cfg.ssid_idx["ra3"], 	cfg.ssid_idx["ra8"] = 3, 3
end

local function reset_local_ip()
	local tip = bs.local_ip()
	if not tip then 
		syserr("get local ip fail, exit")
		os.exit(0)
		return nil
	end 
	if tip == cfg.local_ip then
		return nil
	end 
	sysinfo("reset local ip from %s to %s", cfg.local_ip, tip)
	cfg.local_ip = tip
	return tip 
end 

local function reset_url(idx, url)
	local content = string.format("%02d %04d %s", idx, #url, url)
	print(content)
	misc.write_config("/sys/module/auth/redirect", content)
end

local function reset_redirect(loop) 
	local oldip = cfg.local_ip
	local newip = reset_local_ip()
	if not newip then
		return false
	end   
	local escape_group = lurl.escape(cfg.apgroup):gsub("%%", "%%%%") 
	for i = 0, 3 do
		local ssid, url
			ssid = cfg.ssid_cloud[string.format("ra%d", i)]
		local escape_ssid = lurl.escape(ssid):gsub("%%", "%%%%")
		--if cfg.account == "fx" then 
		--	local urlfmt = "HTTP/1.1 302 Moved Temporarily\r\nLocation: http://www.adfx.cn/wifi/serv/ads.action?apmac=%s&apgroup=%s&ssid=%s&usermac=%%s&userip=%%s\r\nContent-Type: text/html;\r\nCache-Control: no-cache\r\nContent-Length: 0\r\n\r\n"
		--	url = string.format(urlfmt, cfg.ugwid, escape_group, escape_ssid)
		--else
			local urlfmt = "HTTP/1.1 302 Moved Temporarily\r\nLocation: http://%s/index.html?ugwid=%s&apgroup=%s&ssid=%s&account=%s&mac=%%s&ip=%%s\r\nContent-Type: text/html;\r\nCache-Control: no-cache\r\nContent-Length: 0\r\n\r\n"
			url = string.format(urlfmt, cfg.local_ip, cfg.ugwid, escape_group, escape_ssid, cfg.account)
		--end
		reset_url(i, url)
		misc.config_past_host("d", i, oldip)
		misc.config_past_host("a", i, cfg.local_ip)
	end
	return true
end

local function init_cloud(loop) 
	if not reset_ac_host() or not reset_redirect() or not reset_weixin_host(loop) or not reset_ads(loop) then 
		syserr("init_cloud fail")
		cloudlog("init fail\n")
		return false
	end 
	reset_connection(loop)
	return true 
end 

local function check_online_user(loop)
	sysinfo("check_online_user")
	local online_path = "/sys/module/auth/online"
	local file, err = io.open(online_path, "rb")
	if not file then 
		return syserr("open fail %s %s", online_path, err) 
	end 
	local content = file:read("*all")
	file:close()
	local users = {}
	bs.parse_user(content, function(user)
			local cloud_ssid = cfg.ssid_cloud[user.Ssid]
			if not cloud_ssid then 
				return syserr("cannot find cloud ssid for %s", user.Ssid)
			end
			user.Ssid = cloud_ssid
			table.insert(users, user)
		end)
	--if #users == 0 then table.insert(users, {Idx = 0, Jf = 0, Ip = "0.0.0.0", Mac = "00:00:00:00:00:00", Ssid = "####"}) end 
	local tv = {
		Url = get_cloud_url(),
		Content = {
			Cmd = "active",
			Account = cfg.account,
			Ugwid = cfg.ugwid,
			Data = users
		}
	} 
	evhttpclient(loop, tv, {need_read = true, timeout = 60}, function(rt, timeout) 
			if timeout then 
				cloudlog("check online user timeout\n")
				return
			end 
			local t = cjson.decode(rt.content)
			if not t then 
				print("active decode fail", rt.content)
				return
			end
			if not t.Cmd or t.Cmd ~= "active" then 
				return syserr("why result cmd not active %s", t.Cmd)
			end
			local function translate(users, trans, cb)
				for _, user in ipairs(users) do
					if trans then 
						local ssid = local_ssid(user.Ssid)
						if not ssid then 
							syserr("cannot find local ssid for", user.Ssid)
						else 
							user.Ssid = ssid 
							cb(user)
						end
					else 
						cb(user)
					end 
				end 
			end 
			translate(type(t.Offline) == 'table' and t.Offline or {}, true, function(user)
					misc.notify_kernel_offline(user)
				end)
			cfg.roaming = {} 
			translate(type(t.Online) == 'table' and t.Online or {}, false, function(user)
					cfg.roaming[user.Mac .. user.Ssid] = new_user(user)
				end) 
			--pt(cfg.roaming)
			--if #cfg.roaming == 0 then cfg.roaming["f0:c1:f1:11:35:70default_ssid"] = {Idx = 0, Ssid = "default_ssid", Ip = "192.168.10.10", Mac = "f0:c1:f1:11:35:70", Jf = 0} end --TODO delete 
		end) 
end

local function active_msg(loop)
	if cfg.cloud_devname == "" then 
		return syserr("cannot find cloud_devname") 
	end 
	local tv = {
		Url = get_cloud_url(),
		Content = {
			Cmd = "smbwdev_active",
			Account = cfg.account,
			Ugwid = cfg.ugwid,
			Data = {
				DeviceName = cfg.cloud_devname
			}
		}
	}
	evhttpclient(loop, tv, {need_read = true}, function(rt) end)
end 

local function clear_outdate(loop)
	sysinfo("clear_outdate")
	local sec = bs.monotonic_s()
	local left = {}
	for _, item in ipairs(cfg.check_file) do 
		if sec - item.time > 60 then 
			os.remove(item.path)
		else 
			table.insert(left, item)
		end
	end
	cfg.check_file = left
end 

local function timeout_reset(loop) 
	ev.Timer.new(function() pcallf(function() reset_ads(loop) end) end, 300, 300):start(loop)
	--ev.Timer.new(function() pcallf(function() reset_subnet(loop) end) end, 20, 20):start(loop)
	ev.Timer.new(function() pcallf(function() reset_ac_host(loop) end) end, 60, 60):start(loop)
	ev.Timer.new(function() pcallf(function() reset_connection(loop) end) end, 300, 300):start(loop)
	ev.Timer.new(function() pcallf(function() check_online_user(loop) end) end, 10, 300):start(loop)
	ev.Timer.new(function() pcallf(function() reset_weixin_host(loop) end) end, 3600, 3600):start(loop) 
	ev.Timer.new(function() pcallf(function() reset_account_info(loop) end) end, 10, 10):start(loop)
	--ev.Timer.new(function() pcallf(function() active_msg(loop) end) end, 0.1, 180):start(loop)
	ev.Timer.new(function() pcallf(function() clear_outdate(loop) end) end, 300, 300):start(loop)
	ev.Timer.new(function() pcallf(function() reset_redirect(loop) end) end, 30, 30):start(loop) 
end

local function receive_command(loop) 
	udp_server = assert(socket.udp(), "create udp socket fail")
	local host, port = "127.0.0.1", 9999
	udp_server:setsockname(host, port)
	udp_server:settimeout(0)
	ev.IO.new(function()
			pcallf(function()
				local s, ip, port = udp_server:receivefrom() 
				local t = cjson.decode(s)
				if not t then 
					syserr("decode fail %s %s %d", s, ip, port)
				else 
					t.client_ip = ip
					t.client_port = port  
					cmdlist.default():push(cjson.encode(t)) 
				end  
			end)
		end, udp_server:getfd(), ev.READ):start(loop)
end

local function check_roaming(user)
	local cloud_ssid = cfg.ssid_cloud[user.Ssid]
	if not cloud_ssid then 
		syserr("ERROR cannot find cloud_ssid for %s", user.Ssid)
		return false
	end
	if cfg.roaming[user.Mac .. cloud_ssid] then 
		sysinfo("user %s %s %s is roaming", user.Ip, user.Mac, user.Ssid)
		misc.notify_kernel_online(user)
		return true
	end 
	return false
end

function cmd_map.chek(loop, cmd, s) 
	local query = function(user)
		local user = new_user(user)
		local cloud_ssid = cfg.ssid_cloud[user.Ssid]
		if not cloud_ssid then 
			syserr("cannot find cloud_ssid for %s", user.Ssid)
			return false 
		end 
		local notify_content = {
			Url = get_cloud_url(), 
			Content = {
				Cmd = "login",
				Account = cfg.account,
				Ugwid = cfg.ugwid,
				Data = {Mac = user.Mac, Ssid = cloud_ssid, UserName = "x", Password = "x", Ip = user.Ip}
			}
		}

		evhttpclient(loop, notify_content, {need_read = true, timeout = 30}, function(rt)
				local t = cjson.decode(rt.content)
				if not t or not t.Cmd or not t.Data then
					return syserr("decode %s fail", s) 
				end
				if t.Cmd ~= "login" or t.Data == "fail" then 
					return
				end
				sysinfo("user is online %s %s %s %s", user.Ip, user.Mac, user.Ssid, rt.content)
				misc.notify_kernel_online(user)
			end)
	end

	local ms = bs.monotonic_ms()
	local user = cmd.Data
	local key = user.Mac .. user.Idx 
	local old = cfg.unautherized[key]
	if not old then
		local new = new_user(user)
		new.Jf = ms 
		cfg.unautherized[key] = new
		if check_roaming(new) then
			return true 
		end
		sysinfo("unautherized %s %s %s", new.Ip, new.Mac, new.Ssid)
		query(new)
		return true
	end
	if check_roaming(old) then
		return true 
	end
	local d = ms - old.Jf
	if d < 10 * 1000000 then 
		return true 
	end
	old.Jf = ms
	old.Ip = user.Ip
	query(old)
	return true
end

function cmd_map.aplg(loop, cmd, s)
	if not cmd.Data or not cmd.Data.Seq or not cmd.Data.Ip 
		or not cmd.Data.UserName or not cmd.Data.Password then 
		return false
	end
	if not cmd.Data.Ssid then 
		syserr("do not find Ssid %s", s)
		return false
	end
	local cloud_ssid = lurl.unescape(cmd.Data.Ssid) 
	local lssid = local_ssid(cloud_ssid)
	if not lssid then 
		syserr("cannot find local ssid for %s", cloud_ssid)
		return false
	end
	local user
	for x, k in pairs(cfg.unautherized) do
		if (lssid == k.Ssid or lssid == get_alias(k.Ssid)) and cmd.Data.Ip == k.Ip then 
			user = k
			break 
		end
	end  
	if not user then  
		cloudlog("cannot find user for ip %s %s\n", cmd.Data.Ip, lssid)
		syserr("cannot find user for ip %s %s", cmd.Data.Ip, lssid)
		return false
	end 
	local mac = user.Mac 

	local function reply(t)
		local s = cjson.encode(t)
		local wio
		local server = udp_server
		wio = ev.IO.new(function()
				wio:stop(loop)
				pcallf(function()  
					server:sendto(s, cmd.client_ip, cmd.client_port)
				end)
			end, server:getfd(), ev.WRITE)
		wio:start(loop)
	end

	local tv = {
		Url = get_cloud_url(),
		Content = {
			Cmd = "login",
			Account = cfg.account,
			Ugwid = cfg.ugwid,
			Data = {
				Mac = mac,
				Ssid = cloud_ssid,
				UserName = cmd.Data.UserName,
				Password = cmd.Data.Password,
				Ip = cmd.Data.Ip
			}
		}
	}
	print(cjson.encode(tv))
	evhttpclient(loop, tv, {need_read = true, timeout = 30}, function(rt, timeout) 
			if timeout then 
				return cloudlog("login timeout %s %s %s\n", cmd.Data.Ip, mac, cmd.Data.UserName)
			end 
			local t = cjson.decode(rt.content)
			if not t or not t.Cmd or t.Cmd ~= "login" or not t.Data or not t.Detail then 
				return syserr("decode %s fail", rt.content)
			end 
			local code = "202"
			if t.Data == "success" then 
				code = "302"
				misc.notify_kernel_online(user)
			else 
				cloudlog("user %s %s %s login fail\n", cmd.Data.Ip, mac, cmd.Data.UserName)
			end 
			local re = {	Cmd = cmd.Cmd, 
						Data = {
							Seq = cmd.Data.Seq,
							Code = code,
							Detail = t.Detail
						}
					}
			reply(re)
		end)
	return true
end 

function cmd_map.apif(loop, cmd, s)
	if not cmd.Data or not cmd.Data.Seq or not cmd.Data.Ip then 
		return false
	end 

	local function reply(t)
		local s = cjson.encode(t)
		local wio
		local server = udp_server
		wio = ev.IO.new(function()
				wio:stop(loop)
				pcallf(function()  
					server:sendto(s, cmd.client_ip, cmd.client_port)
				end)
			end, server:getfd(), ev.WRITE)
		wio:start(loop)
	end

	local seq, ip = cmd.Data.Seq, cmd.Data.Ip
	local user
	for _, item in pairs(cfg.unautherized) do  
		if ip == item.Ip then 
			user = item 
			break 
		end 
	end
	if not user then 
		syserr("cannot find mac for %s", cmd.Data.Ip)
		cloudlog("cannot find mac for %s\n", cmd.Data.Ip)
		reply({Cmd = cmd.Cmd, Data = {Seq = seq, Ip = ip, Ugwid = cfg.ugwid, Account = cfg.account, Ssid = "none", Mac = "00:00:00:00:00:00"}})
		return true 
	end 
	misc.set_through(bs.ipbin(ip))
	local t = {Cmd = cmd.Cmd, Data = {
			Seq = seq,
			Ip = user.Ip,
			Ugwid = cfg.ugwid,
			Account = cfg.account,
			Apgroup = cfg.apgroup,
			Ssid = cfg.ssid_cloud[user.Ssid] or "none",
			Mac = user.Mac
		}
	} 
	reply(t)
	return true
end 

function cmd_map.usst(loop, cmd, s)
	sysinfo("%s", s)
	if not cmd.Data then
		syserr("usst cmd.Data nil")
		return false
	end
	for _, item in ipairs(cmd.Data) do 
		if not item.Action or not item.Ssid or not item.Ip or not item.Mac then 
			return false 
		end 
		local ssid = local_ssid(item.Ssid)
		if not ssid then 
			syserr("usst cannot find local ssid for %s", item.Ssid)
			return false 
		end 
		local idx = cfg.ssid_idx[ssid]
		if not idx then 
			syserr("usst cannot find idx for ssid %s", ssid)
			return false 
		end
		local user = {Mac = item.Mac, Idx = idx, Jf = 0, Ssid = ssid, Ip = item.Ip}
		if item.Action == "off" then 
			misc.notify_kernel_offline(user)
			cfg.roaming[item.Mac .. item.Ssid] = nil
			sysinfo("delete %s from roaming", item.Mac .. item.Ssid)
		else
			misc.notify_kernel_online(user)
		end
	end
	return true
end 

function cmd_map.wxlg(loop, cmd, s)
	if not cmd.Data then 
		return false 
	end
	local user = cmd.Data
	local cloud_ssid = cfg.ssid_cloud[user.Ssid]
	if not cloud_ssid then 
		syserr("cannot find cloud ssid for %s", user.Ssid)
		return false 
	end 

	local tv = {
		Url = get_cloud_url(),
		Content = {
			Cmd = "weixin",
			Account = cfg.account,
			Ugwid = cfg.ugwid,
			Data = {
				Mac = user.Mac,
				Ssid = cloud_ssid or "error_cloud_id",
				UserName = "x",
				Password = "x",
				Ip = user.Ip
			}
		}
	}
	evhttpclient(loop, tv, {need_read = true}, function(rt, timeout) 
			if timeout then 
				return cloudlog("weixin login timeout %s %s\n", user.Mac, user.Ip)
			end
			sysinfo("%s", rt.content)
		end)
	return true
end 

function cmd_map.smlg(loop, cmd, s) 
	if not cmd.Data or not cmd.Data.Seq or not cmd.Data.Ip 
		or not cmd.Data.UserName then 
		return false
	end
	if not cmd.Data.Ssid then 
		syserr("do not find Ssid")
		return false
	end
	local cloud_ssid = lurl.unescape(cmd.Data.Ssid) 
	local lssid = local_ssid(cloud_ssid)
	if not lssid then 
		syserr("cannot find local ssid for %s", cloud_ssid)
		return false
	end
	local user 
	for x, k in pairs(cfg.unautherized) do
		if (lssid == k.Ssid or lssid == get_alias(k.Ssid)) and cmd.Data.Ip == k.Ip then 
			user = k
			break
		end
	end  
	if not user then  
		cloudlog("cannot find user for ip %s %s\n", cmd.Data.Ip, lssid)
		syserr("cannot find user for ip %s %s", cmd.Data.Ip, lssid)
		return false
	end 
	local mac = user.Mac 
	local function reply(t)
		local s = cjson.encode(t)
		local wio
		local server = udp_server
		wio = ev.IO.new(function()
				wio:stop(loop)
				pcallf(function()  
					server:sendto(s, cmd.client_ip, cmd.client_port)
				end)
			end, server:getfd(), ev.WRITE)
		wio:start(loop)
	end

	local tv = {
		Url = get_cloud_url(),
		Content = {
			Cmd = "phonereg",
			Account = cfg.account,
			Ugwid = cfg.ugwid,
			Data = {
				Mac = mac,
				Ssid = "test_cloud_id",
				UserName = cmd.Data.UserName,
				Password = "x",
				Ip = cmd.Data.Ip
			}
		}
	}

	evhttpclient(loop, tv, {need_read = true, timeout = 60}, function(rt) 
			local t = cjson.decode(rt.content)
			if not t or not t.Cmd or t.Cmd ~= "login" or not t.Data or not t.Detail then 
				return syserr("decode %s fail", rt.content)
			end
			local code = "302"
			if t.Data == "fail" then 
				code = "202"
			end
			local re = {	Cmd = cmd.Cmd, 
						Data = {
							Seq = cmd.Data.Seq,
							Code = code,
							Detail = t.Detail
						}
					}
			reply(re)
		end)
	return true		
end 

local function deal_command(loop) 
	ev.Timer.new(function()
			pcallf(function()
				local dflist = cmdlist.default()
				local s = dflist:pop()
				if not s then return end
				local cmd = cjson.decode(s) 
				if cmd and cmd.Cmd and cmd_map[cmd.Cmd] then 
					local ret = cmd_map[cmd.Cmd](loop, cmd, s)
					local _ = ret or syserr("process fail %s", s)
				else 
					syserr("error", s)
				end
			end)
		end, 0.01, 0.01):start(loop)
end

local function start(loop)
	sysinfo("start authv")
	init(loop)
	init_cloud(loop)
	receive_command(loop)
	timeout_reset(loop)
	deal_command(loop) 
end

return {start = start}