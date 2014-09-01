for i = 1, 20 do
	local file = io.popen(string.format('find /bin/scripts/ -name "*.lua"'), "r")
	if file then
		for line in file:lines() do
			local need_compile = true
			local f = io.open(line, "rb")
			if f then
				local c = f:read(1)
				f:close()
				if string.byte(c) == 27 then 
					need_compile = false
				end
			end
			if need_compile then 
				os.execute(string.format("luac -s -o %s %s", line, line)) 
			end
		end
		os.exit(0)
	end
end