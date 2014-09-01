local cmd = {}

local mt = {
	__index = {
		push = function(ins, new)
			table.insert(ins.list, new)
		end,
		pop = function(ins)
			return table.remove(ins.list, 1)
		end,
	},
	__newindex = function(t, k, v)
		error("attemp to add new field", k)
	end,
}

function cmd.new()
	local ins = {list = {}}
	setmetatable(ins, mt)
	return ins
end

local default
function cmd.default()
	if default then 
		return default
	end
	default = cmd.new()
	return default
end

return cmd
