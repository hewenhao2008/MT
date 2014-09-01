#include "lz4.h"
#include <stdio.h>
#include <stdlib.h>
#include <lua.h>
#include <lauxlib.h> 

static int l_decompress(lua_State *L) {
	if (!lua_isstring(L, 1) || !lua_isnumber(L, 2)) {
		lua_pushnil(L);
		lua_pushfstring(L, "invalid input type %s %s", lua_typename(L, lua_type(L, 1)), lua_typename(L, lua_type(L, 2)));
		return 2;
	} 
	const char *addr = lua_tostring(L, 1);
	int total = lua_tointeger(L, 2);
	int rawlen = *(int *)addr;
	addr += 4;
	if (rawlen > 1024*1024*10) {
		lua_pushnil(L);
		lua_pushfstring(L, "invalid rawlen %d %d, max %d\n", rawlen, total, 1024*1024*10);
		return 2;
	} 
	char *out = (char *)malloc(rawlen);
	if (!out) {
		lua_pushnil(L);
		lua_pushfstring(L, "malloc fail");
		return 2;
	} 
	int ret = LZ4_decompress_safe(addr, out, total - 4, rawlen);
	if (ret <= 0 || ret > rawlen || ret != rawlen) {
		lua_pushnil(L);
		lua_pushfstring(L, "LZ4_decompress_safe fail %d %d", ret, rawlen);
		free(out);
		return 2;
	}
	lua_pushlstring(L, out, rawlen);
	lua_pushnumber(L, rawlen);
	return 2;
}
static int l_compress(lua_State *L) {
	if (!lua_isstring(L, 1) || !lua_isnumber(L, 2)) {
		lua_pushnil(L);
		lua_pushfstring(L, "invalid input type %s %s", lua_typename(L, lua_type(L, 1)), lua_typename(L, lua_type(L, 2)));
		return 2;
	}
	const char *addr = lua_tostring(L, 1);
	int len = lua_tointeger(L, 2);
	int outlen = LZ4_compressBound(len) + 4;
	char *out = (char *)malloc(outlen);
	if (!out) {
		lua_pushnil(L);
		lua_pushfstring(L, "malloc fail");
		return 2;
	}
	int *rawlen = (int *)out; 
	int ret = LZ4_compress(addr, out + 4, len);
	if (ret <= 0) {
		free(out);
		lua_pushnil(L);
		lua_pushfstring(L, "LZ4_compress fail");
		return 2;
	}
	*rawlen = len; 
	lua_pushlstring(L, out, ret + 4);
	lua_pushnumber(L, ret + 4);
	free(out);
	return 2;
}

static luaL_Reg reg[] = { 
		{ "compress", l_compress },
		{ "decompress", l_decompress },
        { NULL, NULL }
    };
	
LUALIB_API int luaopen_lz4(lua_State *L) {
	luaL_register(L, "lz4", reg);
	return 1;
}

