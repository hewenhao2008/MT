#include "miniz.c"

#include <stdio.h>
#include <limits.h>
#include <lua.h>
#include <lauxlib.h> 

typedef unsigned char uint8;
typedef unsigned short uint16;
typedef unsigned int uint;

int deflate_binary(const char *next_in, int in_bytes, char *out, int *out_bytes) { 
	tinfl_decompressor inflator;
	tinfl_init(&inflator); 
	char *nout = out;
	tinfl_status status = tinfl_decompress(&inflator, (const mz_uint8 *)next_in, (size_t *)&in_bytes, (mz_uint8 *)out, (mz_uint8 *)nout, (size_t *)out_bytes, 0); 
	if (status < TINFL_STATUS_DONE)
		return -1;
	return 0;
}
static int plower_bould(int size) {
	int i = 10, least = 1<<10;
	while (1) {
		least = 1<<i; 
		if (size <= least)
			return least;
		i++;
	}
	return 0;
}
static int l_deflate_binary(lua_State *L) {
	if (!lua_isstring(L, 1) || !lua_isstring(L, 2)) {
		lua_pushnil(L);
		lua_pushfstring(L, "invalid input type %s %s", lua_typename(L, lua_type(L, 1)), lua_typename(L, lua_type(L, 2)));
		return 2;
	}
	const char *addr = lua_tostring(L, 1);
	int len = lua_tointeger(L, 2);
	int outlen = plower_bould(len * 10);
	char *out = (char *)malloc(outlen);
	if (deflate_binary(addr, len, out, &outlen)) {
		lua_pushnil(L);
		lua_pushfstring(L, "deflate_binary fail");
		return 2;
	}
	lua_pushlstring(L, out, outlen);
	free(out);
	return 1;
}

static luaL_Reg reg[] = { 
		{ "deflate", l_deflate_binary },
        { NULL, NULL }
    };
	
LUALIB_API int luaopen_miniz(lua_State *L) {
	luaL_register(L, "miniz", reg);
	return 1;
}

