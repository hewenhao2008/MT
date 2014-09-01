#include <time.h>
#include <string.h> 
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <lua.h>
#include <lauxlib.h> 
#include "wrap.h"

static lua_State *s_L;
static void res_cb(int timeout, const char *data, int data_len) {
	lua_getglobal(s_L, "response_callback");
	lua_pushboolean(s_L, timeout);
	lua_pushlstring(s_L, data, data_len);
	lua_pcall(s_L,2,0,0);
	exit(0);
}

static int l_start(lua_State *L) {
	if (!lua_isstring(L, 1) || !lua_isstring(L, 2) || !lua_isstring(L, 3)) {
		lua_pushnil(L);
		lua_pushfstring(L, "invalid input type %s %s", lua_typename(L, lua_type(L, 1)), 
			lua_typename(L, lua_type(L, 2)), lua_typename(L, lua_type(L, 3)));
		return 2;
	}
	int timeout = -1;
	if (lua_isnumber(L, 4)) {
		timeout = lua_tonumber(L, 4);
		printf("reset timeout to %d\n", timeout);
	}
	struct ev_http *ins = evhttp_create();
	if (timeout > 0)
		evhttp_set_timeout(ins, timeout);
	evhttp_set_header(ins,  "Content-Type", "application/octet-stream"); 
	evhttp_set_header(ins,  "Content-Length", lua_tostring(L, 3)); 
	evhttp_post(ins, lua_tostring(L, 1), lua_tostring(L, 2), res_cb);
	return 0;
}

static luaL_Reg reg[] = {
		{ "start", l_start }, 
        { NULL, NULL }
    };
	
LUALIB_API int luaopen_ehc(lua_State *L) {
	luaL_register(L, "ehc", reg);
	s_L = L;
	return 1;
}


