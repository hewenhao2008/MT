#include <time.h>
#include <string.h> 
#include <memory.h>
#include <stdio.h>
#include <syslog.h>
#include <stdlib.h>
#include <errno.h> 
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h> 
#include <lua.h>
#include <lauxlib.h> 

struct user_info_st {
	int idx;
	unsigned int ip;
	unsigned int jf; 	 
	unsigned char mac[6];
	char ssid[6];
};

static int l_monotonic (lua_State *L) {
	struct timespec t;
	int ret = clock_gettime(CLOCK_MONOTONIC, &t);
	if (ret) {
		lua_pushnil(L);
		lua_pushfstring(L, "clock_gettime fail, errno %d", errno);
		return 2;
	}
	lua_pushnumber(L, t.tv_sec);
	lua_pushnumber(L, t.tv_nsec); 
	return 2;
}

static char *ipbin(const char *str, unsigned char *ip) {
	int i;
	unsigned int tmp[4] = {0};
	int ret = sscanf(str, "%d.%d.%d.%d", &tmp[0], &tmp[1], &tmp[2], &tmp[3]);
	if (ret != 4) 
		return NULL;
	for (i = 0; i < 4; i++) {
		if (tmp[0] > 255) 
			return NULL;
		ip[i] = tmp[i];
	}
	return ip;
}

static int l_ipbin (lua_State *L) {
	int ret; 
	unsigned char ip[4];
	const char *str = lua_tostring(L, 1);
	if (!str)
		goto invalid_input;
	if (!ipbin(str, ip))
		goto invalid_input;
	lua_pushlstring(L, ip, 4);
	return 1;
invalid_input:
	lua_pushnil(L);
	lua_pushfstring(L, "invalid input %s", str);
	return 2;
}

static int l_ipstr (lua_State *L) {
	int ret, i; 
	if (!lua_isstring(L, 1)) {
		lua_pushnil(L);
		lua_pushfstring(L, "invalid input type %s", lua_typename(L, lua_type(L, 1)));
		return 2;
	}
	
	const unsigned char *addr = lua_tostring(L, 1); 
	char buff[32] = {0};
	snprintf(buff, sizeof(buff), "%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3]);
	lua_pushfstring(L, "%s", buff); 
	return 1;
}

static char *macbin(const char *str, unsigned char *mac) {
	int i;
	unsigned int tmp[6] = {0};
	int ret = sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x", &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5]);
	if (ret != 6) 
		return NULL;
	for (i = 0; i < 6; i++) {
		if (tmp[0] > 255) 
			return NULL;
		mac[i] = tmp[i];
	}
	return mac;
}

static int l_macbin (lua_State *L) {
	int ret; 
	unsigned char mac[6];
	const char *str = lua_tostring(L, 1);
	if (!str)
		goto invalid_input;
	if (!macbin(str, mac))
		goto invalid_input;
	lua_pushlstring(L, mac, 6);
	return 1;
invalid_input:
	lua_pushnil(L);
	lua_pushfstring(L, "invalid input %s", str);
	return 2;
}

static int l_macstr (lua_State *L) {
	int ret, i;
	
	if (!lua_isstring(L, 1)) {
		lua_pushnil(L);
		lua_pushfstring(L, "invalid input type %s", lua_typename(L, lua_type(L, 1)));
		return 2;
	}
	
	const char *str = lua_tostring(L, 1);
	char buff[32] = {0};
	unsigned char *addr = (unsigned char *)str;
	snprintf(buff, sizeof(buff), "%02x:%02x:%02x:%02x:%02x:%02x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
	lua_pushfstring(L, "%s", buff); 
	return 1;
}

static int l_lshift (lua_State *L) {
	if (!lua_isnumber(L, 1) || !lua_isnumber(L, 2)) {
		lua_pushnil(L);
		lua_pushfstring(L, "invalid input type %s %s", lua_typename(L, lua_type(L, 1)), lua_typename(L, lua_type(L, 2)));
		return 2;
	}
	lua_pushnumber(L, lua_tointeger(L, 1) << lua_tointeger(L, 2));
	return 1;
}

static int l_htonl (lua_State *L) {
	if (!lua_isnumber(L, 1)) {
		lua_pushnil(L);
		lua_pushfstring(L, "invalid input type %s", lua_typename(L, lua_type(L, 1)));
		return 2;
	}
	lua_pushnumber(L, htonl(lua_tointeger(L, 1)));
	return 1;
}

static int l_maskbybit (lua_State *L) {
	if (!lua_isnumber(L, 1)) {
		lua_pushnil(L);
		lua_pushfstring(L, "invalid input type %s", lua_typename(L, lua_type(L, 1)));
		return 2;
	}
	unsigned int mask = htonl(0XFFFFFFFF<<(32-lua_tointeger(L, 1)));
	const unsigned char *addr = (unsigned char *)&mask;
	char buff[32] = {0};
	snprintf(buff, sizeof(buff), "%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3]);
	lua_pushfstring(L, "%s", buff); 
	return 1;
}



static int l_luser (lua_State *L) {
	if (!lua_isstring(L, 1)) {
		lua_pushnil(L);
		lua_pushfstring(L, "invalid input type %s", lua_typename(L, lua_type(L, 1)));
		return 2;
	}
	
	struct user_info_st *user = (struct user_info_st *)lua_tostring(L, 1);
	if (strlen(user->ssid) > 6) {
		lua_pushnil(L);
		lua_pushfstring(L, "invalid ssid\n");
		return 2;
	}
	
	char mac[32] = {0}, ip[32] = {0};
	unsigned char *addr = (unsigned char *)user->mac;
	snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
	addr = (unsigned char *)&user->ip;
	snprintf(ip, sizeof(ip), "%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3]);
	
	lua_newtable(L); 
	lua_pushnumber(L, user->idx);			lua_setfield(L, -2, "Idx");
	lua_pushnumber(L, user->jf);			lua_setfield(L, -2, "Jf");
	lua_pushfstring(L, "%s", mac);			lua_setfield(L, -2, "Mac");
	lua_pushfstring(L, "%s", ip);			lua_setfield(L, -2, "Ip"); 
	lua_pushfstring(L, "%s", user->ssid);	lua_setfield(L, -2, "Ssid"); 
	return 1;
}

static int l_cuser (lua_State *L) {
	unsigned char addr[6];
	struct user_info_st user;
	int index = 1, len;
	const char *field = "input", *ssid;
	if (!lua_istable(L, 1))
		goto invalid;
	
	index = 2;	
	memset(&user, 0, sizeof(user));
	field = "Idx"; lua_getfield(L, -1, field);
	if (!lua_isnumber(L, 2))
		goto invalid;
	user.idx = lua_tointeger(L, 2); lua_pop(L, 1);
	 
	field = "Jf"; lua_getfield(L, -1, field);
	if (!lua_isnumber(L, 2)) 
		goto invalid;
	user.jf = lua_tointeger(L, 2); lua_pop(L, 1);
	
	field = "Ssid"; lua_getfield(L, -1, field);
	if (!lua_isstring(L, 2)) 
		goto invalid;
	ssid = lua_tostring(L, 2); len = strlen(ssid);	lua_pop(L, 1);
	if (len > 6) {
		lua_pushnil(L);
		lua_pushfstring(L, "invalid ssid %s", ssid);
		return 2;
	} 
	strncpy(user.ssid, ssid, len);
	
	field = "Mac"; lua_getfield(L, -1, field);
	if (!lua_isstring(L, 2))
		goto invalid; 
	if (!macbin(lua_tostring(L, 2), addr))
		goto invalid;
	memcpy(user.mac, addr, 6); 	lua_pop(L, 1);
	
	field = "Ip"; lua_getfield(L, -1, field);
	if (!lua_isstring(L, 2)) 
		goto invalid;
	if (!ipbin(lua_tostring(L, 2), addr))
		goto invalid;
	memcpy(&user.ip, addr, 4); 	lua_pop(L, 1);
	
	lua_pushlstring(L, (char *)&user, sizeof(user));
	return 1;
invalid:
	lua_pushnil(L);
	lua_pushfstring(L, "invalid %s type %s", field, lua_typename(L, lua_type(L, 2)));
	return 2;
}

static int l_int2bin(lua_State *L) {
	if (!lua_isnumber(L, 1)) {
		lua_pushnil(L);
		lua_pushfstring(L, "invalid input type %s", lua_typename(L, lua_type(L, 1)));
		return 2;
	}
	unsigned long n = lua_tointeger(L, 1);
	char *addr = (char *)&n;
	lua_pushlstring(L, addr, 4);
	return 1;
}

static int l_bin2int(lua_State *L) {
	if (!lua_isstring(L, 1)) {
		lua_pushnil(L);
		lua_pushfstring(L, "invalid input type %s", lua_typename(L, lua_type(L, 1)));
		return 2;
	}
	const char *addr = lua_tostring(L, 1);
	lua_pushnumber(L, *(unsigned int *)addr);
	return 1;
}

void xxor(char *buff, int len) { 
	unsigned int e = 0X653DAA00 + len;
	char *pos = buff, *end = buff + len;
	for (; end > pos && end - pos >= 4; pos += 4)
		*(unsigned int *)pos ^= e;
}

static int l_xor(lua_State *L) {
	if (!lua_isstring(L, 1) || !lua_isnumber(L, 2)) {
		lua_pushnil(L);
		lua_pushfstring(L, "invalid input type %s %s", lua_typename(L, lua_type(L, 1)), lua_typename(L, lua_type(L, 2)));
		return 2;
	} 
	const char *addr = lua_tostring(L, 1);
	int len = lua_tointeger(L, 2);
	char *buff = (char *)malloc(len);
	if (!buff) {
		lua_pushnil(L);
		lua_pushfstring(L, "malloc fail");
		return 2;
	}
	memcpy(buff, addr, len);
	xxor(buff, len);
	lua_pushlstring(L, buff, len);
	lua_pushnumber(L, len);	
	free(buff);
	return 2;
}

static int l_syslog(lua_State *L) {
	if (!lua_isnumber(L, 1) || !lua_isstring(L, 2)) {
		lua_pushnil(L);
		lua_pushfstring(L, "invalid input type %s %s", lua_typename(L, lua_type(L, 1)), lua_typename(L, lua_type(L, 2)));
		return 2;
	}
	int level = lua_tointeger(L, 1);
	const char *addr = lua_tostring(L, 2);
	syslog(level, "%s", addr);
	return 0;
}
static const char *get_local_ip() {
	int sock;
	char *addr;
	struct sockaddr_in *sin;  
	struct ifreq ifr_ip;   
	
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		return NULL;
	
	memset(&ifr_ip, 0, sizeof(ifr_ip));     
	strncpy(ifr_ip.ifr_name, "br0", sizeof(ifr_ip.ifr_name) - 1);     
	if(ioctl(sock, SIOCGIFADDR, &ifr_ip) < 0) {
		close(sock);
		return NULL;
	}
	
	sin = (struct sockaddr_in *)&ifr_ip.ifr_addr;     
	addr = inet_ntoa(sin->sin_addr); 
	close(sock);
	return addr;
}

static int l_localbr0ip(lua_State *L) {
	const char *ip = get_local_ip();
	if (!ip) {
		lua_pushnil(L);
		lua_pushfstring(L, "get local br0 ip fail");
		return 2;
	}
	lua_pushfstring(L, "%s", ip);
	return 1;
}

static luaL_Reg reg[] = {
        { "monotonic", l_monotonic },
		{ "ipbin", l_ipbin },
		{ "ipstr", l_ipstr },
		{ "macstr", l_macstr },
		{ "macbin", l_macbin },
		{ "lshift", l_lshift },
		{ "htonl", l_htonl },
		{ "cuser", l_cuser },
		{ "luser", l_luser },
		{ "int2bin", l_int2bin },
		{ "bin2int", l_bin2int },
		{ "xor", l_xor },
		{ "syslog", l_syslog },
		{ "maskbybit", l_maskbybit },
		{ "localbr0ip", l_localbr0ip },
        { NULL, NULL }
    };
	
LUALIB_API int luaopen_basic(lua_State *L) {
	luaL_register(L, "basic", reg);
	return 1;
}


