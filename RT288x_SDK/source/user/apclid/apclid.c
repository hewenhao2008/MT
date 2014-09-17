#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <syslog.h>
#include <ctype.h>

#include "apclid.h"
#include "conn.h"
#include "api.h"

static char sys_buff[4096];

struct nv_node_t {
	char key[NVRAM_BUFSIZE];
	char val[NVRAM_BUFSIZE];
};

static struct nv_node_t conv_tab[] = {
	{"wl_channel", "Channel"},
	{"lan_ipaddr", "dhcpEnabled"},
};

char * nvram_trim(char *v)
{
	int i=0;
	while(v && v[i]!='\0'){
		if(v[i]==' ' || v[i]=='\r' || v[i]=='\n') {
			if(v[i+1]=='\r' || v[i+1]=='\n') {
				v[i]='\0';
				break;
			}
			v[i] = v[i+1];
		}
		i++;
	}
	return v;
}

char *pipe_get_mac(char *ifname)
{
	char buff[NVRAM_BUFSIZE];
	snprintf(buff, sizeof(buff), "ip link show dev %s | grep ether | awk '{print $2}'", ifname);
	return nvram_trim(pipe_get("%s", buff, sys_buff, sizeof(sys_buff), 0))?:"00:00:00:00:00:00";
}

unsigned int ap_chap = 0;
void init_ap_chap(void)
{
	char *mac = pipe_get_mac("eth2");
	if (strlen(mac)<17) {
		APLOG(LOG_ERR, "can't read link mac addr\n");
		return;
	}

	if(ap_chap!=0){
		return;
	}

	unsigned int a1,a2,a3,a4,a5,a6;
	sscanf(mac, "%02x:%02x:%02x:%02x:%02x:%02x", &a1, &a2, &a3, &a4, &a5, &a6);
	ap_chap = a1 ^ (a2 << 8) ^ (a3<<16) ^ (a4 <<24) ^ (a5 << 8) ^ (a6 << 16);
	APLOG(LOG_INFO, "ap[%s] cli chap: %x\n", mac, ap_chap);
}

//private
static int cb_nvrame_set(char *key, char *val, void *par)
{
	int ret, offset;
	char *p = (char*)par;

	if (key == NULL || val == NULL)
		return 0;

	//do someting...
	if (strlen(val) >= 250) {
		APLOG(LOG_ERR, "set [%s=%s] failed too long.\n", key, val);
		return 0;
	}

	ret = nvram_ra_set(key, val);
	if(ret) {
		APLOG(LOG_ERR, "set nvram[%s:%s] failed. %d\n", key, val, ret);
		return ret;
	}

	APLOG(LOG_INFO, "set %s %s\n", key, val);

	offset = strlen(p);
	ret = snprintf(p + offset, MAX_NVRAM_SIZE - offset, "%s=%s\n", key, val);
	if(ret < 0) {
		APLOG(LOG_ERR, "%s: snprintf failed. %d\n", __FUNCTION__, ret);
		return ret;
	}

	return 0;
}

static int cb_nvrame_list(char *key, char *val, void *par)
{
	int ret, offset;
	char *p = (char*)par;
	char buff[NVRAM_BUFSIZE];

	if(key == NULL || strlen(key)<1){
		return 0;
	}
	strncpy(buff, nvram_ra_get(key), NVRAM_BUFSIZE);

	offset = strlen(p);
	ret = snprintf(p + offset, MAX_NVRAM_SIZE - offset, "%s=%s\n", key, buff);
	if(ret < 0) {
		APLOG(LOG_ERR, "%s: snprintf failed %d\n", __FUNCTION__, ret);
	}

	return ret;
}

static int cb_nvram_unset(char *key, char *val, void *par)
{
	//do somting
	return nvram_ra_unset(key);
}

int on_get_mac(sstr_t *rep)
{
	extern sstr_t str_ac_addr;
	char *addr = str_ac_addr.data ?: nvram_ra_get("ac_ipaddr");
	//set ac connected flags for led blink
	nvram_ra_set("ac_connected", addr);

	//这里chap不能开启, 否则服务器端收不到MAC地址
	ap_chap = 0;
	APLOG(LOG_INFO, "connect to ac[%s]\n", addr);

	char buff[256];
	snprintf(buff, sizeof(buff), "%s %s", 
		pipe_get_mac("eth2"), nvram_ra_get("cloud_account"));

	*rep = sstr_copy_cstr(buff);
	return 0;
}

int on_set_ip(sstr_t request, sstr_t *rep)
{
	APLOG(LOG_INFO, "set ip: [%.*s]\n", (int)request.size, request.data);
	*rep = sstr_copy_cstr("OK");
	return 0;
}

int on_get_user_addrs(sstr_t *rep)
{
	*rep = sstr_move_cstr(api_get_user_addrs(NULL));
	return 0;
}

int on_get_basic(sstr_t *rep)
{
	//连接AC成功, 回显当前AC地址.
	int c = 0;
	extern sstr_t str_ac_addr;
	char *ac_addr = str_ac_addr.data ? str_ac_addr.data : "x.x.x.x";

	//format results.
	*rep = sstr_fmt(
		"ipaddr=%s\n"
		"nick_name=%s\n"
		"os_version=%s\n"
		"lan_dhcp=%s\n"
		"lan_ipaddr=%s\n"
		"lan_netmask=%s\n"
		"lan_gateway=%s\n"
		"ac_current=%s\n"
		"wl0_channel=%s\n"
		"wl0_noise=%s\n"
		"auth_count=%s\n"
		"assoc_num=%s\n"
		"wl0_txpwr_cur=%s\n",
		pipe_get("%s", "ip addr show dev br0 | grep inet | awk '{print $2}'", sys_buff, sizeof(sys_buff), 0), 
		nvram_ra_get("nick_name"),
		nvram_ra_get("os_version"),
		nvram_ra_get("lan_dhcp"),
		nvram_ra_get("lan_ipaddr"),
		nvram_ra_get("lan_netmask"),
		nvram_ra_get("lan_gateway"),
		ac_addr,
		pipe_get("%s", "wlconf ra0 ugw info,channel", sys_buff+(24*c++), 24, 0), 
		pipe_get("%s", "wlconf ra0 ugw info,noise", sys_buff+(24*c++), 24, 0),
		pipe_get("%s", "wlconf ra0 ugw info,conn", sys_buff+(24*c++), 24, 0), 
		pipe_get("%s", "wlconf ra0 ugw info,assoc", sys_buff+(24*c++), 24, 0),
		pipe_get("%s", "wlconf ra0 ugw info,txpower", sys_buff+(24*c++), 24, 0));

	//free mem
	APLOG(LOG_INFO, "basic %s\n", rep->data);
	return 0;
}

int do_nvram_parse(char *start, int size, int callback(char *k, char *v, void *par), void *cb_par)
{
	int res = 0;
	int line = 0;
	char val[128], key[32];
	char *field_start=start, *div_kv=NULL, *field_end=NULL, *next = NULL;

	while(field_start != NULL && ((field_start - start) < size))
	{
		memset(key, 0, sizeof(key));
		memset(val, 0, sizeof(val));
		next = strchr(field_start, '\n');
		div_kv = strchr(field_start, '=');
		//APLOG(LOG_ERR, "field_start[%p], div_kv[%p], next[%p]\n", field_start, div_kv, next);
		if (next==NULL) {
			field_end = field_start + size;
		} else {
			field_end = next;
		}
		if (div_kv && div_kv < next) {
			/* 
			*	aa=xx\nbb=yy\n...
			*	div_kv: '=xxxxx'; 
			*/
			memcpy(key, field_start, div_kv - field_start);
			memcpy(val, div_kv + 1, field_end - div_kv - 1);
			res = callback(key, val, cb_par);
		} else if(field_start < field_end){
			/*
			*	aa\nbb\ncc\n...
			*/
			memcpy(key, field_start, field_end - field_start);
			res = callback(key, NULL, cb_par);
		}
		if (res < 0) {//error
			APLOG(LOG_ERR, "parse line[%d] [%s]->[%s], cb: %d\n", line ++, key, val, res);
			break;
		}
		//field_end
		if (!next)
			break;
		else
			field_start = next + 1;
	}

	return res;
}

int do_nvram_lst(sstr_t req, sstr_t *rep)
{
	char *buff = NULL;

	if (req.size < 4) {
		APLOG(LOG_ERR, "%s: req data too short %d.\n", __FUNCTION__, req.size);
		*rep = sstr_fmt("req data too short: %d\n", req.size);
		return 102;
	}

	buff = malloc(MAX_NVRAM_SIZE);
	if(!buff) {
		APLOG(LOG_ERR, "%s: malloc failed %d\n", __FUNCTION__, MAX_NVRAM_SIZE);
		*rep = sstr_fmt("malloc %d for %s failed.", MAX_NVRAM_SIZE, __FUNCTION__);
		return 101;
	}
	memset(buff, 0, MAX_NVRAM_SIZE);

	do_nvram_parse(req.data + 4, req.size - 4, cb_nvrame_list, buff);
	*rep = sstr_move_cstr(buff);
	return 0;
}
int do_nvram_set(sstr_t req, sstr_t *rep)
{
	char *buff = NULL;

	if (req.size < 4) {
		APLOG(LOG_ERR, "%s: req data too short %d.\n", __FUNCTION__, req.size);
		*rep = sstr_fmt("req data too short: %d\n", req.size);
		return 102;
	}

	buff = malloc(MAX_NVRAM_SIZE);
	if(!buff) {
		APLOG(LOG_ERR, "%s: malloc failed %d\n", __FUNCTION__, MAX_NVRAM_SIZE);
		*rep = sstr_fmt("malloc %d for %s failed.", MAX_NVRAM_SIZE, __FUNCTION__);
		return 101;
	}
	memset(buff, 0, MAX_NVRAM_SIZE);

	do_nvram_parse(req.data + 4, req.size - 4, cb_nvrame_set, buff);
	nvram_ra_commit();

	*rep = sstr_move_cstr(buff);
	return 0;
}
int do_nvram_all(sstr_t *rep)
{
	int i;
	char *buff = NULL;

	buff = malloc(MAX_NVRAM_SIZE); //32k
	if (!buff)
	{
		APLOG(LOG_ERR, "malloc 32k failed %s\n", __FUNCTION__);
		*rep = sstr_copy_cstr("malloc failed.");
		return 101;
	}

	nvram_ra_getall(buff, MAX_NVRAM_SIZE);

	i = 0;
	while(i<MAX_NVRAM_SIZE){
		if (buff[i]=='\0')
		{
			if(buff[i+1] == '\0')
				break;
			//replace
			buff[i] = '\n';
		}
		i++;
	}

	//APLOG(LOG_ERR, "all nvram: [%s]\n", buff);
	*rep = sstr_move_cstr(buff);
	return 0;
}
#undef MAX_NVRAM_SIZE

int on_unset_nvram(sstr_t req, sstr_t *rep)
{
	do_nvram_parse(req.data, req.size, cb_nvram_unset, NULL);
	return do_nvram_all(rep);
}

int on_set_nvram(sstr_t req, sstr_t *rep)
{
	if(memcmp("set", req.data, 3) == 0) {
		return do_nvram_set(req, rep);
	}else if(memcmp("lst", req.data, 3) == 0) {
		return do_nvram_lst(req, rep);
	}else {
		return do_nvram_all(rep);
	}
}

int on_set_auth_user_list(sstr_t req, sstr_t *rep)
{
	char *ifname = req.data;
	
	//APLOG(LOG_DEBUG, "on get the ulist of iface[%s]\n", ifname);
	*rep = sstr_move_cstr(api_get_wl_auth_list(ifname));
	return 0;
}

int on_set_auth_user_info(sstr_t req, sstr_t *rep)
{
	/* 解析出wl网口名和用户的mac地址 */
	char *mac = req.data;
	char *ifname = strchr(req.data, ' ');
	if(ifname){
		ifname += 1; //offset
	}

	//APLOG(LOG_DEBUG, "on set uinfo[%s]\n", mac);
	*rep =  sstr_move_cstr(api_get_wl_auth_info(ifname, mac));
	return 0;
}

int on_set_exec_cmds(sstr_t req, sstr_t *rep)
{
	char *par = req.data;

	APLOG(LOG_DEBUG, "exec [%s]\n", par);
	*rep = sstr_move_cstr(api_set_exec_cmds(par));
	return 0;
}

int on_set_upgrade(sstr_t req, sstr_t *rep)
{
	char *par = req.data;

	APLOG(LOG_DEBUG, "upgrade with par %s\n", par);
	*rep = sstr_move_cstr(api_set_upgrade(par));
	return 0;
}

int on_set_fetch(sstr_t req, sstr_t *rep)
{
	int pos = 0;
	char *fname = req.data;
	char *post_fetch = NULL;

	while(fname[pos]!='\0' && pos < req.size){
		if (fname[pos]==' ') {
			fname[pos] = '\0'; //set end of str.
			if (pos + 1 < req.size) {
				//has cmds
				post_fetch = fname + pos + 1;
				break;
			}
		}
		pos ++;
	}

	//APLOG(LOG_DEBUG, "fetch file: %s cmds:%s\n", fname, (post_fetch ? post_fetch : "none"));
	*rep = sstr_move_cstr(api_set_fetch(fname, post_fetch));
	return 0;
}

void init_handlers(void)
{
	register_request_get_handler("mac", on_get_mac);
	register_request_get_handler("basic", on_get_basic);
	register_request_get_handler("user_addrs", on_get_user_addrs);

	register_request_set_handler("ip", on_set_ip);
	register_request_set_handler("nvram", on_set_nvram);
	register_request_set_handler("unset", on_unset_nvram);
	register_request_set_handler("user_list", on_set_auth_user_list);
	register_request_set_handler("user_info", on_set_auth_user_info);
	register_request_set_handler("exec_cmds", on_set_exec_cmds);
	register_request_set_handler("upgrade", on_set_upgrade);
	register_request_set_handler("fetch", on_set_fetch);
}