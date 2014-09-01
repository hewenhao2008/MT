#include <typedefs.h>

#include <linux/module.h>
#include <linuxver.h>
#include <bcmdefs.h>
#include <osl.h>

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/delay.h>
#include <linux/string.h>

#include <linux/netfilter.h>
#include <linux/netfilter_bridge.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/netfilter_arp.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in_route.h>
#include <linux/inetdevice.h>
#include <linux/ppp_defs.h>
#include <linux/spinlock.h>

#include "auth_log.h"
#include "auth_cfg.h"
#include "ap_user.h"
#include "ap_verify.h"
#include "ap_3rd.h"

#define MAX_REDIRECT_HOST_SIZE 	(256) 
#define MAX_REDIRECT_PKT_SIZE 	(2048)

static struct auth_cfg_st s_auth_cfg; 
static int s_verify_readable = 0;
static int s_weixin_readable = 0;

static ssize_t auth_host_attr_show(struct module_attribute *mattr,	struct module *mod,	char *buf) {
	int ret = 0;
	
	mutex_lock(&s_auth_cfg.auth_cfg_mutex);
	auth_cfg_lock(&s_auth_cfg);
	
	ret = ap_host_fill_all(s_auth_cfg.ap, buf, 4096);
	
	auth_cfg_unlock(&s_auth_cfg);
	mutex_unlock(&s_auth_cfg.auth_cfg_mutex);

	return ret;
}

static ssize_t auth_host_attr_store(struct module_attribute *mattr, struct module *mod, 
	const char *buf, size_t count) 
{
	char cmd; 
	int i = 0, idx, hostlen, ret;
	const char *host; 
	
	ret = sscanf(buf, "%c %02d %02d", &cmd, &idx, &hostlen);
	if (ret != 3 || idx < 0 || idx >= s_auth_cfg.ap->maxid || hostlen >= MAC_HOST_LEN || (cmd != 'a' && cmd != 'd' && cmd != 'c')) {
		logerr("error host string %d %d %d %d %d %c | %s\n", ret, idx, s_auth_cfg.ap->maxid, hostlen, MAC_HOST_LEN, cmd, buf);
		return count;
	}
	
	host = buf + sizeof("a 01 12");
	for (i = 0; i < hostlen; i++) {
		if (host[i] <= ' ')
			break;
	}
	
	if (i != hostlen) {
		logerr("error line %d %d %s\n", i, hostlen, buf);
		return count;
	}
	
	mutex_lock(&s_auth_cfg.auth_cfg_mutex);
	auth_cfg_lock(&s_auth_cfg);
	
	if (cmd == 'a') 
		ret = ap_host_insert(s_auth_cfg.ap, idx, host, hostlen);
	else if (cmd == 'd')
		ret = ap_host_delete(s_auth_cfg.ap, idx, host, hostlen);
	else if (cmd == 'c')
		ret = ap_host_clear(s_auth_cfg.ap, idx);
	
	auth_cfg_unlock(&s_auth_cfg);
	mutex_unlock(&s_auth_cfg.auth_cfg_mutex);
	
	return count;
}

static ssize_t auth_online_attr_show(struct module_attribute *mattr,	struct module *mod,	char *buf) {
	int ret; 

	mutex_lock(&s_auth_cfg.auth_cfg_mutex);
	auth_cfg_lock(&s_auth_cfg);
	
	ret = ap_online_fill_all(s_auth_cfg.ap, buf + sizeof(ret), 4096 - sizeof(ret));
	memcpy(buf, &ret, sizeof(ret));
	
	auth_cfg_unlock(&s_auth_cfg);
	mutex_unlock(&s_auth_cfg.auth_cfg_mutex);

	return ret + sizeof(ret);
}

static ssize_t auth_online_attr_store(struct module_attribute *mattr, struct module *mod, 
	const char *buf, size_t count) 
{
	int len;
	int *idx; 
	struct ap_user user;
	const char *pos, *end, *cmd;
	 
	memcpy(&len, buf, sizeof(len));
	if (sizeof(len) + len != count) {
		logerr("auth_online_attr_store length not match %d %d\n", count, sizeof(len) + len);
		return count;
	}
	
	mutex_lock(&s_auth_cfg.auth_cfg_mutex);
	auth_cfg_lock(&s_auth_cfg);
	
	/* cmd idx ip jf mac */
	for (pos = buf + sizeof(len), end = buf + count; pos < end && end - pos >= AP_USER_SIZE + 1 + sizeof(int);) {
		cmd = pos;								pos += 1;
		idx = (int *)pos;						pos += sizeof(int); 
		memcpy(&user.ip, pos, AP_USER_SIZE);	pos += AP_USER_SIZE; 
		
		if ((*cmd != 'a' && *cmd != 'd') || *idx < 0 || *idx >= s_auth_cfg.ap->maxid) {
			const unsigned char *mac = user.mac;
			logerr("error cmd %c %d %02x-%02x-%02x-%02x-%02x-%02x\n", *cmd, *idx, mac[0], mac[1], mac[3], mac[3], mac[4], mac[5]);
			continue;
		}
		if (*cmd == 'a') {
			ap_online_insert(s_auth_cfg.ap, *idx, user.mac, user.ssid, user.ip); 
			continue;
		}
		ap_online_delete(s_auth_cfg.ap, *idx, user.mac);
	}
	
	if (end - pos != 0)
		logerr("error config %d %d %d\n", end - pos, len, count);
		
	auth_cfg_unlock(&s_auth_cfg);
	mutex_unlock(&s_auth_cfg.auth_cfg_mutex);
	
	return count;	
}

static ssize_t auth_verify_attr_show(struct module_attribute *mattr,	
	struct module *mod,	char *buf) 
{
	int ret;
	if (!s_verify_readable)
		return 0;
	mutex_lock(&s_auth_cfg.auth_cfg_mutex); 
	auth_cfg_lock(&s_auth_cfg);
	
	ret = ap_verify_fill_all(s_auth_cfg.ap, buf + sizeof(ret), 4096 - sizeof(ret));
	memcpy(buf, &ret, sizeof(ret));
	s_verify_readable = 0;
	auth_cfg_unlock(&s_auth_cfg);
	mutex_unlock(&s_auth_cfg.auth_cfg_mutex);
	
	return ret + sizeof(ret);
}

static ssize_t auth_verify_attr_store(struct module_attribute *mattr, struct module *mod, 
	const char *buf, size_t count) 
{
	logerr("not implement auth_verify_attr_store\n");
	return count;
}

static ssize_t auth_redirect_attr_show(struct module_attribute *mattr,	
	struct module *mod,	char *buf) 
{
	int ret; 
	
	mutex_lock(&s_auth_cfg.auth_cfg_mutex); 
	auth_cfg_lock(&s_auth_cfg);
	ret = ap_redirect_url_fill(s_auth_cfg.ap, buf, 4096);
	auth_cfg_unlock(&s_auth_cfg);
	mutex_unlock(&s_auth_cfg.auth_cfg_mutex);

	return ret;
}

#define AP_REDIRECT_READ_FMT 	"%02d %04d" 
static ssize_t auth_redirect_attr_store(struct module_attribute *mattr, struct module *mod, 
	const char *buf, size_t count) 
{
	int ret, idx, urllen;
	const char *url;
	
	ret = sscanf(buf, AP_REDIRECT_READ_FMT, &idx, &urllen);
	if (ret != 2 || idx < 0 || idx >= s_auth_cfg.ap->maxid || urllen < 0 || urllen >= MAC_REDIRECT_URL_SIZE) {
		logerr("error config %d %d %d %d %d | %s\n", ret, idx, s_auth_cfg.ap->maxid, urllen, MAC_REDIRECT_URL_SIZE, buf);
		return count;
	}
	
	url = buf + sizeof("01 0015"); 
	mutex_lock(&s_auth_cfg.auth_cfg_mutex); 
	auth_cfg_lock(&s_auth_cfg);
	
	ret = ap_redirect_url_set(s_auth_cfg.ap, idx, url, urllen);
	
	auth_cfg_unlock(&s_auth_cfg);
	mutex_unlock(&s_auth_cfg.auth_cfg_mutex);
	
	return count;
}

static ssize_t auth_account_attr_show(struct module_attribute *mattr,	
	struct module *mod,	char *buf) 
{
	int ret = 0; 

	mutex_lock(&s_auth_cfg.auth_cfg_mutex); 
	auth_cfg_lock(&s_auth_cfg);
	ret = ap_account_fill(s_auth_cfg.ap, buf, 4096);
	auth_cfg_unlock(&s_auth_cfg);
	mutex_unlock(&s_auth_cfg.auth_cfg_mutex);
	
	if (ret <= 0) 
		logerr("ap_account_fill fail %d\n", ret);
	
	return ret;
}

static ssize_t auth_account_attr_store(struct module_attribute *mattr, struct module *mod, 
	const char *buf, size_t count)  
{
	mutex_lock(&s_auth_cfg.auth_cfg_mutex); 
	auth_cfg_lock(&s_auth_cfg);
	if (ap_account_set(s_auth_cfg.ap, buf, count)) 
		logerr("ap_account_set fail\n");
	auth_cfg_unlock(&s_auth_cfg);
	mutex_unlock(&s_auth_cfg.auth_cfg_mutex);
	return count;
}

static ssize_t auth_apgroup_attr_show(struct module_attribute *mattr,	
	struct module *mod,	char *buf) 
{
	int ret; 
	
	mutex_lock(&s_auth_cfg.auth_cfg_mutex); 
	auth_cfg_lock(&s_auth_cfg);
	ret = ap_apgroup_fill(s_auth_cfg.ap, buf, 4096);
	auth_cfg_unlock(&s_auth_cfg);
	mutex_unlock(&s_auth_cfg.auth_cfg_mutex);
	
	if (ret <= 0) 
		logerr("ap_apgroup_fill fail %d\n", ret);
	
	return ret;
}

static ssize_t auth_apgroup_attr_store(struct module_attribute *mattr, struct module *mod, 
	const char *buf, size_t count)  
{
	mutex_lock(&s_auth_cfg.auth_cfg_mutex); 
	auth_cfg_lock(&s_auth_cfg);
	if (ap_apgroup_set(s_auth_cfg.ap, buf, count)) 
		logerr("ap_account_set fail\n");
	auth_cfg_unlock(&s_auth_cfg);
	mutex_unlock(&s_auth_cfg.auth_cfg_mutex);
	return count;
}

static ssize_t auth_through_attr_show(struct module_attribute *mattr,	
	struct module *mod,	char *buf) 
{
	logerr("not implement %s %d\n", __FUNCTION__, __LINE__);
	return 0;
}

static ssize_t auth_though_attr_store(struct module_attribute *mattr, struct module *mod, 
	const char *buf, size_t count)  
{
	mutex_lock(&s_auth_cfg.auth_cfg_mutex); 
	auth_cfg_lock(&s_auth_cfg);
	
	if (count != 4) 
		logerr("invalid ip size %d\n", count);
	else 
		ap_3rd_set_through(s_auth_cfg.ap3rd, *(unsigned int *)buf);
	
	auth_cfg_unlock(&s_auth_cfg);
	mutex_unlock(&s_auth_cfg.auth_cfg_mutex);
	return count;
}

static ssize_t auth_weixin_attr_show(struct module_attribute *mattr,	
	struct module *mod,	char *buf) 
{
	int ret;
	if (!s_weixin_readable)
		return 0;
	mutex_lock(&s_auth_cfg.auth_cfg_mutex); 
	auth_cfg_lock(&s_auth_cfg);
	
	ret = ap_3rd_weixin_login_fill(s_auth_cfg.ap3rd, buf + sizeof(ret), 4096 - sizeof(ret)); 
	memcpy(buf, &ret, sizeof(ret));
	//logdbg("---------weixin len %d\n", ret);
	auth_cfg_unlock(&s_auth_cfg);
	mutex_unlock(&s_auth_cfg.auth_cfg_mutex);
	s_weixin_readable = 0;
	return ret + sizeof(ret);
}

static ssize_t auth_weixin_attr_store(struct module_attribute *mattr, struct module *mod, 
	const char *buf, size_t count)  
{
	logerr("not implement %s %d\n", __FUNCTION__, __LINE__);
	return count;
}

static ssize_t auth_ac_host_attr_show(struct module_attribute *mattr,	
	struct module *mod,	char *buf)  
{
	int ret; 
	
	mutex_lock(&s_auth_cfg.auth_cfg_mutex); 
	auth_cfg_lock(&s_auth_cfg);
	ret = ac_host_fill(s_auth_cfg.ap, buf, 4096);
	auth_cfg_unlock(&s_auth_cfg);
	mutex_unlock(&s_auth_cfg.auth_cfg_mutex);
	
	if (ret <= 0) 
		logerr("ac_host_fill fail %d\n", ret);
	
	return ret;
}	
static ssize_t auth_ac_host_attr_store(struct module_attribute *mattr, struct module *mod, 
	const char *buf, size_t count)  
{
	mutex_lock(&s_auth_cfg.auth_cfg_mutex); 
	auth_cfg_lock(&s_auth_cfg);
	if (ac_host_set(s_auth_cfg.ap, buf, count)) 
		logerr("ac_host_set fail\n");
	auth_cfg_unlock(&s_auth_cfg);
	mutex_unlock(&s_auth_cfg.auth_cfg_mutex);
	return count;
}

static ssize_t auth_bypass_attr_show(struct module_attribute *mattr,	
	struct module *mod,	char *buf)  
{
	mutex_lock(&s_auth_cfg.auth_cfg_mutex); 
	auth_cfg_lock(&s_auth_cfg);
	
	*(int *)buf = auth_cfg_bypass(&s_auth_cfg);
	
	auth_cfg_unlock(&s_auth_cfg);
	mutex_unlock(&s_auth_cfg.auth_cfg_mutex); 
	buf[4] = 0;
	logdbg("bypass : %d\n", *(int *)buf);
	return 4;
}	
static ssize_t auth_bypass_attr_store(struct module_attribute *mattr, struct module *mod, 
	const char *buf, size_t count)  
{
	int bypass;
	if (count != 4) {
		logerr("auth_bypass_attr_store coutn not 4\n");
		return count;
	}
	mutex_lock(&s_auth_cfg.auth_cfg_mutex); 
	auth_cfg_lock(&s_auth_cfg);
	bypass = *(int *)buf;
	if (bypass != 0 && bypass != 1) 
		logerr("bypass value invalid %d\n", bypass);
	else 
		auth_cfg_set_bypass(&s_auth_cfg, bypass);
	auth_cfg_unlock(&s_auth_cfg);
	mutex_unlock(&s_auth_cfg.auth_cfg_mutex);
	return count;
}
struct attri_item {
	struct module_attribute item;
	int init;
};

static struct attri_item s_attri_item[] = {
	{__ATTR(pass_host, 0644, auth_host_attr_show, auth_host_attr_store), 0},
	{__ATTR(online, 0644, auth_online_attr_show, auth_online_attr_store), 0},
	{__ATTR(redirect, 0644, auth_redirect_attr_show, auth_redirect_attr_store), 0},
	{__ATTR(verify, 0644, auth_verify_attr_show, auth_verify_attr_store), 0},
	{__ATTR(account, 0644, auth_account_attr_show, auth_account_attr_store), 0},
	{__ATTR(ip_through, 0644, auth_through_attr_show, auth_though_attr_store), 0},
	{__ATTR(weixin_login, 0644, auth_weixin_attr_show, auth_weixin_attr_store), 0},
	{__ATTR(bypass, 0644, auth_bypass_attr_show, auth_bypass_attr_store), 0},
	{__ATTR(ac_host, 0644, auth_ac_host_attr_show, auth_ac_host_attr_store), 0},
	{__ATTR(apgroup, 0644, auth_apgroup_attr_show, auth_apgroup_attr_store), 0}
};

struct auth_cfg_st *auth_cfg_create(void) {
	int ret, i;
	
	mutex_init(&s_auth_cfg.auth_cfg_mutex);
	spin_lock_init(&s_auth_cfg.lock);

	s_auth_cfg.bypass = 1;
	s_auth_cfg.ap = ap_create();
	s_auth_cfg.ap3rd = ap_3rd_create();
	for (i = 0; i < sizeof(s_attri_item) / sizeof(struct attri_item); i++) {
		ret = sysfs_create_file(&THIS_MODULE->mkobj.kobj, &s_attri_item[i].item.attr); 
		if (ret) {
			logerr("sysfs_create_file %d fail\n", i);
			goto error_flag;
		}
		s_attri_item[i].init = 1;
	}
	return &s_auth_cfg;
error_flag:
	for (i = 0; i < sizeof(s_attri_item) / sizeof(struct attri_item); i++) {
		if (s_attri_item[i].init) {
			sysfs_remove_file(&THIS_MODULE->mkobj.kobj, &s_attri_item[i].item.attr);   
			s_attri_item[i].init = 0;
		}
	}
	ap_destroy(s_auth_cfg.ap);
	mutex_destroy(&s_auth_cfg.auth_cfg_mutex);
	return NULL; 
}

void auth_cfg_destroy(struct auth_cfg_st *acfg) {
	int i;
	for (i = 0; i < sizeof(s_attri_item) / sizeof(struct attri_item); i++) {
		if (s_attri_item[i].init) {
			sysfs_remove_file(&THIS_MODULE->mkobj.kobj, &s_attri_item[i].item.attr);   
			s_attri_item[i].init = 0;
		}
	}
	ap_destroy(acfg->ap);
	ap_3rd_destroy(acfg->ap3rd);
	mutex_destroy(acfg->auth_cfg_mutex);
}

const char *auth_cfg_account(struct auth_cfg_st *acfg) {
	return acfg->ap->ap_account;
}

const char *auth_cfg_ac_host(struct auth_cfg_st *acfg) {
	return acfg->ap->ac_host;
}

int auth_cfg_bypass(struct auth_cfg_st *acfg) {
	return acfg->bypass;
}

int auth_cfg_set_bypass(struct auth_cfg_st *acfg, int bypass) {
	if (acfg->bypass != bypass)
		logdbg("set bypass from %d to %d\n", acfg->bypass, bypass);
	acfg->bypass = bypass;
	return 0;
}

void auth_cfg_lock(struct auth_cfg_st *acfg) {
	spin_lock_bh(&acfg->lock);
}

void auth_cfg_unlock(struct auth_cfg_st *acfg) {
	spin_unlock_bh(&acfg->lock);
}

void auth_cfg_weixin_readable() {
	s_weixin_readable = 1;
	//logdbg("auth_cfg_weixin_readable-----------------\n");
}

void auth_cfg_verify_readable() {
	s_verify_readable = 1;
	//logdbg("auth_cfg_verify_readable-----------------\n");
}