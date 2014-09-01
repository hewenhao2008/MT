#include <linux/list.h> 
#include <linux/slab.h> 
#include <linux/spinlock.h>
#include <linux/module.h> 
#include <linux/sched.h>

#include "ap_user.h"
#include "ap_verify.h"
#include "auth_log.h"
#include "auth_cfg.h"

static struct ap_st s_ap; 

static int ap_user_hash_init(struct ap_st *ap, int idx);
static void ap_user_hash_finit(struct ap_st *ap, int idx);
static int online_user_fill(struct ap_user_hash *uh, char *buf, int buflen);

int get_idx(const char *in) {
	int idx;
	
	if (*in == 'e')
		return 0;
		
	idx = in[4] - '0';
	if (idx >= AP_SSID_COUNT) {
		idx = 0;
		logerr("error ssid %d %s\n", idx, in);
	}
	
	return idx;
}

static inline struct ap_user_hash *ap_get_user_hash(struct ap_st *ap, const char *in) { 
	int idx = get_idx(in);
	return &ap->ap_users[idx]; 
}

struct ap_st *ap_create(void) {
	int i;

	memset(&s_ap, 0, sizeof(s_ap));
	memcpy(s_ap.ap_account, "default_account", strlen("default_account"));
	memcpy(s_ap.ac_host, "default_host", strlen("default_host"));
	
	s_ap.maxid = AP_SSID_COUNT;
	for (i = 0; i < AP_SSID_COUNT; i++) {
		if (ap_user_hash_init(&s_ap, i))
			goto error_flag;
	}
	
	return &s_ap;
error_flag:
	for (i = 0; i < AP_SSID_COUNT; i++) 
		ap_user_hash_finit(&s_ap, i);
	
	return NULL;
}

void ap_destroy(struct ap_st *ap) {
	int i;
	for (i = 0; i < AP_SSID_COUNT; i++) 
		ap_user_hash_finit(ap, i);
}

static int ap_user_hash_init(struct ap_st *ap, int idx)
{
	int j; 
	struct ap_user_hash *uh = &ap->ap_users[idx];
	
	for (j = 0; j <= AP_USER_HASH_MASK; j++) {
		INIT_HLIST_HEAD(&uh->slots[j]);
		INIT_HLIST_HEAD(&uh->pass_host);
	}
	
	uh->verify_buff = verify_buff_create();
	ap->ap_users[idx].idx = idx;

	return 0;
}

static void ap_user_hash_finit(struct ap_st *ap, int idx) {
	int i;
	struct ap_host *host;
	struct ap_user *user;
	struct hlist_node *node, *n;
	struct ap_user_hash *uh = &ap->ap_users[idx];
	
	hlist_for_each_entry_safe(host, node, n, &uh->pass_host, hnode) {
		hlist_del(&host->hnode);
		kfree(host);
	} 
	
	for (i = 0; i <= AP_USER_HASH_MASK; i++) {
		hlist_for_each_entry_safe(user, node, n, &uh->slots[i], hnode) {
			hlist_del(&user->hnode);
			kfree(user);
		}
	}
	
	verify_buff_destroy(uh->verify_buff);
}

struct ap_host *host_find(struct ap_user_hash *uh, const char *h, int hostlen) 
{
	struct ap_host *host;
	struct hlist_node *node;
	struct hlist_head *head; 
	
	head = &uh->pass_host;
	hlist_for_each_entry(host, node, head, hnode) {
		if (memcmp(h, host->host, hostlen) == 0) 
			return host; 
	}
	
	return NULL;
}
int ap_host_find(struct ap_st *ap, const char *in, const char *host, int hostlen) 
{
	return host_find(ap_get_user_hash(ap, in), host, hostlen) != NULL;
}

static int host_insert(struct ap_user_hash *uh, const char *h, int hostlen) {
	struct ap_host *host, *tmp; 
	
	if (hostlen >= MAC_HOST_LEN - 1) {
		logerr("host too long %d %d\n", hostlen, MAC_HOST_LEN - 1);
		return -1;
	}
	
	host = host_find(uh, h, hostlen);
	if (host) {
		logdbg("host %d %s %d exist!\n", uh->idx, h, hostlen);
		return 1;
	}
	
	tmp = kmalloc(sizeof(struct ap_host), GFP_NOWAIT);
	if (tmp == NULL) {
		logerr("kmalloc fail\n");
		return -1;
	}
	
	strncpy(tmp->host, h, hostlen);
	tmp->host[hostlen] = 0;
	hlist_add_head(&tmp->hnode, &uh->pass_host); 
	
	return 0;
}

int ap_host_insert(struct ap_st *ap, int idx, const char *host, int hostlen) {
	if (idx < 0 || idx >= ap->maxid) {
		logerr("error index %d %d\n", idx, ap->maxid);
		return -1;
	}
		
	return host_insert(&ap->ap_users[idx], host, hostlen);
}

int ap_host_clear(struct ap_st *ap, int idx) {
	struct ap_host *host;
	struct hlist_node *node, *n;
	struct ap_user_hash *uh = &ap->ap_users[idx];
	
	hlist_for_each_entry_safe(host, node, n, &uh->pass_host, hnode) {  
		hlist_del(&host->hnode);
		kfree(host);
	}
	
	return 0;
}

int ap_host_delete(struct ap_st *ap, int idx, const char *h, int hostlen) {
	struct ap_host *host;
	struct ap_user_hash *uh ;

	if (idx < 0 || idx >= ap->maxid)
		return -1;
	
	uh = &ap->ap_users[idx];
	host = host_find(uh, h, hostlen);
	if (host) {
		logdbg("delete host %d %s %d\n", idx, host->host, hostlen);
		hlist_del(&host->hnode);
		kfree(host);
		return 0;
	}
	
	return 1;
}

static inline int set_redirect_url(struct ap_st *ap, int idx, const char *url, int urllen) {
	struct ap_user_hash *uh = &ap->ap_users[idx];
	if (urllen >= MAC_REDIRECT_URL_SIZE - 1)
		return -1;
		
	strncpy(uh->url, url, urllen);
	uh->url[urllen] = 0;
	uh->urllen = urllen;
	
	return 0;
}

static uint32_t ap_user_mac_hash(const unsigned char *mac)
{
	int i;
	uint32_t hash = 0; 

	for (i = 0; i < 6; i++) {
		hash += hash * 33 + mac[i];
	}

	return hash;
}

static struct ap_user *ap_user_hash_lookup(struct ap_user_hash *uh, const unsigned char *mac) 
{
	struct ap_user *user;
	struct hlist_node *node;
	struct hlist_head *slot;
	
	slot = &uh->slots[ap_user_mac_hash(mac) & AP_USER_HASH_MASK]; 
	hlist_for_each_entry(user, node, slot, hnode) {
		if (memcmp(mac, user->mac, sizeof(user->mac)) == 0)
			return user;
	}
	
	return NULL;
}

static inline struct ap_user *ap_user_lookup(struct ap_st *ap, const char *in, const unsigned char *mac, char status) 
{
	struct ap_user *user; 
	struct ap_user_hash *uh = ap_get_user_hash(ap, in);
	if (!uh)
		return NULL;
	
	user = ap_user_hash_lookup(uh, mac); 
	if (!user || user->status != status)
		return NULL;
		
	user->jf = jiffies;
	return user;
}

static inline void set_source_ip(struct ap_user *user, unsigned int sip) {
	if (!user || user->ip == sip)
		return;
		
	if (sip == 0) {
		logerr("ERROR why source ip is 0.0.0.0\n");
		return;
	}
	{
	//unsigned char *old = (unsigned char *)&user->ip;
	//unsigned char *new = (unsigned char *)&sip;
	//logdbg("1 user ip changed from %d.%d.%d.%d to %d.%d.%d.%d\n", old[0], old[1], old[2], old[3], new[0], new[1], new[2], new[3]); 
	}
	user->ip = sip;
}

struct ap_user *ap_online_lookup(struct ap_st *ap, const char *in, const unsigned char *mac, unsigned int sip)
{
	struct ap_user *user = ap_user_lookup(ap, in, mac, 'w');
	set_source_ip(user, sip);
	return user;
}

struct ap_user *ap_verify_lookup(struct ap_st *ap, const char *in, const unsigned char *mac, unsigned int sip)
{
	struct ap_user *user = ap_user_lookup(ap, in, mac, 'v');
	set_source_ip(user, sip);
	return user;
}

static struct ap_user *ap_user_insert(struct ap_user_hash *uh, const unsigned char *mac, const char *ssid, unsigned int ip)  
{
	struct ap_user *user; 
	struct hlist_node *node;
	struct hlist_head *slot; 
	 
	slot = &uh->slots[ap_user_mac_hash(mac) & AP_USER_HASH_MASK];
	
	hlist_for_each_entry(user, node, slot, hnode) {
		if (!memcmp(mac, user->mac, sizeof(user->mac))) 
			return user; 	
	}

	user = kmalloc(sizeof(struct ap_user), GFP_NOWAIT);
	if (!user) {
		logerr("kmalloc fail\n"); 
		return NULL;
	}

	memset(user, 0, sizeof(struct ap_user));
	memcpy(user->mac, mac, 6); 
	memcpy(user->ssid, ssid, 6);
	user->status = 'n';
	user->ip = ip;
	user->jf = jiffies;
	hlist_add_head(&user->hnode, slot); 
	
	return user;
}

struct ap_user *ap_online_insert_by_ssid(struct ap_st *ap, const unsigned char *mac, const char *ssid, unsigned int ip) 
{
	return ap_online_insert(ap, get_idx(ssid), mac, ssid, ip);
}

struct ap_user *ap_online_insert(struct ap_st *ap, int idx, const unsigned char *mac, const char *ssid, unsigned int ip)
{
	struct ap_user *user;
	struct ap_user_hash *uh;
	unsigned char *addr = (unsigned char *)&ip;
	
	uh = &ap->ap_users[idx];
	user = ap_user_insert(uh, mac, ssid, ip); 
	if (!user)
		return NULL;
		
	if (user->status == 'n') 
		logdbg("insert online user %02d %02x-%02x-%02x-%02x-%02x-%02x %d.%d.%d.%d %s ok\n", uh->idx, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], addr[0], addr[1], addr[2], addr[3], ssid);
	else 
		logdbg("already exist online user %c %02d %02x-%02x-%02x-%02x-%02x-%02x %d.%d.%d.%d %s ok\n", user->status, uh->idx, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], addr[0], addr[1], addr[2], addr[3], ssid);
	
	user->status = 'w';
	user->jf = jiffies;
	
	return user;
}

struct ap_user *ap_verify_insert(struct ap_st *ap, const char *in, const unsigned char *mac, const char *ssid, unsigned int ip) 
{
	struct ap_user *user;
	struct ap_user_hash *uh;
	
	uh = ap_get_user_hash(ap, in);
	user = ap_user_insert(uh, mac, ssid, ip);
	if (!user || user->status != 'n') {	/* w/v的，不再插入待验证列表 */ 
		return NULL;
	}
	if (user->status == 'v')
		return user;
		
	user->status = 'v';
	if (verify_buff_add(uh->verify_buff, user))
		logerr("verify_buff_add fail %d %02x-%02x-%02x-%02x-%02x-%02x\n", uh->idx, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	
	auth_cfg_verify_readable();
	
	return user;
}

void ap_online_delete(struct ap_st *ap, int idx, const unsigned char *mac)
{
	struct ap_user *user;
	struct ap_user_hash *uh;
	const unsigned char *addr;
	uh = &ap->ap_users[idx]; 

	user = ap_user_hash_lookup(uh, mac);
	if (!user)
		return;
	
	addr = (const unsigned char *)&user->ip;
	if (user->status != 'w') {
		logdbg("logical error, should not delete offline user %d %02x-%02x-%02x-%02x-%02x-%02x %d.%d.%d.%d\n", idx, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], addr[0], addr[1], addr[2], addr[3]);
		return;
	}
	logdbg("delete online user %d %02x-%02x-%02x-%02x-%02x-%02x %d.%d.%d.%d ok\n", idx, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], addr[0], addr[1], addr[2], addr[3]);
	
	hlist_del(&user->hnode);
	kfree(user);
}

int ap_online_fill_all(struct ap_st *ap, char *buf, int buflen) {
	int i, total;
	char *pos = buf, *end = buf + buflen;
	
	total = 0;
	for (i = 0; i < ap->maxid; i++) {
		int left = end - pos; 
		int ret = online_user_fill(&ap->ap_users[i], pos, left); 
		total += ret; 
		if (ret >= left) 
			break; 
		pos += ret; 
	}
	return total;
}

#define AP_HOST_OUTPUT_FMT 	"%02d %02d %s"
#define AP_HOST_OUTPUT_DEMO	"01 13 192.168.0.107"
int ap_host_fill_all(struct ap_st *ap, char *buf, int buflen) {
	int i, total;
	struct ap_host *host;
	struct hlist_node *node;
	struct hlist_head *head; 
	struct ap_user_hash *uh;
	char *pos = buf, *end = buf + buflen;
	
	total = 0;
	for (i = 0; i < 1; i++) {
		uh = &ap->ap_users[i];
		head = &uh->pass_host;
		hlist_for_each_entry(host, node, head, hnode) {
			int left = end - pos, ret;
			ret = snprintf(pos, left, AP_HOST_OUTPUT_FMT"\n", uh->idx, strlen(host->host), host->host);
			if (ret < 0) {
				logerr("space not enough bufflen %d\n", buflen);
				goto finish;
			}
			total += ret; 
			pos += ret; 
		} 
	}
finish:
	return total;
}

void delete_user(void *u, void *param) {
	struct ap_user *user = (struct ap_user *)u;
	hlist_del(&user->hnode);
	kfree(user);
}

int ap_verify_fill_all(struct ap_st *ap, char *buf, int buflen) {
	int i, total, left, ret;
	char *pos = buf, *end = buf + buflen;
	
	total = 0;
	for (i = 0; i < ap->maxid; i++) {
		left = end - pos;
		ret = verify_buff_fill(ap->ap_users[i].verify_buff, pos, left, ap->ap_users[i].idx, delete_user, &ap->ap_users[i]); 
		total += ret; 
		if (ret >= left) 
			break; 
		pos += ret;
	}

	return total;
}

int online_user_fill(struct ap_user_hash *uh, char *buf, int buflen) {
	int j, total, left, d;
	char *pos, *end;
	struct ap_user *user;
	struct hlist_head *slot;
	struct hlist_node *node, *n;
	unsigned int now = jiffies;
	
	total = 0;
	pos = buf, end = buf + buflen; 
	for (j = 0; j < AP_USER_HASH_MASK; j++) {
		slot = &uh->slots[j];
		hlist_for_each_entry_safe(user, node, n, slot, hnode) {
			if (user->status != 'w')
				continue;
			
			d = (now - user->jf)/HZ;
			if (d > ONLINE_TIMEOUT) {
				unsigned char *mmac = user->mac;
				unsigned char *ip = (unsigned char *)&user->ip;
				logdbg("user timeout, delete %u %u %d %d, %d %02x-%02x-%02x-%02x-%02x-%02x %d.%d.%d.%d %s\n", now, user->jf, d, ONLINE_TIMEOUT, uh->idx, 
					mmac[0], mmac[1], mmac[2], mmac[3], mmac[4], mmac[5], ip[0], ip[1], ip[2], ip[3], user->ssid);
				hlist_del(&user->hnode);
				kfree(user);
				continue;
			}
				
			left = end - pos;
			if (left < AP_USER_SIZE + sizeof(int)) {
				logerr("buff too small %d %d\n", left, AP_USER_SIZE + sizeof(int));
				goto finish;
			}
			
			memcpy(pos, &uh->idx, sizeof(int));		pos += sizeof(int);
			ap_user_fill(user, pos, left);			pos += AP_USER_SIZE;
			
			total += AP_USER_SIZE + sizeof(int); 
		}
	}
finish: 
	return total;
}

#define AP_REDIRECT_OUTPUT_FMT "%02d %04d %s" 
int ap_redirect_url_fill(struct ap_st *ap, char *buf, int buflen) {
	char *pos, *end;
	int i, total, left, ret; 
	struct ap_user_hash *uh; 
	
	total = 0;
	pos = buf, end = buf + buflen;
	for (i = 0; i < ap->maxid; i++) { 
		uh = &ap->ap_users[i];
		
		left = end - pos;
		ret = snprintf(pos, left, AP_REDIRECT_OUTPUT_FMT"\n", uh->idx, strlen(uh->url), uh->url);
		if (ret < 0) {
			logerr("space not enough bufflen %d\n", buflen);
			goto finish;
		}
		
		total += ret; 
		pos += ret;
	}
finish:
	return total;
}

int ap_redirect_url_set(struct ap_st *ap, int idx, const char *url, int urllen) 
{
	return set_redirect_url(ap, idx, url, urllen);
}

const char *ap_redirect_url(struct ap_st *ap, const char *in, int *urllen) {
	struct ap_user_hash *uh = ap_get_user_hash(ap, in);
	*urllen = uh->urllen;
	return uh->url;
} 

char *ap_user_fill(struct ap_user *user, char *buf, int buflen) {
	if (buflen < AP_USER_SIZE)
		return NULL;
	
	memcpy(buf, &user->ip, AP_USER_SIZE);
	return buf;
}

int ap_account_set(struct ap_st *ap, const char *account, int account_len) {
	int len = strlen(account);
	if (len > account_len || account_len >= MAX_AP_ACCOUNT_SIZE - 1) {
		logerr("account size too large %d %d %d\n", len, account_len, MAX_AP_ACCOUNT_SIZE - 1);
		return -1;
	} 
	
	strncpy(ap->ap_account, account, len);
	ap->ap_account[len] = 0;
	return 0;
}

int ap_apgroup_set(struct ap_st *ap, const char *apgroup, int apgroup_len) {
	int len = strlen(apgroup);
	if (len > apgroup_len || apgroup_len >= MAX_AP_GROUP_SIZE - 1) {
		logerr("account size too large %d %d %d\n", len, apgroup_len, MAX_AP_GROUP_SIZE - 1);
		return -1;
	} 
	
	strncpy(ap->ap_group, apgroup, len);
	ap->ap_group[len] = 0;
	return 0;
}

int ac_host_set(struct ap_st *ap, const char *host, int hostlen) {
	int len = strlen(host);
	if (len > hostlen || hostlen >= MAC_AC_HOST_SIZE - 1) {
		logerr("host size too large %d %d %d\n", len, hostlen, MAC_AC_HOST_SIZE - 1);
		return -1;
	} 
	
	strncpy(ap->ac_host, host, len);
	ap->ac_host[len] = 0;
	return 0;
}

int ap_account_fill(struct ap_st *ap, char *buff, int buflen) {
	int len = strlen(ap->ap_account); 
	if (len >= buflen - 1) {
		logerr("in buff too small %d %d\n", len, buflen);
		buff[0] = 0;
		return 0;
	}
	
	strncpy(buff, ap->ap_account, len);
	buff[len] = 0;
	return len;
}

int ap_apgroup_fill(struct ap_st *ap, char *buff, int buflen) {
	int len = strlen(ap->ap_group); 
	if (len >= buflen - 1) {
		logerr("in buff too small %d %d\n", len, buflen);
		buff[0] = 0;
		return 0;
	}
	
	strncpy(buff, ap->ap_group, len);
	buff[len] = 0;
	return len;
}

int ac_host_fill(struct ap_st *ap, char *buff, int buflen) {
	int len = strlen(ap->ac_host); 
	if (len >= buflen - 1) {
		logerr("in buff too small %d %d\n", len, buflen);
		buff[0] = 0;
		return 0;
	}
	
	strncpy(buff, ap->ac_host, len);
	buff[len] = 0;
	return len;
}
/*
单频:2.4G
 eth1 	SSID1
wl0.1 	SSID2
wl0.2	SSID3
wl0.3	SSID4

双频:
 eth1	0 SSID1 	5G		
 eth2	0 SSID1		2.4G
wl0.1	1 SSID2		5G
wl1.1 	1 SSID2		2.4G
wl0.2	2 SSID3
wl1.2	2 SSID3
wl0.3	3 SSID4
wl1.3	3 SSID4
*/
