#include <linux/list.h> 
#include <linux/slab.h>  
#include <linux/module.h> 
#include <linux/sched.h>
#include "auth_misc.h" 
#include "ap_user.h"
#include "ap_3rd.h"
#include "auth_log.h"
#include "auth_cfg.h"

#define AP_3RD_HASH_MASK		((1 << 12) - 1)
enum {
	T_WEIXIN_START,
	T_WEIXIN_SIP,
	T_QQ_START, 
	T_ALL_START,
};
struct ap_3rd {
	struct hlist_head slots[AP_3RD_HASH_MASK + 1];
	struct hlist_head wx_ol_list;
};

struct weixin_online {
	struct hlist_node 	hnode;
	struct ap_user		user;
};

struct type_key {
	unsigned int type;
	unsigned int ip;
};
 
struct qq_extra {
	unsigned int crc;
	unsigned int is_qq_host; 	/* 1表示已经确认该连接(tcp_tuple)是访问qq host的 */
};
struct pass_extra {
	unsigned int crc;
	unsigned int is_pass;
};

struct iptime {
	struct hlist_node 	hnode;
	struct type_key		iptype;
	unsigned int 		jf;  
	union {
		struct qq_extra 	qq_ext; 
		struct pass_extra	pass_ext;
		char 				reserved[8];
	};
};

struct ap_3rd *ap_3rd_create(void) {
	int j;
	static struct ap_3rd s_3rd;
	
	memset(&s_3rd, 0, sizeof(s_3rd));
	for (j = 0; j <= AP_3RD_HASH_MASK; j++) {
		INIT_HLIST_HEAD(&s_3rd.slots[j]);  
	} 
	INIT_HLIST_HEAD(&s_3rd.wx_ol_list);  
	
	return &s_3rd;
}

void ap_3rd_destroy(struct ap_3rd *a3) {
	int i;
	struct iptime *it; 
	struct weixin_online *wo;
	struct hlist_node *node, *n; 
	
	for (i = 0; i <= AP_3RD_HASH_MASK; i++) {
		hlist_for_each_entry_safe(it, node, n, &a3->slots[i], hnode) {
			hlist_del(&it->hnode);
			kfree(it);
		}
	}
	hlist_for_each_entry_safe(wo, node, n, &a3->wx_ol_list, hnode) {
		hlist_del(&wo->hnode);
		kfree(wo);
	}
}

static unsigned int hash_crc(const void *p, int len)
{
	int i;
	unsigned int hash = 0;
	const char *addr = (const char *)p;
	
	for (i = 0; i < len; i++) 
		hash += hash * 33 + addr[i];

	return hash;
}

static inline struct hlist_head *get_slot(struct ap_3rd *a3, const struct type_key *key) {
	return &a3->slots[hash_crc(key, sizeof(struct type_key)) & AP_3RD_HASH_MASK];  
}

static struct iptime *iptime_lookup(struct ap_3rd *a3, const struct type_key *key) {
	struct iptime *it;
	struct hlist_node *node;
	struct hlist_head *slot;
	 
	slot = get_slot(a3, key);
	hlist_for_each_entry(it, node, slot, hnode) {
		if (!memcmp(&it->iptype, key, sizeof(struct type_key)))
			return it;
	}
	
	return NULL;
}

int ap_3rd_replace(struct ap_3rd *a3, const struct type_key *key, unsigned int jf) {
	struct iptime *ipt; 
	struct hlist_node *node;
	struct hlist_head *slot; 
	 
	slot = get_slot(a3, key);
	hlist_for_each_entry(ipt, node, slot, hnode) {
		if (!memcmp(key, &ipt->iptype, sizeof(struct type_key))) {
			ipt->jf = jf;
			//logdbg("---- jf %d\n", jf);
			return 1;
		}
	}
	
	ipt = kmalloc(sizeof(struct iptime), GFP_NOWAIT);
	if (!ipt) {
		logerr("kmalloc fail %d\n", sizeof(struct iptime));
		return -1;
	}
		
	memset(ipt, 0, sizeof(struct iptime));
	memcpy(&ipt->iptype, key, sizeof(struct type_key));
	ipt->jf = jf;
	//logdbg("---- jf %d+++\n", jf);
	hlist_add_head(&ipt->hnode, slot);
	return 0;
}

void ap_3rd_delete(struct ap_3rd *a3, const struct type_key *key) {
	struct iptime *it = iptime_lookup(a3, key);
	if (!it) 
		return;
	hlist_del(&it->hnode);
	kfree(it);
}

#define WEIXIN_URI	"/prompt_weixin.php?account="
#define QQ_URI		"/admin/ci/qq" 
int ap_3rd_match(struct ap_3rd *a3, struct host_uri *hu, struct tcp_tuple *tuple, const char *account, const char *ac_host, const char *ap_group)
{
	struct type_key key; 
	char *host, *uri;
	
	uri = hu->uri;
	host = hu->host;
	if (!uri)
		return 0; 	/* 非HTTP数据包 */
	
	if(!strncmp(uri, WEIXIN_URI, sizeof(WEIXIN_URI) - 1)) {	/* 微信登录重定向HTTP包 "id.ip-com.com.cn/prompt_weixin.php?account=ghw" */
		if ((strlen(account) == 0 && strlen(ap_group) == 0) || (strncmp(account, uri + sizeof(WEIXIN_URI) - 1, strlen(account)) &&
			strncmp(ap_group, uri + sizeof(WEIXIN_URI) - 1, strlen(ap_group))))
			return 0;
		
		if (!host || strncmp(host, ac_host, strlen(ac_host)))
			return 0;
		
		key.type = T_WEIXIN_START;
		key.ip = tuple->saddr;
		if (ap_3rd_replace(a3, &key, jiffies) < 0 )
			logerr("ap_3rd_replace T_WEIXIN_START fail\n");

		return 1;
	}

	//feixun 定制代码
	if (strlen(account) == strlen("fx") && !strncmp(account, "fx", strlen("fx"))) {
		if (!strncmp(uri, "/wifi/serv/ads.action", strlen("/wifi/serv/ads.action"))) {
			key.type = T_WEIXIN_START;
			key.ip = tuple->saddr;
			logdbg("visit fx ad home page\n");
			if (ap_3rd_replace(a3, &key, jiffies) < 0 )
				logerr("ap_3rd_replace T_WEIXIN_START fail\n");
			return 1;
		}
	}
	
	if(!strncmp(uri, QQ_URI, sizeof(QQ_URI) - 1)) { 		/* QQ登录重定向HTTP包 "id.ip-com.com.cn/admin/ci/qq" */
		if (!host || strncmp(host, ac_host, strlen(ac_host)))
			return 0;
		
		key.type = T_QQ_START;
		key.ip = tuple->saddr; 
		if (ap_3rd_replace(a3, &key, jiffies) < 0)
			logerr("ap_3rd_replace T_QQ_START fail\n");

		return 1;
	}

	return 0;
}

#define QQ_POSTFIX ".qq.com"
#define WEIXIN_HOST_FLAG ".weixin.qq.com" 
#define WEIXIN_ACCOUNT_FLAG "/weixin.php?account="
int ap_3rd_weixin(struct ap_3rd *a3, struct host_uri *hu, const char *mac, 
	struct tcp_tuple *tuple, const char *account, struct ap_st *ap, const char *in, const char *ac_host)
{
	int df;
	char old_ch;
	unsigned int now;
	struct iptime *ipt;
	struct type_key key;
	int hostlen;
	struct ap_user *user;
	char *host, *uri, *end, *pos;
	int need_pass_time = 6;
	int is_feixun = 0;
	const char *apgroup = ap->ap_group;

	key.ip = tuple->saddr;
	now = jiffies;
	
	host = hu->host;	hostlen = hu->hostlen;
	uri = hu->uri; 
	if (!uri || !host) 
		goto other_packet;

	/* 微信公众号的回复中要包含此服务号特征 */
	if (!strncmp(host, ac_host, strlen(ac_host)) && !strncmp(uri, WEIXIN_ACCOUNT_FLAG, sizeof(WEIXIN_ACCOUNT_FLAG) - 1)) {
		/* 用户在公众账号里面点击了我要上网 */
		if ((strlen(account) > 0 && !strncmp(uri + sizeof(WEIXIN_ACCOUNT_FLAG) - 1, account, strlen(account))) ||
			(strlen(apgroup) > 0 && !strncmp(uri + sizeof(WEIXIN_ACCOUNT_FLAG) - 1, apgroup, strlen(apgroup)))) {
			logdbg("weixin login success. %s---%s\n", account, apgroup);
			
			if (strlen(account) == strlen("fx") && !strcmp(account, "fx")) {
				is_feixun = 1;
			}

			if (is_feixun != 1) {//如果是feixun的ap不在本地上线
				if (!ap_online_insert_by_ssid(ap, mac, in, tuple->saddr)) {
					logerr("!!!!!!!!!!!!!!ap_online_insert_by_ssid fail\n");
					return 0;
				}
			}

			if (is_feixun != 1) {
				user = ap_online_lookup(ap, in, mac, tuple->saddr);
			} else {
				user = ap_verify_lookup(ap, in, mac, tuple->saddr);
			}
			
			if (user) {
				struct weixin_online *wo = kmalloc(sizeof(struct weixin_online), GFP_NOWAIT);
				if (wo) {
					memset(wo, 0, sizeof(struct weixin_online));
					memcpy(&wo->user, user, sizeof(struct ap_user)); 
					hlist_add_head(&wo->hnode, &a3->wx_ol_list);
					auth_cfg_weixin_readable();
				} else {
					logerr("kmalloc fail\n"); 
				}
			} else {
				logerr("cannot find user! error !!!!!!!\n");
			}
			if (is_feixun == 1 ) { //飞讯定制
				return -1;
			}
			return -2;	//通过微信认证，继续重定向到广告页面，用于统计用户上线
		}
	}
	
	/* 访问微信的主机 */
	end = host + hostlen;
	old_ch = *end;
	*end = 0;
	pos = strstr(host, WEIXIN_HOST_FLAG);
	*end = old_ch;
	if (pos) { 
		key.type = T_WEIXIN_SIP;
		ap_3rd_replace(a3, &key, now);
		return 1;
	}
	
other_packet:
	key.type = T_WEIXIN_START;
	ipt = iptime_lookup(a3, &key);
	if (ipt) {
		df = (now - ipt->jf)/HZ;
		if (df < 0) {
			logerr("ERROR !!!! %d %u %u delete \n", df, now, ipt->jf);
			ap_3rd_delete(a3, &key);
			return 0;
		}
		if (df < need_pass_time) {//dbg[ap_3rd_weixin]: drivers/net/auth/../../../../../auth/sys/ap_3rd.c ap_3rd_weixin 259 0 1233 1233 123361
			/* 此用户需要微信认证，先放通所有数据，防止苹果等终端无法接入wifi. 苹果终端接入wifi后，会自动弹出web认证页面，如果web认证不成功，将不会接入wifi网络 */
			return 1;
		}
		if (df <= 180 && host && ap_host_find(ap, in, host, hostlen)) {
			//logdbg("weixin within 180s and in pass hosts\n"); 
			return 1; 	/* 此用户需要微信认证, 180s内放通所有到微信服务的数据包 */
		}
		//logdbg("T_WEIXIN_START %d.%d.%d.%d %d --- \n", pp[0], pp[1], pp[2], pp[3], df);	
		if (df > 240) {
			unsigned char *pp = (unsigned char *)&key.ip;
			logdbg("T_WEIXIN_START %d.%d.%d.%d over 240 %d, restart\n", pp[0], pp[1], pp[2], pp[3], df);
			ap_3rd_replace(a3, &key, jiffies-need_pass_time*HZ);
			return 0;
		}
	} else {
		ap_3rd_replace(a3, &key, jiffies-need_pass_time*HZ);
	}
	
	return 0;
}
int ap_3rd_qq(struct ap_3rd *a3, struct host_uri *hu, struct tcp_tuple *tuple)
{
	int hostlen, df;
	char old_ch;
	unsigned int now, crc;
	struct iptime *ipt;
	struct type_key key; 
	char *host, *end, *pos;

	key.ip = tuple->saddr;
	key.type = T_QQ_START;
	ipt = iptime_lookup(a3, &key); 
	if (!ipt)
		return 0;
	
	now = jiffies;
	df = (now - ipt->jf)/HZ;
	if (df < 0) {
		logerr("T_QQ_START ERROR %d %u %u\n", df, now, ipt->jf);
		ap_3rd_delete(a3, &key);
		return 0;
	}
	if (df <= 6) 
		return 1;
		
	if (df > 120) {
		logdbg("T_QQ_START delete %ds \n", df);
		ap_3rd_delete(a3, &key);
		return 0;
	}
	
	crc = hash_crc(tuple, sizeof(struct tcp_tuple));
	if (ipt->qq_ext.is_qq_host && crc == ipt->qq_ext.crc) 
		return 1; 	/* 访问了qq.com，并且tcp_tuple一样，放过 */
	
	if (ntohs(tuple->dest) == 443)
		return 1;
	 
	host = hu->host;	hostlen = hu->hostlen;
	if (!hu->host) 
		return 0;
	
	end = host + hostlen;
	old_ch = *end;
	*end = 0;
	pos = strstr(host, QQ_POSTFIX);
	*end = old_ch;
	if (!pos) 
		return 0;

	ipt->qq_ext.crc = crc;
	ipt->qq_ext.is_qq_host = 1;
	return 1;
}

int ap_3rd_set_through(struct ap_3rd *a3, unsigned int ip) {
	struct type_key key; 
	unsigned char *addr = (unsigned char *)&ip;
	
	logdbg("set through %d.%d.%d.%d\n", addr[0], addr[1], addr[2], addr[3]);
	
	key.ip = ip;
	key.type = T_WEIXIN_START;
	return ap_3rd_replace(a3, &key, jiffies) >= 0;
}

int ap_3rd_weixin_login_fill(struct ap_3rd *a3, char *buff, int len) {
	int idx, left;
	char *pos, *end;
	struct weixin_online *wo;
	struct hlist_node *node, *n; 

	pos = buff, end = buff + len;
	hlist_for_each_entry_safe(wo, node, n, &a3->wx_ol_list, hnode) {
		left = end - pos;
		if (len < sizeof(idx) + AP_USER_SIZE) {
			logerr("not enough buff \n");
			break;
		}
		logdbg("fill weixin user\n");
		idx = get_idx(wo->user.ssid);
		memcpy(pos, &idx, sizeof(idx));				pos += sizeof(idx);
		ap_user_fill(&wo->user, pos, left);			pos += AP_USER_SIZE; 
		hlist_del(&wo->hnode);
		kfree(wo);
	}
	return pos - buff;
}


static void clear_timeout_nodes(struct ap_3rd *a3) {
	int i;
	unsigned int now;
	struct iptime *ipt;  
	struct hlist_node *node, *n; 
	now = jiffies;
	for (i = 0; i <= AP_3RD_HASH_MASK; i++) {
		hlist_for_each_entry_safe(ipt, node, n, &a3->slots[i], hnode) {
			int d = (now - ipt->jf) / HZ;
			if (d < 1800)
				continue; 
			hlist_del(&ipt->hnode);
			kfree(ipt);
		}
	}
}

int ap_3rd_set_pass(struct ap_3rd *a3, struct tcp_tuple *tuple) {
	unsigned int crc;
	struct iptime *ipt;
	struct type_key key;  

	//key.ip = tuple->saddr;
	crc = hash_crc(tuple, sizeof(struct tcp_tuple));
	key.ip = crc;
	key.type = T_ALL_START;
	ipt = iptime_lookup(a3, &key); 
	if (ipt) {
		ap_3rd_replace(a3, &key, jiffies);
		goto clear_timeout;
	}
	
	ap_3rd_replace(a3, &key, jiffies);
	//ipt = iptime_lookup(a3, &key); 
	//crc = hash_crc(tuple, sizeof(struct tcp_tuple));
	//ipt->pass_ext.crc = crc;
	
clear_timeout: 
	{
		static unsigned int last_time = 0;
		int d = (jiffies - last_time) / HZ;
		if (d > 60) {
			clear_timeout_nodes(a3);
			last_time = jiffies;
		}
	}
	return 0;
}

int ap_3rd_find_pass(struct ap_3rd *a3, struct tcp_tuple *tuple) {
	unsigned int crc;
	struct iptime *ipt;
	struct type_key key;  

	crc = hash_crc(tuple, sizeof(struct tcp_tuple));
	//key.ip = tuple->saddr;
	key.ip = crc;
	key.type = T_ALL_START;
	ipt = iptime_lookup(a3, &key); 
	if (!ipt)
		return 0; 
	//crc = hash_crc(tuple, sizeof(struct tcp_tuple));
	//if (crc != ipt->pass_ext.crc)
	//	return 0;
	return 1;
}