#ifndef __AUTH_AP_USER_H__
#define __AUTH_AP_USER_H__

#define AP_SSID_COUNT			(4)
#define AP_USER_HASH_MASK		((1 << 12) - 1)
#define MAC_REDIRECT_URL_SIZE	(4096)
#define MAC_HOST_LEN			(64)
#define MAX_AP_ACCOUNT_SIZE		(32)
#define MAX_AP_GROUP_SIZE		(32)
#define MAC_AC_HOST_SIZE		(256)
#define ONLINE_TIMEOUT			(300)

#include <linux/list.h> 

struct ap_host {
	struct 	hlist_node 	hnode;
	char	host[MAC_HOST_LEN];
};

struct ap_user_hash {
	int idx;
	struct hlist_head slots[AP_USER_HASH_MASK + 1];
	struct hlist_head pass_host;
	char url[MAC_REDIRECT_URL_SIZE];
	int urllen;
	struct verify_buff_st *verify_buff;
};

struct ap_st {
	struct ap_user_hash ap_users[AP_SSID_COUNT];
	char ap_account[MAX_AP_ACCOUNT_SIZE];
	char ap_group[MAX_AP_GROUP_SIZE];
	char ac_host[MAC_AC_HOST_SIZE];
	int maxid;
};

#define AP_MAC_SIZE 	(6)
#define AP_SSID_SIZE 	(6)
#define AP_IP_SIZE		(sizeof(unsigned int)) 
#define AP_JF_SIZE		(sizeof(unsigned int))
#define AP_USER_SIZE	(AP_MAC_SIZE+AP_IP_SIZE+AP_JF_SIZE+AP_SSID_SIZE)
struct ap_user {
	struct hlist_node 	hnode;
	unsigned int 		ip;
	unsigned int 		jf;
	unsigned char 		mac[6];
	unsigned char 		ssid[6];
	short 				status;
};

struct ap_st *ap_create(void);
void ap_destroy(struct ap_st *);

struct ap_user *ap_online_lookup(struct ap_st *ap, const char *in, const unsigned char *mac, unsigned int sip);
struct ap_user *ap_online_insert(struct ap_st *ap, int idx, const unsigned char *mac, const char *ssid, unsigned int ip);
struct ap_user *ap_online_insert_by_ssid(struct ap_st *p, const unsigned char *mac, const char *ssid, unsigned int ip);
void ap_online_delete(struct ap_st *ap, int idx, const unsigned char *mac);
int ap_online_fill_all(struct ap_st *ap, char *buf, int buflen);

struct ap_user *ap_verify_lookup(struct ap_st *ap, const char *in, const unsigned char *mac, unsigned int sip);
struct ap_user *ap_verify_insert(struct ap_st *ap, const char *in, const unsigned char *mac, const char *ssid, unsigned int ip);

int ap_host_clear(struct ap_st *ap, int idx);
int ap_host_insert(struct ap_st *ap, int idx, const char *host, int hostlen);
int ap_host_delete(struct ap_st *ap, int idx, const char *host, int hostlen);
int ap_host_find(struct ap_st *ap, const char *in, const char *host, int hostlen);
int ap_host_fill_all(struct ap_st *ap, char *buf, int buflen);

int ap_redirect_url_fill(struct ap_st *ap, char *buf, int buflen);
int ap_redirect_url_set(struct ap_st *ap, int idx, const char *url, int urllen);
const char *ap_redirect_url(struct ap_st *ap, const char *in, int *urllen);

int ap_account_set(struct ap_st *ap, const char *account, int account_len);
int ap_account_fill(struct ap_st *ap, char *buff, int buflen);
int ap_apgroup_set(struct ap_st *ap, const char *apgroup, int apgroup_len);
int ap_apgroup_fill(struct ap_st *ap, char *buff, int buflen);

int ac_host_set(struct ap_st *ap, const char *ac_host, int hostlen);
int ac_host_fill(struct ap_st *ap, char *buff, int buflen);

int ap_verify_fill_all(struct ap_st *ap, char *buf, int buflen);
char *ap_user_fill(struct ap_user *user, char *buf, int buflen);

int get_idx(const char *in) ;

#endif 
