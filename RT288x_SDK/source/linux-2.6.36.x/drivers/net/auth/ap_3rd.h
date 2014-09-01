#ifndef __AP_3RD_H__
#define __AP_3RD_H__

struct ap_3rd;

struct tcp_tuple {
	unsigned int saddr;
	unsigned int daddr;
	unsigned short source;
	unsigned short dest;
};

struct host_uri {
	char *host;
	char *uri;
	int hostlen;
	int urilen;
};

struct ap_3rd *ap_3rd_create(void);
void ap_3rd_destroy(struct ap_3rd *a3);

int ap_3rd_match(struct ap_3rd *a3, struct host_uri *hu, struct tcp_tuple *tuple, const char *account, const char *ac_host, const char *ap_group);
	
int ap_3rd_weixin(struct ap_3rd *a3, struct host_uri *hu, const char *mac, 
	struct tcp_tuple *tuple, const char *account, struct ap_st *ap, const char *in, const char *ac_host);
	
int ap_3rd_qq(struct ap_3rd *a3, struct host_uri *hu, struct tcp_tuple *tuple);

int ap_3rd_set_through(struct ap_3rd *a3, unsigned int ip);

int ap_3rd_weixin_login_fill(struct ap_3rd *a3, char *buff, int len);

int ap_3rd_set_pass(struct ap_3rd *a3, struct tcp_tuple *tuple);
int ap_3rd_find_pass(struct ap_3rd *a3, struct tcp_tuple *tuple);


#endif 
