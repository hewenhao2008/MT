#ifndef __AUTH_CONFIG_H__
#define __AUTH_CONFIG_H__

struct ap_st;
struct ap_3rd;
typedef struct auth_cfg_st {
	struct 	mutex auth_cfg_mutex;	/* 配置文件访问互斥 */
	struct 	ap_3rd *ap3rd;			/* 第三方认证 */
	struct 	ap_st *ap;				/* 全局配置 */
	int 	bypass;				
	spinlock_t lock;				/* 全局变量互斥 */
} auth_cfg_st;

struct auth_cfg_st *auth_cfg_create(void);
void auth_cfg_destroy(struct auth_cfg_st *); 

const char *auth_cfg_host(struct auth_cfg_st *acfg, int *hostlen);
int auth_cfg_set_host(struct auth_cfg_st *acfg, const char *host, int hostlen);

int auth_cfg_bypass(struct auth_cfg_st *acfg);
int auth_cfg_set_bypass(struct auth_cfg_st *acfg, int bypass);

const char *auth_cfg_url(struct auth_cfg_st *acfg);

const char *auth_cfg_account(struct auth_cfg_st *acfg);

const char *auth_cfg_ac_host(struct auth_cfg_st *acfg);

void auth_cfg_lock(struct auth_cfg_st *acfg);
void auth_cfg_unlock(struct auth_cfg_st *acfg);

void auth_cfg_weixin_readable(void);
void auth_cfg_verify_readable(void);

#endif 
