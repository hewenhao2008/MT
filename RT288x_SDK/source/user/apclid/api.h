#ifndef __APCLID_API_H__
#define __APCLID_API_H__

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]
#define NIPQUAD_FMT "%u.%u.%u.%u"


typedef struct maclist;

//common ext call
struct maclist* get_wl_mac_list(char *ifname, const char *query);

//api interface.
int api_get_channel_id(char *ifname);
int api_get_wl_auth_count(char *ifname, int *assoc_num);
char *api_get_wl_auth_list(char *ifname);
char *api_get_wl_auth_info(char *ifname, char *umac);
char *api_get_user_addrs(unsigned char *ea);
char *api_set_exec_cmds(char *pars);
char *api_set_upgrade(char *pars);
char *api_set_fetch(char *fn, char *post_cmds);
int api_get_noise(char *ifname, int *noise);
int api_get_txpwr(char *ifname, int *pwr);

void init_handlers(void);

#endif //__APCLID_API_H__