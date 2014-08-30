#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <linux/if_bridge.h>
#include <net/ethernet.h>

#include "apclid.h"
#include "conn.h"
#include "api.h"

///////////////////////////////////////////////////////////////////
struct maclist* get_wl_mac_list(char *ifname, const char *query_cmds)
{
	int mac_list_size;
	struct maclist *mac_list;

	return mac_list;
}
///////////////////////////////////////////////////////////////////apis
int api_get_channel_id(char *ifname) 
{
	int channel;

	return channel;
}

int api_get_wl_auth_count(char *ifname, int *assoc_num) 
{
	int count = 0;

	return count;
}

char* api_get_wl_auth_list(char *ifname) 
{
	char *buff;

	return buff;
}

int api_get_noise(char *ifname, int *noise)
{
	int res = 0;
	return res;
}

int api_get_txpwr(char *ifname, int *pwr)
{
	int res = 0;
	return 0;
}

char* api_get_wl_auth_info(char *ifname, char *mac)
{
	char *buff = NULL;

	return buff;
}

extern struct sysfs_class *br_class_net;
char* api_get_user_addrs(unsigned char *ea)
{
	long buff_size = 0, buff_cur;
	int i, brIndex, fd = -1, n, len;
	char *buffer = NULL;
	struct __fdb_entry fe;
	
	// if(ea){
	// 	APLOG(LOG_DEBUG, "GetAddr of: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
	// 			ea[0],ea[1],ea[2],ea[3],ea[4],ea[5]);
	// }

	n = 1024;
	buff_size = n * sizeof("00:00:00:00:00:00 255.255.255.255\n");
	buffer = malloc(buff_size);
	if (!buffer) {
		APLOG(LOG_ERR, "%s: malloc failed[%d].\n", __FUNCTION__, (int)buff_size);
		return strdup("");
	}
	memset(buffer, 0, buff_size);

	buff_cur = 0;
	for (brIndex = 0; brIndex < 5; ++brIndex) {
		char brX[128];
		/* open /sys/class/net/brXXX/brforward */
		snprintf(brX, sizeof(brX), "/sys/class/net/br%x/brforward", brIndex);
		fd = open(brX, O_RDONLY, 0);
		if (fd < 0) {
			continue;
		}
		for (i = 0; i < n; ++i) {
			lseek(fd, i * sizeof(struct __fdb_entry), SEEK_SET);
			if (read(fd, &fe, sizeof(struct __fdb_entry)) > 0) {
				//debug
				// APLOG(LOG_ERR, "%d:%d\t%.2x:%.2x:%.2x:%.2x:%.2x:%.2x %u.%u.%u.%u\n", i, (int)buff_cur, 
				// 	fe.mac_addr[0],fe.mac_addr[1],fe.mac_addr[2],
				//     fe.mac_addr[3],fe.mac_addr[4],fe.mac_addr[5],
				//     NIPQUAD(fe.l3addr));
				//xxx
				if (fe.l3addr == 0) {
					continue;
				}

				if(!ea) {
					len = snprintf(buffer + buff_cur, buff_size - buff_cur, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x "NIPQUAD_FMT"\n",
				    				fe.mac_addr[0],fe.mac_addr[1],fe.mac_addr[2],
					    			fe.mac_addr[3],fe.mac_addr[4],fe.mac_addr[5],
					    			NIPQUAD(fe.l3addr));
					if (len>0) {
						buff_cur += len;
					} else {
						APLOG(LOG_ERR, "snprintf failed %d,%d,%d,%d\n", i, len, (int)buff_cur, (int)buff_size);
						break;
					}	
				} else {
					if(memcmp(ea, fe.mac_addr, ETHER_ADDR_LEN) == 0){
						snprintf(buffer, buff_size, NIPQUAD_FMT, NIPQUAD(fe.l3addr));
						break;
					}
				}
			}else{
				//APLOG(LOG_ERR, "fetch mac-addr: [%d][%d] records parsed.\n", i, (int)buff_cur);
				break;
			}
		}
		close(fd);
	}
	return buffer;
}

char *api_set_exec_cmds(char *par)
{
	if (strcmp(par, "services") == 0 || strstr(par, "rc restart")!=NULL)
	{
		system("ugw_networks.sh restart &");
	}else if(strcmp(par, "reboot") == 0) {
		system("reboot");
	}else{
		system(par);
	}
	return strdup("");
}

char *api_set_upgrade(char *par)
{
	// int ppid;
	// char *argv[] = {NULL, NULL, NULL, NULL};
	// char res[256];

	// //write url linux mtd.
	// argv[0] = "write";
	// argv[1] = par;
	// argv[2] = "linux";
	// argv[3] = NULL;
	// _eval(argv, NULL, 0, &ppid);

	// snprintf(res, sizeof(res), "upgrade started pid[%d]...\n", ppid);
	return strdup("");
}

char *api_set_fetch(char *fn, char *cmds)
{
	int res, fd;
	struct stat fsta;
	size_t fsize, readsize, count;
	char *buffer = NULL;

	fd = open(fn, O_RDONLY);
	if (fd < 0) {
		return strdup("open file failed.\n");
	}

	res = fstat(fd, &fsta);
	if (res < 0) {
		close(fd);
		return strdup("fstat failed.\n");
	}
	fsize = fsta.st_size;
	//APLOG(LOG_INFO, "fetch fsize: %d\n", fsize);

	buffer = malloc(fsize + 1);
	if (!buffer) {
		close(fd);
		APLOG(LOG_ERR, "fetch malloc failed. size:%d\n", fsize);
		return strdup("malloc failed.\n");
	}
	memset(buffer, 0, fsize + 1);

	readsize = 0;
	while(readsize < fsize) {
		count = read(fd, buffer + readsize, fsize);
		if (count <= fsize) {
			readsize += count;//continue
		}
		if (count < 0) {
			APLOG(LOG_ERR, "file fetch %s zero.\n", fn);
			break;
		}
	}
	buffer[readsize] = '\0';
	//APLOG(LOG_INFO, "fetch string[%s]\n", buffer);

	close(fd);
	if (cmds) {
		//exec cmds to file.
		char tmp[128];
		snprintf(tmp, sizeof(tmp), "%s %s", cmds, fn);
		system(tmp);
	}
	return buffer;
}

