#ifndef __APCLID_H__
#define __APCLID_H__

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>

#include "nvram.h"

#define NVRAM_BUFSIZE 	128
#define MAX_NVRAM_SIZE	(1024 * 32)


#define APLOG syslog
#define logerr(fmt, args...) \
 	do{	\
 		syslog(LOG_ERR, "%s: "fmt, __FUNCTION__, ##args); \
	}while(0)
#define logdbg(fmt, args...) \
	do { \
		syslog(LOG_INFO, "%s: "fmt, __FUNCTION__, ##args); \
	}while(0)



static inline char * nvram_ra_get(char *key)
{	
	return (char *)nvram_bufget(RT2860_NVRAM, key);
}

static inline int nvram_ra_set(char *key, char *val)
{
	return nvram_bufset(RT2860_NVRAM, key, val);
}

static inline int nvram_ra_unset(char *key)
{
	return nvram_bufset(RT2860_NVRAM, key, "");
}

static inline int nvram_ra_commit(void)
{
	return nvram_commit(RT2860_NVRAM);
}

static inline int nvram_ra_getall(char *buff, int size)
{
	return nvram_getall(RT2860_NVRAM, buff, size);
}

static inline int nvram_ra_match(char* key, char* mval)
{
	const char *v = nvram_bufget(RT2860_NVRAM, key);
	if(strlen(v)<=0 || !mval) {
		return 0;
	}
	if(strcmp(v, mval) == 0){
		return 1;
	}
	return 0;
}	

extern int ac_addr_invalid;


#endif //__APCLID_H__
