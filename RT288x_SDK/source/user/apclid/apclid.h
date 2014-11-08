#ifndef __APCLID_H__
#define __APCLID_H__

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

#include "nvram.h"

#define APLOG syslog
#define logerr(fmt, args...) \
 	do{	\
 		syslog(LOG_ERR, "%s: "fmt, __FUNCTION__, ##args); \
	}while(0)
#define logdbg(fmt, args...) \
	do { \
		syslog(LOG_INFO, "%s: "fmt, __FUNCTION__, ##args); \
	}while(0)


extern int ac_addr_invalid;


#endif //__APCLID_H__
