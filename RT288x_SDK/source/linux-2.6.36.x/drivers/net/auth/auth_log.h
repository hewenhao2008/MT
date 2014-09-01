#ifndef __AUTH_LOG_H__
#define __AUTH_LOG_H__

#define loginfo(fmt, args...) \
	do { \
		printk("info[%s]: "fmt, __FUNCTION__, ##args); \
	}while(0)

#define logerr(fmt, args...) \
	do { \
		printk("erro[%s]: "fmt, __FUNCTION__, ##args); \
	}while(0)

#define logdbg(fmt, args...) \
	do { \
		printk("dbg[%s]: "fmt, __FUNCTION__, ##args); \
	}while(0)

#endif 
