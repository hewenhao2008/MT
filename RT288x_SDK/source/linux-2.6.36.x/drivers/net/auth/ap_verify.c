#include <linux/slab.h> 
#include "ap_verify.h"
#include "ap_user.h"
#include "auth_log.h"
#define MAX_VERIFY_COUNT 1024

struct verify_buff_st {
	void *data[MAX_VERIFY_COUNT];
	int count;
};

struct verify_buff_st *verify_buff_create(void)
{
	struct verify_buff_st *vb = kmalloc(sizeof(struct verify_buff_st), GFP_NOWAIT);
	if (!vb) {
		logerr("kmalloc fail\n");
		return NULL;
	}
	memset(vb, 0, sizeof(struct verify_buff_st));
	return vb;
}

void verify_buff_destroy(struct verify_buff_st *mb) {
	kfree(mb);
}

int verify_buff_add(struct verify_buff_st *mb, void *user)
{
	if (mb->count >= MAX_VERIFY_COUNT) 
		return -1;
	mb->data[mb->count++] = user; 	
	return 0;
}

void verify_buff_clear(struct verify_buff_st *mb)
{
	memset(mb, 0, sizeof(struct verify_buff_st));
}

int verify_buff_fill(struct verify_buff_st *mb, char *buff, int len, int idx, del_callback cb, void *param) {
	int total = 0, i, maxid;
	struct ap_user *user;
	char *pos, *end;
	
	if (!mb->count)
		return 0;
	
	pos = buff, end = buff + len;
	for (i = 0; i < mb->count; i++) {
		int left = end - pos;
		if (left < AP_USER_SIZE + sizeof(idx)) {
			logerr("buff too small %d %d\n", left, AP_USER_SIZE + sizeof(idx));
			break;
		}
		
		user = (struct ap_user*)mb->data[i];
		if (user->status == 'v') {
			memcpy(pos, &idx, sizeof(idx));			pos += sizeof(idx);
			ap_user_fill(user, pos, AP_USER_SIZE);	pos += AP_USER_SIZE;  
			total += AP_USER_SIZE + sizeof(idx); 
			
			cb(user, param);
			continue;
		}
		
		/* 微信登录时，会直接把待认证的user节点从'v'改成'w' */
		{
		unsigned char *mac = user->mac;
		logdbg("status %c %d %02x-%02x-%02x-%02x-%02x-%02x\n", user->status, idx, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		}
	}
	
	maxid = 0;
	if (i < mb->count) {
		maxid = mb->count - i;
		logerr("buffer too small len %d, need %d %d %d\n", len, (AP_IP_SIZE + AP_MAC_SIZE) * mb->count, i, mb->count);
		memmove(&mb->data[0], &mb->data[i], maxid * sizeof(void *));
	}
	mb->count = maxid;

	return total;
}
