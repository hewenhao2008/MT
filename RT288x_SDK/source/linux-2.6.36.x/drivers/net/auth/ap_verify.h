#ifndef __AUTH_AP_VERIFY_H__
#define __AUTH_AP_VERIFY_H__

struct verify_buff_st;

struct verify_buff_st *verify_buff_create(void); 
void verify_buff_destroy(struct verify_buff_st *mb);

int verify_buff_add(struct verify_buff_st *mb, void *user);

void verify_buff_clear(struct verify_buff_st *mb);

typedef void (* del_callback)(void *user, void *param);
int verify_buff_fill(struct verify_buff_st *mb, char *buff, int len, int idx, del_callback cb, void *param);

#endif 
