#ifndef __AUTH_MISC_H__
#define __AUTH_MISC_H__

char *get_host(char *addr, int size, int *len);
char *get_uri(char *addr, int size, int *len);
unsigned short tcp_v4_check(int len, unsigned int saddr, unsigned int daddr, unsigned int base);


int format_mac(const unsigned char *mac, unsigned char *out, size_t outlen);
int format_ip(const unsigned char *ip, unsigned char *out, size_t outlen);
			
void print_http(unsigned char *payload, int size);
void print_macxx(const unsigned char *mac);
//void print_mac(struct sk_buff *skb);
void hexdump(const void *data, int size);

#endif 

