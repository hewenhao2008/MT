#include <linux/in.h>
#include <linux/ip.h>  
#include "auth_misc.h"
#include "auth_log.h"

typedef struct pse_hdr_st {
	unsigned int saddr, daddr;
	unsigned char mbz, proto;
	unsigned short len;
} pse_hdr_st;


int format_mac(const unsigned char *mac, unsigned char *out, size_t outlen) {
	return snprintf(out, outlen, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2],
		mac[3], mac[4], mac[5]);
}

int format_ip(const unsigned char *ip, unsigned char *out, size_t outlen) {
	return snprintf(out, outlen, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
}

unsigned short tcp_v4_check(int len, unsigned int saddr,
		unsigned int daddr, unsigned int base)
{
	struct pse_hdr_st psd;

	psd.saddr = saddr;
	psd.daddr = daddr;
	psd.mbz = 0;
	psd.proto = IPPROTO_TCP;
	psd.len = htons(len);

	return csum_fold(csum_partial(&psd, sizeof(psd), base));
}
/*
static void print_ip(__be32 sip, __be32 dip) {
	unsigned char *saddr = (unsigned char *)&sip;
	unsigned char *daddr = (unsigned char *)&dip;
	loginfo("ip %d.%d.%d.%d --> %d.%d.%d.%d\n", saddr[0], saddr[1], saddr[2], saddr[3], daddr[0], daddr[1], daddr[2], daddr[3]);
}
*/
void print_http(unsigned char *payload, int size) {
	char buff[1024];
	const char *pos;
	int len; 
	pos = get_host((char *)payload, size, &len);
	if (pos) {
		memcpy(buff, pos, len);
		buff[len] = 0;
		printk("host %d %s\n", len, buff);
		//return;
	} 
	pos = strstr((const char *)payload, "\r\n\r\n");
	len = pos - (const char *)payload > sizeof(buff) - 1 ? sizeof(buff) - 1 : pos - (const char *)payload - 1;
	
	memcpy(buff, payload, len);
	buff[len] = 0;
	printk("%s\n-------------------------\n", buff);
	pos = get_uri(payload, size, &len);
	printk("%d %s\n-------------------------\n", len, buff);
}

void print_macxx(const unsigned char *mac) {
	loginfo("%02x:%02x:%02x:%02x:%02x:%02x\n",
	       mac[0], mac[1], mac[2],
	       mac[3], mac[4], mac[5]);
}
void print_mac(struct sk_buff *skb) {
	//const unsigned char *mac = mac_source(skb);
	//print_macxx(mac);
}

void hexdump(const void *data, int size)
{
    /* dumps size bytes of *data to stdout. Looks like:
     * [0000] 75 6E 6B 6E 6F 77 6E 20
     *                  30 FF 00 00 00 00 39 00 unknown 0.....9.
     * (in a single line of course)
     */

    const unsigned char *p = data;
    unsigned char c;
    int n;
    char bytestr[4] = {0};
    char addrstr[10] = {0};
    char hexstr[ 16*3 + 5] = {0};
    char charstr[16*1 + 5] = {0};
    for(n=1;n<=size;n++) {
        if (n%16 == 1) {
            /* store address for this line */
            snprintf(addrstr, sizeof(addrstr), "%.4x",
               (unsigned int)(p-(const unsigned char *)data));
        }
            
        c = *p;
        if (!((c>='0' && c<='9') || 
		(c>='a' && c<='z') || 
		(c>='A' && c<='Z' ))
		) {
            c = '.';
        }

        /* store hex str (for left side) */
        snprintf(bytestr, sizeof(bytestr), "%02x ", *p);
        strncat(hexstr, bytestr, sizeof(hexstr)-strlen(hexstr)-1);

        /* store char str (for right side) */
        snprintf(bytestr, sizeof(bytestr), "%c", c);
        strncat(charstr, bytestr, sizeof(charstr)-strlen(charstr)-1);

        if(n%16 == 0) { 
            /* line completed */
            printk("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
            hexstr[0] = 0;
            charstr[0] = 0;
        } else if(n%8 == 0) {
            /* half line: add whitespaces */
            strncat(hexstr, "  ", sizeof(hexstr)-strlen(hexstr)-1);
            strncat(charstr, " ", sizeof(charstr)-strlen(charstr)-1);
        }
        p++; /* next byte */
    }

    if (strlen(hexstr) > 0) {
        /* print rest of buffer if not empty */
        printk("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
    }
}

char *get_host(char *addr, int size, int *len) {
	char *pos, *end_pos,*end = addr + size;
	for (pos = addr; pos < end; ) {
		// find 'Host' case insensitive 
		if (*pos != 'H' && *pos != 'h') {
			pos++;
			continue;
		}
		if (strnicmp(pos, "Host", 4)) {
			pos += 4;
			continue;
		}
		pos += 4;
		
		while (pos < end && (*pos == ' ' || *pos == '\t')) pos++;	// skip space and tab
		if (pos >= end)
			break;
		
		if (*pos++ != ':')
			continue;
		
		while (pos < end && (*pos == ' ' || *pos == '\t')) pos++;	// skip space and tab
		if (pos >= end)
			break;
	
		end_pos = pos + 1;
		while (end_pos < end && *end_pos != '\n' && *end_pos != ':') end_pos++;		// find end flag "\r\n" or "\n"
		if (*(end_pos - 1) == '\r') 
			end_pos--;
		if (end_pos <= pos)
			return NULL;
		*len = end_pos - pos;
	
		return pos;
	}
	
	return NULL; 
}

char *get_uri(char *addr, int size, int *len) {
	char *pos = addr, *end = addr + size, *start;
	for ( ; pos < end; pos++) {
		if (*pos == '/')
			break;
	}
	if (pos >= end)
		return NULL;
		
	start = pos;
	for ( ; pos < end; pos++) {
		if (*pos == ' ' || *pos == '\t' || *pos == '\r' || *pos == '\n')
			break;
	}
	
	*len = pos - start;
	return start;
}

