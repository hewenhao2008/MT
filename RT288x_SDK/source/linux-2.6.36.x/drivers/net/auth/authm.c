#include <linux/module.h>

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/in.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/delay.h>
#include <linux/string.h>
#include <linux/sysfs.h>

#include <linux/netfilter.h>
#include <linux/netfilter_bridge.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/netfilter_arp.h>
#include <net/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in_route.h>
#include <linux/inetdevice.h>
#include <linux/ppp_defs.h>

#include "auth_log.h"
#include "auth_cfg.h"
#include "auth_misc.h"
#include "ap_user.h"
#include "ap_3rd.h"

static struct auth_cfg_st *s_acfg = NULL;

static inline unsigned char *mac_source(struct sk_buff *skb) {
	return ((struct ethhdr *)skb_mac_header(skb))->h_source;
}

#ifndef nf_bridge_encap_header_len
static inline unsigned int nf_bridge_encap_header_len(const struct sk_buff *skb)
{
	switch (skb->protocol) {
	case __constant_htons(ETH_P_8021Q):
		return VLAN_HLEN;
	case __constant_htons(ETH_P_PPP_SES):
		return PPPOE_SES_HLEN;
	default:
		return 0;
	}
}
#endif

#ifdef CONFIG_SYSCTL
static int brnf_filter_vlan_tagged __read_mostly = 1;
static int brnf_filter_pppoe_tagged __read_mostly = 1;
#else
#define brnf_filter_vlan_tagged 1
#define brnf_filter_pppoe_tagged 1
#endif

static inline __be16 vlan_proto(const struct sk_buff *skb)
{
	return vlan_eth_hdr(skb)->h_vlan_encapsulated_proto;
}

#define IS_VLAN_IP(skb) \
	(skb->protocol == htons(ETH_P_8021Q) && \
	 vlan_proto(skb) == htons(ETH_P_IP) && 	\
	 brnf_filter_vlan_tagged)
 
static inline __be16 pppoe_proto(const struct sk_buff *skb)
{
	return *((__be16 *)(skb_mac_header(skb) + ETH_HLEN +
			    sizeof(struct pppoe_hdr)));
}

#define IS_PPPOE_IP(skb) \
	(skb->protocol == htons(ETH_P_PPP_SES) && \
	 pppoe_proto(skb) == htons(PPP_IP) && \
	 brnf_filter_pppoe_tagged)

static inline void nf_bridge_push_encap_header(struct sk_buff *skb)
{
	unsigned int len = nf_bridge_encap_header_len(skb);

	skb_push(skb, len);
	skb->network_header -= len;
}

static inline void nf_bridge_pull_encap_header(struct sk_buff *skb)
{
	unsigned int len = nf_bridge_encap_header_len(skb);

	skb_pull(skb, len);
	skb->network_header += len;
}

static int auth_reset(struct sk_buff *skb, const struct net_device *dev)
{
	int len;
	struct sk_buff *nskb;
	struct tcphdr *otcph, *ntcph;
	struct ethhdr *neth, *oeth;
	struct iphdr *niph, *oiph;
	unsigned int csum, header_len; 

	oeth = (struct ethhdr *)skb_mac_header(skb);
	oiph = ip_hdr(skb);
	otcph = (struct tcphdr *)(skb_network_header(skb) + (oiph->ihl << 2));

	header_len = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr);
	nskb = alloc_skb(header_len, GFP_KERNEL);
	if (!nskb) {
		logerr("alloc_skb fail\n");
		return -1;
	}
	
	skb_reserve(nskb, header_len);
	ntcph = (struct tcphdr *)skb_push(nskb, sizeof(struct tcphdr));
	memset(ntcph, 0, sizeof(struct tcphdr));
	ntcph->source = otcph->source;
	ntcph->dest = otcph->dest;
	ntcph->seq = otcph->seq;
	ntcph->ack_seq = otcph->ack_seq;
	ntcph->doff = sizeof(struct tcphdr) / 4;
	((u_int8_t *)ntcph)[13] = 0;
	ntcph->rst = 1; 
	ntcph->ack = otcph->ack; 
	ntcph->window = htons(0);
	
	niph = (struct iphdr *)skb_push(nskb, sizeof(struct iphdr)); 
	memset(niph, 0, sizeof(struct iphdr));
	niph->saddr = oiph->saddr;
	niph->daddr = oiph->daddr; 
	niph->version = oiph->version;
	niph->ihl = 5;
	niph->tos = 0;
	niph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
	niph->ttl = 0x80;
	niph->protocol = oiph->protocol;
	niph->id = 0; 
	niph->frag_off = 0x0040;
	ip_send_check(niph);
	
	len = ntohs(niph->tot_len) - (niph->ihl<<2);
	csum = csum_partial((char*)ntcph, len, 0);
	ntcph->check = tcp_v4_check(len, niph->saddr, niph->daddr, csum);
	
	neth = (struct ethhdr *)skb_push(nskb, sizeof(struct ethhdr)); 
	memcpy(neth, oeth, sizeof(struct ethhdr)); 
	
	nskb->dev = (struct net_device *)dev;
	dev_queue_xmit(nskb);
	return 0;
}

static int auth_URL(const char *url, int urllen, struct sk_buff *skb, const struct net_device *dev) {
	struct sk_buff *nskb;
	struct ethhdr *neth, *oeth;
	struct iphdr *niph, *oiph;
	struct tcphdr *otcph, *ntcph;
	int len;
	unsigned int csum, header_len; 
	char *data;

	oeth = (struct ethhdr *)skb_mac_header(skb);
	oiph = ip_hdr(skb);
	otcph = (struct tcphdr *)(skb_network_header(skb) + (oiph->ihl<<2));

	header_len = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr);
	nskb = alloc_skb(header_len + urllen, GFP_KERNEL);
	if (!nskb) {
		logerr("alloc_skb fail\n");
		return -1;
	}

	skb_reserve(nskb, header_len); 

	data = (char *)skb_put(nskb, urllen);
	memcpy(data, url, urllen);
	
	ntcph = (struct tcphdr *)skb_push(nskb, sizeof(struct tcphdr)); 
	memset(ntcph, 0, sizeof(struct tcphdr));
	ntcph->source = otcph->dest;
	ntcph->dest = otcph->source;
	ntcph->seq = otcph->ack_seq;
	ntcph->ack_seq = htonl(ntohl(otcph->seq) + ntohs(oiph->tot_len) - (oiph->ihl<<2) - (otcph->doff<<2));
	ntcph->doff = 5;
	ntcph->ack = 1;
	ntcph->psh = 1;
	ntcph->fin = 1;
	ntcph->window = 65535;
	
	niph = (struct iphdr *)skb_push(nskb, sizeof(struct iphdr)); 
	memset(niph, 0, sizeof(struct iphdr));
	niph->saddr = oiph->daddr;
	niph->daddr = oiph->saddr; 
	niph->version = oiph->version;
	niph->ihl = 5;
	niph->tos = 0;
	niph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + urllen);
	niph->ttl = 0x80;
	niph->protocol = oiph->protocol;
	niph->id = 0x2658; 
	niph->frag_off = 0x0040;
	ip_send_check(niph);
	
	len = ntohs(niph->tot_len) - (niph->ihl<<2);
	csum = csum_partial((char*)ntcph, len, 0);
	ntcph->check = tcp_v4_check(len, niph->saddr, niph->daddr, csum);

	neth = (struct ethhdr *)skb_push(nskb, sizeof(struct ethhdr));  
	memcpy(neth->h_dest, oeth->h_source, 6);
	memcpy(neth->h_source, oeth->h_dest, 6);
	neth->h_proto = htons(ETH_P_IP);  
	nskb->dev = (struct net_device *)dev;
	dev_queue_xmit(nskb);
	return 0; 
}

static int auth_redirect(const char *url, int urllen, struct sk_buff *skb,
					const struct net_device *in,
					const struct net_device *out)
{
	/* 构造一个URL重定向包, 从in接口发出去 */
	if(auth_URL(url, urllen, skb, in)){
		logerr("error send redirect url.\n");
		return -1;
	}
	
	/* 构造一个reset包, 从out接口发出去 */
	if (out)
		auth_reset(skb, out);
	return 0;
}

// static inline bool ipv4_is_lbcast(__be32 addr) {return addr == htonl(INADDR_BROADCAST);}
// static inline bool ipv4_is_zeronet(__be32 addr) {return (addr & htonl(0xff000000)) == htonl(0x00000000);}
// static inline bool ipv4_is_multicast(__be32 addr) {return (addr & htonl(0xf0000000)) == htonl(0xe0000000);}
// static inline bool ipv4_is_loopback(__be32 addr) {return (addr & htonl(0xff000000)) == htonl(0x7f000000);}

static int br_fwd_hookfn(struct sk_buff *skb,
				    const struct net_device *in,
				    const struct net_device *out)
{
	int paylen, ret, weixin_ret;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;
	unsigned char *payload, *mac, *daddr;
	struct tcp_tuple tuple = {0};
	struct host_uri hu = {0};
	char ipaddr[20];
	char tmphost[128] = {0};
	bool bypass_url_found = false;
	char redirect_url[512] = {0};
	char tmp_redirect_url[512] = {0};
	char macsrc[32] = {0};
	char ipsrc[32] = {0};
	
	if (skb->protocol != htons(ETH_P_IP))
		return 0; 	/* 非IP协议放通 */
		
	//if (*(int *)in->name == *(int *)"eth0" || *(int *)in->name == *(int *)"vlan") 
	if (*(int *)in->name == *(int *)"eth2") //eth2, eth2.x 都是物理网口.
		return 0; 	/* 回包放通 */
		
	iph = (struct iphdr *)skb->data; 
	if ((iph->protocol != IPPROTO_TCP) && (iph->protocol != IPPROTO_UDP)) 
		return 0;		/* 非TCP/ICMP/UDP的都放通 */
	
	/*将SKB头部已经指向IP头部*/
	nf_bridge_pull_encap_header(skb); 
	
	mac = mac_source(skb);
	
	auth_cfg_lock(s_acfg); 
	
	if (ipv4_is_lbcast(iph->saddr) || ipv4_is_lbcast(iph->daddr) || ipv4_is_loopback(iph->saddr) || 
		ipv4_is_loopback(iph->daddr) || ipv4_is_multicast(iph->saddr) || ipv4_is_multicast(iph->daddr) || 
		ipv4_is_zeronet(iph->saddr) || ipv4_is_zeronet(iph->daddr))
		goto __finished;
	
	if (ap_online_lookup(s_acfg->ap, in->name, mac, iph->saddr)) 
		goto __finished;		/* 已认证 */
	if (auth_cfg_bypass(s_acfg))
		goto __finished;		/* bypass */
	ap_verify_insert(s_acfg->ap, in->name, mac, in->name, iph->saddr); 	/* 如果没在待认证列表中，加入 */
	if (iph->protocol == IPPROTO_UDP) {
		udph = (struct udphdr *)(skb->data + (iph->ihl << 2));
		if (ntohs(udph->dest) == 53)
			goto __finished; 	/* DNS包放通 */ 
		goto __droped;			/* 没通过认证的UDP包，丢弃 */
	}
	
	tcph = (struct tcphdr *)(skb->data + (iph->ihl << 2));
	if (tcph->syn || tcph->fin || tcph->rst) {
 		goto __finished;
	}
	
	paylen = skb->len - (iph->ihl << 2) + (tcph->doff << 2);
	payload = skb->data + (iph->ihl << 2) + (tcph->doff << 2);
	tuple.saddr = iph->saddr;
	tuple.daddr = iph->daddr;
	tuple.source = tcph->source;
	tuple.dest = tcph->dest;

	if(paylen >= 0 && !strncasecmp(payload, "GET", 3)) {	
		hu.host = get_host(payload, paylen, &hu.hostlen);
		hu.uri = get_uri(payload, paylen, &hu.urilen);
		
		if (hu.host) {
			memcpy(tmphost, hu.host, hu.hostlen);
			if (ap_host_find(s_acfg->ap, in->name, hu.host, hu.hostlen)) {
				bypass_url_found = true;
				//if (hu.hostlen < 128) {
					//memcpy(tmphost, hu.host, hu.hostlen);
					//logerr("visit host!!!!!!!!!!! %s, and set bypass\n", tmphost);
				//}
				ap_3rd_set_pass(s_acfg->ap3rd, &tuple); 
			}
		}
		ret = ap_3rd_match(s_acfg->ap3rd, &hu, &tuple, auth_cfg_account(s_acfg), auth_cfg_ac_host(s_acfg), s_acfg->ap->ap_group);
		if (ret) 
			goto __finished;
		
		weixin_ret = ap_3rd_weixin(s_acfg->ap3rd, &hu, mac, &tuple, auth_cfg_account(s_acfg), s_acfg->ap, in->name, auth_cfg_ac_host(s_acfg));
		if (weixin_ret == 1) 
			goto __finished;
		
		if (ap_3rd_qq(s_acfg->ap3rd, &hu, &tuple)) 
			goto __finished;
		
		if (hu.host) {
			//if (!ap_host_find(s_acfg->ap, in->name, hu.host, hu.hostlen)) {
			if (!bypass_url_found || weixin_ret == -1) {
				int urllen;
				const char *redirect = ap_redirect_url(s_acfg->ap, in->name, &urllen);
				
				ret = format_mac(mac, macsrc, sizeof(macsrc));//mac src
				if (ret <= 0) {
					goto __droped;
				}

				ret = format_ip(&tuple.saddr, ipsrc, sizeof(ipsrc));
				if (ret <= 0) {
					goto __droped;
				}

				if (weixin_ret == -1) {
					ret = snprintf(tmp_redirect_url, sizeof(tmp_redirect_url), "%s&is_weixin=1", ipsrc);
					if (ret <= 0) {
						goto __droped;
					}
				} else {
					ret = snprintf(tmp_redirect_url, sizeof(tmp_redirect_url), "%s", ipsrc);
					if (ret <= 0) {
						goto __droped;
					}
				}

				ret = snprintf(redirect_url, sizeof(redirect_url), redirect, macsrc, tmp_redirect_url);
				if (ret <= 0) {
					goto __droped;
				}

				//if (auth_redirect(redirect, urllen, skb, in, out) == 0) {	 
				if (auth_redirect(redirect_url, strlen(redirect_url), skb, in, out) == 0) {	 	 
					logdbg("redirect %s %02x-%02x-%02x-%02x-%02x-%02x %s to %s ok\n", in->name, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], tmphost, redirect_url);
					goto __droped;
				}
			}
			goto __finished;
		}
	}
	if (ap_3rd_weixin(s_acfg->ap3rd, &hu, mac, &tuple, auth_cfg_account(s_acfg), s_acfg->ap, in->name, auth_cfg_ac_host(s_acfg))) 
		goto __finished;
		
	if (ap_3rd_qq(s_acfg->ap3rd, &hu, &tuple)) 
		goto __finished;
	
	daddr = (unsigned char *)&iph->daddr;
	ret = snprintf(ipaddr, sizeof(ipaddr), "%d.%d.%d.%d", daddr[0], daddr[1], daddr[2], daddr[3]);
	
	if (ap_3rd_find_pass(s_acfg->ap3rd, &tuple)) 
		goto __finished; 
		
	if (!ap_host_find(s_acfg->ap, in->name, ipaddr, ret))  {
		//logerr("drop %s %02x-%02x-%02x-%02x-%02x-%02x\n", ipaddr, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		goto __droped; 
	}
	
__finished:
	auth_cfg_unlock(s_acfg);
	/*处理完毕, SKB头部要指回来*/
	nf_bridge_push_encap_header(skb);
	return 0;
__droped:
	if (hu.host) {
		logdbg("drop %s %02x-%02x-%02x-%02x-%02x-%02x %s ok\n", in->name, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], tmphost);
	}
	auth_cfg_unlock(s_acfg);
	nf_bridge_push_encap_header(skb);
	
	return -1;
}

extern int (*br_fwd_hook_auth)(struct sk_buff *,const struct net_device *in, const struct net_device *out);

static int __init auth_module_init(void)
{
	logdbg("module auth init.\n");

	s_acfg = auth_cfg_create();
	if (!s_acfg) {
		logerr("auth_sysfs_register fail \n");
		return -1;
	}

	rcu_assign_pointer(br_fwd_hook_auth, br_fwd_hookfn);
	
	return 0;
}

static void __exit auth_module_exit(void)
{
	loginfo("module auth exit.\n");

	rcu_assign_pointer(br_fwd_hook_auth, NULL);
	synchronize_rcu();

	if (s_acfg)
		auth_cfg_destroy(s_acfg);
}

module_init(auth_module_init);
module_exit(auth_module_exit);

MODULE_AUTHOR("Jesse Ye");
MODULE_DESCRIPTION("Hello, world");
MODULE_VERSION("v0.0");
MODULE_LICENSE("GPL");
