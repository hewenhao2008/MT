#include <linux/ip.h>
#include <linux/in.h>
#include <linux/netfilter.h>
#include <linux/netdevice.h>
#include <../net/bridge/br_private.h>

#include "suq.h"
#include "suq_stats.h"
#include "xxhash.h"


#define SUQ_USER_DEBUG(user, fmt, ...) do { \
	SUQ_DEBUG(fmt " [user "_IP_FMT", active_jiffies: %lu, rc: (%d %d %u) (%d %d %u)]", \
		##__VA_ARGS__, _IP_VAL(user->ip), user->active_jiffies, \
		user->rate_ctrl[0].pending, user->rate_ctrl[0].tokens, user->rate_ctrl[0].tokens_per_jiffy, \
		user->rate_ctrl[1].pending, user->rate_ctrl[1].tokens, user->rate_ctrl[1].tokens_per_jiffy); \
} while (0)


struct suq_global suq;


static void suq_backlog_init(struct suq_backlog *backlog)
{
	INIT_LIST_HEAD(&backlog->packets);
	backlog->octets = 0;
}

static int suq_backlog_empty(struct suq_backlog *backlog)
{
	if (list_empty(&backlog->packets)) {
		BUG_ON(backlog->octets != 0);
		return 1;
	}
	BUG_ON(backlog->octets == 0);
	return 0;
}

static void suq_backlog_enqueue(struct suq_backlog *backlog, struct sk_buff *skb)
{
	struct list_head *skb_node;

	skb_node = (void *)skb;
	list_add_tail(skb_node, &backlog->packets);
	backlog->octets += skb->len;
}

static struct sk_buff *suq_backlog_dequeue(struct suq_backlog *backlog)
{
	struct sk_buff *skb;
	struct list_head *skb_node;

	skb_node = backlog->packets.next;
	list_del(skb_node);

	skb = (struct sk_buff *)skb_node;
	backlog->octets -= skb->len;

	if (list_empty(&backlog->packets)) {
		BUG_ON(backlog->octets != 0);
	} else {
		BUG_ON(backlog->octets == 0);
	}

	return skb;
}

static uint32_t suq_rate_ctrl_update_stats(struct suq_rate_ctrl *rc)
{
	uint32_t cur_octets = (uint32_t)rc->total_octets;
	uint32_t octets = cur_octets - rc->last_octets;
	rc->last_octets = cur_octets;
	return octets;
}

static int suq_rate_ctrl_feed(struct suq_rate_ctrl *rc)
{
	unsigned long current_jiffies;
	unsigned long feed_jiffies;
	int32_t feed_tokens;
	int32_t tokens_after_feed;

	BUG_ON(rc->tokens >= 0);

	current_jiffies = jiffies;

	feed_jiffies = current_jiffies - rc->jiffies;

	// TODO: just ignore the rarely case of jiffies wrapping ?
	if (feed_jiffies == 0)
		return 0;

	if (feed_jiffies > HZ)
		feed_jiffies = HZ;

	feed_tokens = rc->tokens_per_jiffy * feed_jiffies;
	BUG_ON(feed_tokens <= 0);

	tokens_after_feed = rc->tokens + feed_tokens;
	if (tokens_after_feed < 0)
		return 0;

	rc->tokens = tokens_after_feed;
	rc->jiffies = current_jiffies;
	return 1;
}

static void suq_rate_ctrl_deactivate(struct suq_rate_ctrl *rc)
{
	int32_t tokens_per_jiffy;
	unsigned long expire_jiffies;
	unsigned long active_jiffies;

	BUG_ON(rc->tokens >= 0);

	tokens_per_jiffy = rc->tokens_per_jiffy;
	expire_jiffies = (-rc->tokens + tokens_per_jiffy - 1) / tokens_per_jiffy;
	active_jiffies = jiffies + expire_jiffies;

	rc->tokens += expire_jiffies * tokens_per_jiffy;
	rc->jiffies = active_jiffies;

	suq_timer_mod(&suq.timer, &rc->timer_entry, active_jiffies);

	rc->pending = 1;
}

static int suq_rate_ctrl_consume(struct suq_rate_ctrl *rc, int32_t pkt_len)
{
	rc->total_octets += pkt_len;

	rc->tokens -= pkt_len;

	if (rc->tokens < 0 && !suq_rate_ctrl_feed(rc)) {
		suq_rate_ctrl_deactivate(rc);
		return 0;
	}

	return 1;
}

static int suq_rate_ctrl_activate(
	struct suq_rate_ctrl *rc,
	struct list_head *dequeue_packets)
{
	struct sk_buff *skb;
	int nr_dequeue = 0;

	rc->pending = 0;

	while (!suq_backlog_empty(&rc->backlog)) {
		skb = suq_backlog_dequeue(&rc->backlog);
		list_add_tail((struct list_head *)skb, dequeue_packets);
		nr_dequeue++;
		if (!suq_rate_ctrl_consume(rc, skb->len))
			break;
	}

	if (nr_dequeue != 0)
		SUQ_DEBUG("dequeue %d packets", nr_dequeue);

	return nr_dequeue;
}

static void suq_rate_ctrl_timer_func(struct suq_timer_entry *entry)
{
	struct suq_rate_ctrl *rc = entry->data;
	struct list_head dequeue_packets;
	struct list_head *skb_node, *skb_node_next;

	INIT_LIST_HEAD(&dequeue_packets);

	spin_lock_bh(&suq.lock);
	suq.backlog_packets -= suq_rate_ctrl_activate(rc, &dequeue_packets);
	spin_unlock_bh(&suq.lock);

	list_for_each_safe(skb_node, skb_node_next, &dequeue_packets) {
		br_forward_finish((struct sk_buff *)skb_node);
	}

	if (suq.status == SUQ_DISABLING && suq.backlog_packets == 0) {
		complete(&suq.disable_done);
	}
}

static void suq_rate_ctrl_reset_rate_limit(
	struct suq_rate_ctrl *rc,
	uint32_t bytes_per_jiffy)
{
	uint32_t new_rate = bytes_per_jiffy ?: SUQ_BYTES_PER_SEC_MAX / HZ;
	if (rc->tokens_per_jiffy != new_rate) {
		rc->tokens_per_jiffy = new_rate;
		rc->tokens = new_rate;
	}
}

static void suq_rate_ctrl_init(struct suq_rate_ctrl *rc, int16_t dir, uint32_t bytes_per_jiffy)
{
	suq_timer_entry_init(&rc->timer_entry, suq_rate_ctrl_timer_func, rc);
	rc->pending = 0;
	rc->dir = dir;
	rc->tokens_per_jiffy = bytes_per_jiffy ?: SUQ_BYTES_PER_SEC_MAX / HZ;
	rc->tokens = rc->tokens_per_jiffy;
	rc->jiffies = jiffies;
	suq_backlog_init(&rc->backlog);
	rc->last_octets = 0;
	rc->total_octets = 0;
}

static void suq_user_cleanup(struct suq_user *user)
{
	SUQ_DEBUG("user cleanup: "_MAC_FMT" %5s "_IP_FMT", jiffies: %lu",
		_MAC_VAL(user->mac), user->dev, _IP_VAL(user->ip), jiffies);

	BUG_ON(!hlist_unhashed(&user->hnode));
	BUG_ON(!suq_backlog_empty(&user->rate_ctrl[0].backlog));
	BUG_ON(!suq_backlog_empty(&user->rate_ctrl[1].backlog));

	suq_timer_del(&suq.timer, &user->stats_timer);
}

static void suq_user_stats_timer_func(struct suq_timer_entry *entry)
{
	struct suq_user *user = entry->data;
	int user_active = 1;

	spin_lock_bh(&suq.lock);
	if (jiffies - user->active_jiffies > SUQ_USER_TIMEOUT * HZ) {
		hlist_del_init(&user->hnode);
		suq_user_cleanup(user);
		kfree(user);
		user_active = 0;
	}
	spin_unlock_bh(&suq.lock);

	if (user_active) {
		uint32_t xmit = suq_rate_ctrl_update_stats(&user->rate_ctrl[0]);
		uint32_t recv = suq_rate_ctrl_update_stats(&user->rate_ctrl[1]);
		suq_user_stats_update(&suq.user_stats, user,
			xmit / SUQ_USER_STATS_INTERVAL,
			recv / SUQ_USER_STATS_INTERVAL,
			user->rate_ctrl[0].total_octets,
			user->rate_ctrl[1].total_octets);
		suq_timer_mod(&suq.timer, &user->stats_timer, jiffies + SUQ_USER_STATS_INTERVAL * HZ);
	}
}

static void suq_user_update(
	struct suq_user *user,
	const char *dev,
	uint32_t ip,
	struct suq_rate_config *cfg)
{
	strcpy(user->dev, dev);
	user->ip = ip;
	user->active_jiffies = jiffies;
	suq_rate_ctrl_reset_rate_limit(&user->rate_ctrl[0], cfg->xmit_rate);
	suq_rate_ctrl_reset_rate_limit(&user->rate_ctrl[1], cfg->recv_rate);
}

static void suq_user_init(
	struct suq_user *user,
	const uint8_t *mac,
	const char *dev,
	uint32_t ip,
	struct suq_rate_config *cfg)
{
	SUQ_DEBUG("user init: "_MAC_FMT" %5s "_IP_FMT", jiffies: %lu",
		_MAC_VAL(mac), dev, _IP_VAL(ip), jiffies);

	memcpy(user->mac, mac, ETH_ALEN);
	strcpy(user->dev, dev);
	user->ip = ip;
	user->active_jiffies = jiffies;

	INIT_HLIST_NODE(&user->hnode);

	suq_rate_ctrl_init(&user->rate_ctrl[0], 0, cfg->xmit_rate);
	suq_rate_ctrl_init(&user->rate_ctrl[1], 1, cfg->recv_rate);

	suq_timer_entry_init(&user->stats_timer, suq_user_stats_timer_func, user);
	suq_timer_mod(&suq.timer, &user->stats_timer, jiffies + SUQ_USER_STATS_INTERVAL * HZ);
}

static void suq_global_init(void)
{
	int i;

	suq.config.max_backlog_packets = 6000;
	suq.config.latency_shift = 6;

	spin_lock_init(&suq.lock);
	suq_timer_init(&suq.timer);

	for (i = 0; i <= SUQ_USER_HASH_MASK; i++) {
		INIT_HLIST_HEAD(&suq.users[i]);
	}

	suq.backlog_packets = 0;

	suq.status = SUQ_ENABLED;
	init_completion(&suq.disable_done);

	suq_user_stats_init(&suq.user_stats);
}

void suq_global_cleanup(void)
{
	int i;
	int nr_user_free = 0;

	BUG_ON(suq.backlog_packets != 0);

	suq_timer_cleanup(&suq.timer);

	for (i = 0; i <= SUQ_USER_HASH_MASK; i++) {
		struct suq_user *user;
		struct hlist_node *hnode, *next;
		hlist_for_each_entry_safe(user, hnode, next, &suq.users[i], hnode) {
			hlist_del_init(&user->hnode);
			suq_user_cleanup(user);
			kfree(user);
			nr_user_free++;
		}
	}

	suq_user_stats_cleanup(&suq.user_stats);

	SUQ_INFO("users cleanup: %d", nr_user_free);
}


static struct suq_rate_config *suq_get_rate_config(const struct net_device *dev)
{
	int ssid_index;

	if (strncmp(dev->name, "ra", 2) == 0 && dev->name[3] == 0) {
		ssid_index = dev->name[2] - '0';
		if (ssid_index < 0 || ssid_index >= ARRAY_SIZE(suq.config.rates)) {
			SUQ_DEBUG("bad device name: %s", dev->name);
			return NULL;
		}
	} else {
		SUQ_DEBUG("bad device name: %s", dev->name);
		return NULL;
	}
	//SUQ_DEBUG("ssid %d", ssid_index);
	return &suq.config.rates[ssid_index];
}

static void suq_get_user_addr(struct sk_buff *skb, int pkt_dir, uint8_t *mac, uint32_t *ip)
{
	struct ethhdr *eth = eth_hdr(skb);
	struct iphdr *iph = ip_hdr(skb);

	if (pkt_dir == 0) {
		memcpy(mac, eth->h_source, ETH_ALEN);
		*ip = __be32_to_cpu(iph->saddr);
	} else {
		memcpy(mac, eth->h_dest, ETH_ALEN);
		*ip = __be32_to_cpu(iph->daddr);
	}
}

static struct suq_user *suq_get_user(struct sk_buff *skb, int pkt_dir, const struct net_device *in)
{
	uint8_t mac[ETH_ALEN];
	uint32_t ip;
	struct hlist_head *slot;
	struct hlist_node *hnode;
	struct suq_user *user;
	struct suq_rate_config *ratecfg;
	const struct net_device *dev;

	dev = pkt_dir == 0 ? in : skb->dev;

	ratecfg = suq_get_rate_config(dev);
	if (ratecfg == NULL) {
		return NULL;
	}

	suq_get_user_addr(skb, pkt_dir, mac, &ip);

	if (memcmp(mac, "\xFF\xFF\xFF\xFF\xFF\xFF", ETH_ALEN) == 0) {
		return NULL;
	}

	slot = &suq.users[XXH32(mac, sizeof(mac), 0) & SUQ_USER_HASH_MASK];

	hlist_for_each_entry(user, hnode, slot, hnode) {
		if (memcmp(user->mac, mac, sizeof(mac)) == 0) {
			suq_user_update(user, dev->name, ip, ratecfg);
			return user;
		}
	}

	user = SUQ_NEW(struct suq_user);
	if (user == NULL) {
		SUQ_ERROR("out of user");
		return NULL;
	}

	suq_user_init(user, mac, dev->name, ip, ratecfg);
	hlist_add_head(&user->hnode, slot);
	return user;
}

static int suq_get_pkt_dir(const struct net_device *in, const struct net_device *out)
{
	if (in && strcmp(in->name, "eth2") == 0) {
		return 1;
	}

	if (out && strcmp(out->name, "eth2") == 0) {
		return 0;
	}

	SUQ_DEBUG("unknown packet dir, from %s to %s", (in?in->name:"null"), (out?out->name:"null"));
	return -1;
}

static int suq_filter_packet(struct sk_buff *skb, const struct net_device *in)
{
	int pkt_dir;
	struct suq_user *user;
	struct suq_rate_ctrl *rc;

	pkt_dir = suq_get_pkt_dir(in, skb->dev);
	if (pkt_dir == -1)
		return NF_ACCEPT;
	
	user = suq_get_user(skb, pkt_dir, in);
	if (user == NULL)
		return NF_ACCEPT;

	rc = &user->rate_ctrl[pkt_dir];

	if (!rc->pending) {
		suq_rate_ctrl_consume(rc, skb->len);
		return NF_ACCEPT;
	}

	if (rc->backlog.octets >= (rc->tokens_per_jiffy << suq.config.latency_shift)) {
		return NF_DROP;
	}

	if (suq.backlog_packets >= suq.config.max_backlog_packets) {
		return NF_DROP;
	}

	suq.backlog_packets++;
	suq_backlog_enqueue(&rc->backlog, skb);

	return NF_STOLEN;
}

static int suq_hook(
	struct sk_buff *skb,
	const struct net_device *in,
	const struct net_device *out)
{
	int ret;

	//SUQ_DEBUG("suq_hook, in: %s, out: %s", in->name, out->name);

	if (skb->protocol != __cpu_to_be16(ETH_P_IP))
		return NF_ACCEPT;

	switch (ip_hdr(skb)->protocol) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_ICMP:
		break;
	default:
		SUQ_DEBUG("unsupported protocol: %d", (int)ip_hdr(skb)->protocol);
		return NF_ACCEPT;
	}

	spin_lock_bh(&suq.lock);
	ret = suq_filter_packet(skb, in);
	spin_unlock_bh(&suq.lock);

	return ret;
}

extern int (*br_fwd_hook_suq)(struct sk_buff *,const struct net_device *in, const struct net_device *out);

static int __init suq_init(void)
{
	SUQ_INFO("init");

	SUQ_INFO("HZ: %d", HZ);

	suq_global_init();

	rcu_assign_pointer(br_fwd_hook_suq, suq_hook);

	return 0;
}

static void __exit suq_exit(void)
{
	SUQ_INFO("exit");

	rcu_assign_pointer(br_fwd_hook_suq, NULL);
	synchronize_rcu();

	suq.status = SUQ_DISABLING;
	INIT_COMPLETION(suq.disable_done);
	if (suq.backlog_packets != 0) {
		wait_for_completion(&suq.disable_done);
	}
	suq.status = SUQ_DISABLED;

	suq_global_cleanup();
}

module_init(suq_init);
module_exit(suq_exit);

MODULE_AUTHOR("xx");
MODULE_DESCRIPTION("simple/stupid user queue");
MODULE_VERSION("0.1");
MODULE_LICENSE("GPL");

