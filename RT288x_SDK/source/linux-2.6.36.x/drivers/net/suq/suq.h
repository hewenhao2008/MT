#pragma once


#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/completion.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/if_ether.h>	// ETH_ALEN

#include "suq_timer.h"


#define SUQ_LOG_LEVEL			3
#define SUQ_USER_COUNT_SHIFT	7
#define SUQ_USER_HASH_MASK		((1 << SUQ_USER_COUNT_SHIFT) - 1)
#define SUQ_BYTES_PER_SEC_MAX	(2 * 1000 * 1000 * 1000)
#define SUQ_BACKLOG_PACKETS_MAX	100000
#define SUQ_LATENCY_SHIFT_MAX	10
#define SUQ_USER_STATS_INTERVAL	1
#define SUQ_USER_TIMEOUT		6
#define SUQ_USER_STATS_MAX		(1 << SUQ_USER_COUNT_SHIFT)


#define _IP_FMT "%u.%u.%u.%u"
#define _MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"

#define _IP_VAL(n) \
	((n) >> 24) & 0xFF, \
	((n) >> 16) & 0xFF, \
	((n) >> 8) & 0xFF, \
	(n) & 0xFF

#define _MAC_VAL(n) \
	(n)[0],(n)[1],(n)[2],(n)[3],(n)[4],(n)[5]


#define SUQ_NEW(type) \
	SUQ_NEW_N(type, 1)

#define SUQ_NEW_N(type, n) \
	((type *)kzalloc((n) * sizeof(type), GFP_NOWAIT))


#define SUQ_LOG(level, fmt, ...) do { \
	if ((level) <= SUQ_LOG_LEVEL) { \
		printk("*SUQ* " fmt "\n", ##__VA_ARGS__); \
	} \
} while (0)

#define SUQ_LOG_IF(level, cond, fmt, ...) do { \
	if ((level) <= SUQ_LOG_LEVEL) { \
		if (cond) { \
			printk("*SUQ* " fmt "\n", ##__VA_ARGS__); \
		} \
	} \
} while (0)


#define SUQ_ASSERT(cond)	BUG_ON(!(cond))

#define SUQ_ASSERT_MSG(cond, fmt, ...) do { \
	if (unlikely(!(cond))) { \
		printk(fmt "\n", ##__VA_ARGS__); \
		BUG(); \
	} \
} while (0)


#define SUQ_ERROR(...)			SUQ_LOG(0, ##__VA_ARGS__)
#define SUQ_ERROR_IF(cond, ...)	SUQ_LOG_IF(0, cond, ##__VA_ARGS__)

#define SUQ_WARN(...)			SUQ_LOG(1, ##__VA_ARGS__)
#define SUQ_WARN_IF(cond, ...)	SUQ_LOG_IF(1, cond, ##__VA_ARGS__)

#define SUQ_INFO(...)			SUQ_LOG(2, ##__VA_ARGS__)
#define SUQ_INFO_IF(cond, ...)	SUQ_LOG_IF(2, cond, ##__VA_ARGS__)

#define SUQ_DEBUG(...)			SUQ_LOG(3, ##__VA_ARGS__)
#define SUQ_DEBUG_IF(cond, ...)	SUQ_LOG_IF(3, cond, ##__VA_ARGS__)


struct suq_backlog {
	struct list_head packets;
	uint32_t octets;
};

struct suq_rate_config {
	uint32_t xmit_rate;
	uint32_t recv_rate;
};

struct suq_rate_ctrl {
	struct suq_timer_entry timer_entry;
	int16_t pending;
	int16_t dir;
	uint32_t tokens_per_jiffy;
	int32_t tokens;
	unsigned long jiffies;
	struct suq_backlog backlog;
	uint32_t last_octets;
	uint64_t total_octets;
};

struct suq_user {
	uint8_t mac[ETH_ALEN];
	uint8_t dev[6];
	uint32_t ip;
	unsigned long active_jiffies;
	struct hlist_node hnode;
	struct suq_rate_ctrl rate_ctrl[2];
	struct suq_timer_entry stats_timer;
};

struct suq_config {
	uint32_t max_backlog_packets;
	uint32_t latency_shift;
	struct suq_rate_config rates[4];
};

struct suq_user_stats_info {
	struct hlist_node hnode;
	uint8_t mac[ETH_ALEN];
	uint8_t dev[6];
	uint32_t ip;
	uint32_t xmit_rate;
	uint32_t recv_rate;
	uint64_t xmit_total;
	uint64_t recv_total;
};

struct suq_user_stats {
	spinlock_t lock;
	struct suq_user_stats_info result[SUQ_USER_STATS_MAX];
	int latest_index;
	struct mutex mutex;
	struct suq_user_stats_info tmpusers[SUQ_USER_STATS_MAX];
	struct suq_user_stats_info tmpres[SUQ_USER_STATS_MAX];
	struct hlist_head tmphash[SUQ_USER_HASH_MASK + 1];
};

enum suq_status {
	SUQ_ENABLED,
	SUQ_DISABLING,
	SUQ_DISABLED,
};

struct suq_global {
	spinlock_t lock;
	struct suq_config config;
	struct suq_timer timer;
	struct hlist_head users[SUQ_USER_HASH_MASK + 1];
	uint32_t backlog_packets;
	enum suq_status status;
	struct completion disable_done;
	struct suq_user_stats user_stats; 
};

extern struct suq_global suq;

