#include <linux/sort.h>

#include "suq_stats.h"
#include "xxhash.h"


void suq_user_stats_init(struct suq_user_stats *us)
{
	memset(us, 0, sizeof(*us));

	spin_lock_init(&us->lock);
	mutex_init(&us->mutex);
}

void suq_user_stats_cleanup(struct suq_user_stats *us)
{
	mutex_destroy(&us->mutex);
}

void suq_user_stats_update(
	struct suq_user_stats *us,
	struct suq_user *user,
	uint32_t xmit_rate,
	uint32_t recv_rate,
	uint64_t xmit_total,
	uint64_t recv_total)
{
	struct suq_user_stats_info *ui;
#if 0
	SUQ_DEBUG("%8u %8u %9llu %9llu "_MAC_FMT" %5s "_IP_FMT,
		xmit_rate, recv_rate,
		xmit_total, recv_total,
		_MAC_VAL(user->mac), user->dev, _IP_VAL(user->ip));
#endif
	spin_lock_bh(&us->lock);
	if (us->latest_index == 0)
		us->latest_index = SUQ_USER_STATS_MAX;
	ui = &us->result[--us->latest_index];
	memcpy(ui->mac, user->mac, ETH_ALEN);
	strcpy(ui->dev, user->dev);
	ui->ip = user->ip;
	ui->xmit_rate = xmit_rate;
	ui->recv_rate = recv_rate;
	ui->xmit_total = xmit_total;
	ui->recv_total = recv_total;
	spin_unlock_bh(&us->lock);
}

static struct hlist_head *suq_user_stats_tmphash_insert(
	struct hlist_head *tmphash,
	struct suq_user_stats_info *ui)
{
	struct suq_user_stats_info *user;
	struct hlist_head *slot;
	struct hlist_node *hnode;

	if (ui->dev[0] == 0)
		return NULL;

	slot = &tmphash[XXH32(ui->mac, sizeof(ui->mac), 0) & SUQ_USER_HASH_MASK];

	hlist_for_each_entry(user, hnode, slot, hnode) {
		if (memcmp(user->mac, ui->mac, sizeof(ui->mac)) == 0) {
			return NULL;
		}
	}

	return slot;
}

static int suq_user_stats_info_compare(const void *lhs, const void *rhs)
{
	const struct suq_user_stats_info *ua, *ub;

	ua = lhs;
	ub = rhs;
	return (ub->xmit_rate + ub->recv_rate) - (ua->xmit_rate + ua->recv_rate);
}

static int suq_user_stats_report(struct suq_user_stats *us, char *buf, size_t size)
{
	struct suq_user_stats_info *ui;
	struct suq_user_stats_info *user;
	struct hlist_head *slot;
	int i;
	int latest_index;
	int nr_users = 0;
	int nr_bytes = 0;

	mutex_lock(&us->mutex);

	spin_lock_bh(&us->lock);
	memcpy(us->tmpres, us->result, sizeof(us->result));
	latest_index = us->latest_index;
	spin_unlock_bh(&us->lock);

	for (i = 0; i < SUQ_USER_STATS_MAX; i++) {
		ui = &us->tmpres[latest_index++];
		if (latest_index == SUQ_USER_STATS_MAX)
			latest_index = 0;
		slot = suq_user_stats_tmphash_insert(us->tmphash, ui);
		if (slot != NULL) {
			user = &us->tmpusers[nr_users++];
			*user = *ui;		
			hlist_add_head(&user->hnode, slot);
		}		
	}

	memset(us->tmphash, 0, sizeof(us->tmphash));

	SUQ_DEBUG("report users: %d", nr_users);

	sort(us->tmpusers, nr_users, sizeof(*user),
		suq_user_stats_info_compare, NULL);

	for (i = 0; i < nr_users; i++) {
		user = &us->tmpusers[i];
	#if 0
		SUQ_DEBUG("%8u %8u %9llu %9llu "_MAC_FMT" %5s "_IP_FMT,
			user->xmit_rate, user->recv_rate,
			user->xmit_total, user->recv_total,
			_MAC_VAL(user->mac), user->dev, _IP_VAL(user->ip));
	#endif
		if (size >= 60) {
			int ret = sprintf(buf, "%8u %8u %9llu %9llu "_MAC_FMT" %5s "_IP_FMT"\n",
				user->xmit_rate, user->recv_rate,
				user->xmit_total, user->recv_total,
				_MAC_VAL(user->mac), user->dev, _IP_VAL(user->ip));
			nr_bytes += ret;
			buf += ret;
			size -= ret;
		}
	}

	mutex_unlock(&us->mutex);

	return nr_bytes;
}

static int suq_param_get_user_stats(char *valstr, struct kernel_param *kp)
{
	return suq_user_stats_report(&suq.user_stats, valstr, 4096);
}

module_param_call(user_stats, NULL, suq_param_get_user_stats, NULL, 0400);
