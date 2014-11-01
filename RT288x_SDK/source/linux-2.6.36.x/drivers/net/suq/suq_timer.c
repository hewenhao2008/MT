#include "suq_timer.h"


void suq_timer_entry_init(
	struct suq_timer_entry *entry,
	suq_timer_callback cb,
	void *data)
{
	INIT_LIST_HEAD(&entry->list);
	entry->cb = cb;
	entry->data = data;
}

void suq_timer_mod(
	struct suq_timer *timer,
	struct suq_timer_entry *entry,
	unsigned long expire_jiffies)
{
	struct list_head *vec_list;

	vec_list = timer->vec + (expire_jiffies & SUQ_TIMER_VEC_MASK);

	spin_lock_bh(&timer->lock);
	entry->expires = expire_jiffies;
	if (!list_empty(&entry->list)) {
		list_del(&entry->list);
	}
	list_add_tail(&entry->list, vec_list);
	spin_unlock_bh(&timer->lock);
}

void suq_timer_del(struct suq_timer *timer, struct suq_timer_entry *entry)
{
	spin_lock_bh(&timer->lock);
	if (!list_empty(&entry->list)) {
		list_del_init(&entry->list);
	}
	spin_unlock_bh(&timer->lock);
}

static void suq_timer_func(unsigned long data)
{
	struct suq_timer *timer = (void *)data;

	struct list_head *vec_list;
	struct list_head work_list;
	struct suq_timer_entry *entry, *next_entry;
	unsigned long vec_jiffies;

	spin_lock_bh(&timer->lock);

	while (time_before_eq(timer->jiffies, jiffies)) {
		vec_list = timer->vec + (timer->jiffies++ & SUQ_TIMER_VEC_MASK);
		if (!list_empty(vec_list)) {
			list_replace_init(vec_list, &work_list);
			vec_jiffies = timer->jiffies - 1;
			list_for_each_entry_safe(entry, next_entry, &work_list, list) {
				if (entry->expires == vec_jiffies) {
					list_del_init(&entry->list);
					spin_unlock_bh(&timer->lock);
					entry->cb(entry);
					spin_lock_bh(&timer->lock);
				} else {
					list_add_tail(&entry->list, vec_list);
				}
			}
		}
	}

	spin_unlock_bh(&timer->lock);

	mod_timer(&timer->ktimer, jiffies + 1);
}

void suq_timer_init(struct suq_timer *timer)
{
	int i;

	spin_lock_init(&timer->lock);

	timer->jiffies = jiffies;

	for (i = 0; i <= SUQ_TIMER_VEC_MASK; i++) {
		INIT_LIST_HEAD(timer->vec + i);
	}

	setup_timer(&timer->ktimer, suq_timer_func, (unsigned long)timer);
	mod_timer(&timer->ktimer, jiffies + 1);
}

void suq_timer_cleanup(struct suq_timer *timer)
{
	del_timer_sync(&timer->ktimer);
}

