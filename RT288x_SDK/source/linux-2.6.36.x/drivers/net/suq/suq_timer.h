#pragma once


#include <linux/timer.h>
#include <linux/spinlock.h>


#define SUQ_TIMER_VEC_MASK	((1 << 8) - 1)


struct suq_timer_entry;

typedef void (*suq_timer_callback)(struct suq_timer_entry *timer_entry);

struct suq_timer_entry {
	unsigned long expires;
	struct list_head list;
	suq_timer_callback cb;
	void *data;
};

struct suq_timer {
	struct timer_list ktimer;
	spinlock_t lock;
	unsigned long jiffies;
	struct list_head vec[SUQ_TIMER_VEC_MASK + 1];
};


void suq_timer_entry_init(
	struct suq_timer_entry *entry,
	suq_timer_callback cb,
	void *data);

void suq_timer_init(struct suq_timer *timer);

void suq_timer_cleanup(struct suq_timer *timer);

void suq_timer_mod(
	struct suq_timer *timer,
	struct suq_timer_entry *entry,
	unsigned long expire_jiffies);

void suq_timer_del(struct suq_timer *timer, struct suq_timer_entry *entry);


