#pragma once

#include "suq.h"

void suq_user_stats_init(struct suq_user_stats *us);

void suq_user_stats_cleanup(struct suq_user_stats *us);

void suq_user_stats_update(
	struct suq_user_stats *us,
	struct suq_user *user,
	uint32_t xmit_rate,
	uint32_t recv_rate,
	uint64_t xmit_total,
	uint64_t recv_total);

