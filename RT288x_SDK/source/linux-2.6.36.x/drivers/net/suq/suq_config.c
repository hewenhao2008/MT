#include "suq.h"


void suq_enable(void)
{

}

int suq_disable(void)
{
	return 0;
}


static int suq_param_set_uint(const char *valstr, struct kernel_param *kp)
{
	int (* fn)(uint32_t, char *) = kp->arg;
	uint32_t value;
	char tmp;

	if (sscanf(valstr, "%u %c", &value, &tmp) != 1) {
		size_t len = 0;
		const char *p = strrchr(valstr, '\n');
		if (p == NULL)
			len = strlen(valstr);
		else
			len = p - valstr;
		SUQ_ERROR("bad uint parameter: [%.*s]\n", (int)len, valstr);
		return -EINVAL;
	}
	
	return fn(value, NULL);
}

static int suq_param_get_uint(char *valstr, struct kernel_param *kp)
{
	int (* fn)(uint32_t, char *) = kp->arg;

	return fn(0, valstr);
}

#define SUQ_PARAM_UINT(name, min, max) \
	SUQ_PARAM_UINT_NAMED(name, name, min, max)

#define SUQ_PARAM_UINT_NAMED(name, valname, min, max) \
static int suq_param_set_##name(uint32_t value, char *valstr) \
{ \
	if (valstr != NULL) { \
		return sprintf(valstr, "%u", suq.config.valname); \
	} \
	if (value < (min) || value > (max)) { \
		SUQ_ERROR("bad " #name ": %u, out of range: [%d, %d]\n", value, (min), (max)); \
		return -EINVAL; \
	} \
	suq.config.valname = value; \
	SUQ_INFO(#name " set to %u\n", value); \
	return 0; \
} \
module_param_call(name, suq_param_set_uint, suq_param_get_uint, suq_param_set_##name, 0600)


SUQ_PARAM_UINT(max_backlog_packets,	0,	SUQ_BACKLOG_PACKETS_MAX);
SUQ_PARAM_UINT(latency_shift,		0,	SUQ_LATENCY_SHIFT_MAX);


#define SUQ_PARAM_SSID_RATE(index) \
	SUQ_PARAM_UINT_NAMED(ssid##index##_xmit_limit, rates[index].xmit_rate, 0, SUQ_BYTES_PER_SEC_MAX / HZ); \
	SUQ_PARAM_UINT_NAMED(ssid##index##_recv_limit, rates[index].recv_rate, 0, SUQ_BYTES_PER_SEC_MAX / HZ)

SUQ_PARAM_SSID_RATE(0);
SUQ_PARAM_SSID_RATE(1);
SUQ_PARAM_SSID_RATE(2);
SUQ_PARAM_SSID_RATE(3);


module_param_named(backlog_packets,	suq.backlog_packets,	uint,	0400);
//module_param_named(pending_users,	suq.timer.nr_pending,	ulong,	0400);


