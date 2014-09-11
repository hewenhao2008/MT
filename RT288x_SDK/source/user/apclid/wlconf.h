#pragma once

#include <net/ethernet.h>

#include "iwlib.h"

typedef struct maclist{
	uint count;
	struct ether_addr ea[1];
} maclist_t;

int wl_sta_info(char *ifname, char *ea);
struct maclist* wl_sta_list(char *ifname);

int wlconf_main(int argc, char *argv[]);