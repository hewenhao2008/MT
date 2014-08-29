#pragma once

#include <stddef.h>
#include "sstr.h"

void register_request_get_handler(const char *key, int (* cb)(sstr_t *reply));
void register_request_set_handler(const char *key, int (* cb)(sstr_t request, sstr_t *reply));
void start_ap_client();
