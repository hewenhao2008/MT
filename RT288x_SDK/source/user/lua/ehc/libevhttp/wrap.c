#include <iostream>
#include <map>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <unistd.h>
#include <string.h>

#include "ev.h"
#include "wrap.h"
#include "evhttpclient.h"
using namespace std;

typedef struct ev_http {
	int timeout;
	map<string, string> header;
} ev_http;

struct ev_http *evhttp_create() {
	struct ev_http *ins = new ev_http;
	ins->timeout = 10;
	return ins;
}

void evhttp_set_timeout(struct ev_http *eh, int timeout) {
	eh->timeout = timeout;
}

void evhttp_destroy(struct ev_http *eh) {
	delete eh;
}

void evhttp_set_header(struct ev_http *eh, const char *key, const char *value) {
	if (key && value)
		eh->header[key] = value;
	else if (key && !value)
		eh->header.erase(key);
}

struct param {
	EvHttpClient *client; 
	response_callback cb;
	struct ev_http *eh;
	const char *content;
};

void response_cb(ResponseInfo *response, void *requestData, void *clientData) {
	param *pa = (param *)requestData;
	if (!response) {
		fprintf(stderr, "response null\n");
		exit(-1);
	}
	if (response->timeout)
		return pa->cb(1, NULL, 0);
	return pa->cb(0, response->response.data(), response->response.length());
}

void timer_cb(struct ev_loop *loop, struct ev_timer *timer, int revents) {
	param *pa;
	EvHttpClient *client; 
	
	pa = (param *)timer->data;
	client = pa->client; 
	
	int ret = client->makePost(response_cb, "", pa->eh->header, pa->content, pa); 
	
	if (ret < 0) {
		fprintf(stderr, "make post fail\n");
		exit(-1);
	}
	
}
typedef void (*response_callback)(int timeout, const char *data, int data_len);
void evhttp_post(struct ev_http *eh, const char *url, const char *content, response_callback cb) {
	struct ev_loop *loop = ev_default_loop(0);
	EvHttpClient client(loop, url, eh->timeout, NULL, 1);
	struct ev_timer timer;
	
	param pa;
	pa.client = &client;
	pa.cb = cb;
	pa.eh = eh;
	pa.content = content;
	
	timer.data = &pa;
	ev_timer_init(&timer, timer_cb, 0.001, 0.0);
	ev_timer_start(loop, &timer);
	
	while (1) {
		ev_loop(loop, 0);
	}
}
