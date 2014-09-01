#ifndef __EV_HTTP_WRAP_H__
#define __EV_HTTP_WRAP_H__

#ifdef __cplusplus
extern "C" {
#endif 
struct ev_http;
struct ev_http *evhttp_create();
void evhttp_destroy(struct ev_http *eh);
void evhttp_set_header(struct ev_http *eh, const char *key, const char *value);
void evhttp_set_timeout(struct ev_http *eh, int timeout);
typedef void (*response_callback)(int timeout, const char *data, int data_len);
void evhttp_post(struct ev_http *eh, const char *url, const char *content, response_callback cb); 
#ifdef __cplusplus
}
#endif 
#endif 
