#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <errno.h> 
#include <syslog.h>
#include <poll.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string>
#include <vector>
#include <map>
#include "mongoose.h" 
#include "cJSON.h"
using namespace std;

static int exit_flag; 
static const char *s_default_document_root = "/tmp/webui";
static const char *s_default_listening_port = "80"; 

static void signal_handler(int sig_num) {
  // Reinstantiate signal handler
  signal(sig_num, signal_handler);

#ifndef _WIN32
  // Do not do the trick with ignoring SIGCHLD, cause not all OSes (e.g. QNX)
  // reap zombies if SIGCHLD is ignored. On QNX, for example, waitpid()
  // fails if SIGCHLD is ignored, making system() non-functional.
  if (sig_num == SIGCHLD) {
    do {} while (waitpid(-1, &sig_num, WNOHANG) > 0);
  } else
#endif
  { exit_flag = sig_num; }
}


#define DEBUG_LINE do{fprintf(stderr, "%s %d\n", __FILE__, __LINE__);}while(0)

struct server_st { 
	int sock; 
	struct sockaddr_in addr;  
};

typedef int (*request_func)(struct mg_connection *conn, void *param);
typedef int (*response_func)(struct mg_connection *conn, void *param);

struct uri_handler {
	const char *postfix;
	int len;
	request_func request; 
};

struct response_callback {
	struct mg_connection *conn;
	response_func func;
	time_t cache_time;
};

struct cjson_result {
	cJSON *root;
	time_t cache_time;
};

struct ev_param {
	map<unsigned int, response_callback> request_map;
	map<unsigned int, cjson_result> response_map;
	unsigned int 	cur_seq;
	time_t 			clear_time;
};

struct server_st s_server = {0};

static const char *s_cmd_apinfo = "apif";
static const char *s_cmd_aplogin = "aplg";
static const char *s_cmd_smslogin = "smlg";

static inline void set_response_callback(response_callback *rcb, struct mg_connection *conn, response_func func) {
	rcb->conn = conn;
	rcb->func = func;
	rcb->cache_time = time(NULL);
}

static inline void set_cjson_result(cjson_result *cres, cJSON *root) {
	cres->root = root;
	cres->cache_time = time(NULL);
}

static int get_ap_info(struct mg_connection *conn, void *param);
static int cloud_login(struct mg_connection *conn, void *param);
static int sms_login(struct mg_connection *conn, void *param);

static uri_handler s_uri_handler[] = {
	{"/cloudlogin", sizeof("/cloudlogin") - 1, cloud_login},
	{"/getInfo2CloudAuth", sizeof("/getInfo2CloudAuth") - 1, get_ap_info}, 
	{"/PhoneNo", sizeof("/PhoneNo") - 1, sms_login}, 
};

static int parse_json(const char *res_json, void *param) {
	int ret;
	ev_param *evp;
	cJSON *root, *data_root, *seq_item; 
	map<unsigned int, cjson_result>::iterator it;
	//fprintf(stderr, "result json %s\n", res_json);
	root = cJSON_Parse(res_json);
	if (!root) {
		syslog(LOG_ERR, "parse json fail %s\n", res_json);
		return -1;
	}
	
	data_root = cJSON_GetObjectItem(root, "Data");
	if (!data_root || data_root->type != cJSON_Object)
		goto error_release;
	
	seq_item = cJSON_GetObjectItem(data_root, "Seq");
	if (!seq_item || seq_item->type != cJSON_Number) 
		goto error_release;
	
	evp = (ev_param *)param;
	it = evp->response_map.find(seq_item->valueint);
	if (it != evp->response_map.end()) {
		syslog(LOG_ERR, "already cache %d in response_map, replace \n", seq_item->valueint);
		cJSON_Delete(it->second.root);
	}
	
	{
	cjson_result cres;
	set_cjson_result(&cres, root);
	evp->response_map[seq_item->valueint] = cres;	/* release after */
	fprintf(stderr, "result json %d %d\n", evp->response_map.size(), evp->request_map.size());
	}
	/* not release here!!! */
	return 0;
error_release:
	syslog(LOG_ERR, "error res_json %s\n", res_json);
	cJSON_Delete(root);
	return -1;
}

static void recieve_result(void *param) {
	int ret; 
	char buf[2048];
	struct pollfd pfd;
	struct sockaddr client; 
	socklen_t sock_len;
	
	pfd.fd = s_server.sock; 
	pfd.events = POLLIN|POLLPRI;
	while (true) {
		ret = poll(&pfd, 1, 0);
		if (ret <= 0)  
			break;
		
		if (!((pfd.revents & POLLIN) || (pfd.revents & POLLPRI)))
			continue;

		sock_len = sizeof(client); 
		ret = recvfrom(pfd.fd, buf, sizeof(buf) - 1, 0, (struct sockaddr *)&client, &sock_len);
		if (ret <= 0 || sock_len != sizeof(client)) {
			syslog(LOG_ERR, "recvfrom fail %d %d errno %d\n", sock_len, sizeof(client), errno);
			continue;
		}
		buf[sizeof(buf) - 1] = buf[ret] = 0;

		parse_json(buf, param);
	} 
}

static void remove_timeout(void *param) {
	ev_param *evp = (ev_param *)param;
	int timeout = 120;
	time_t now = time(NULL);
	map<unsigned int, cjson_result>::iterator cit; 
	map<unsigned int, response_callback>::iterator rit;
	
	if (now >= evp->clear_time && now - evp->clear_time < timeout)
		return;
		
	printf("clear timeout items %d\n", now - evp->clear_time);
	evp->clear_time = now;
	for (rit = evp->request_map.begin(); rit != evp->request_map.end();) {
		if (now < rit->second.cache_time || now - rit->second.cache_time > timeout) {
			syslog(LOG_ERR, "timeout request_map %d %d %d %d\n", timeout, now, rit->second.cache_time, now - rit->second.cache_time);
			evp->request_map.erase(rit++);
			continue;
		}
		rit++;
	}
	
	for (cit = evp->response_map.begin(); cit != evp->response_map.end(); ) {
		if (now < cit->second.cache_time || now - cit->second.cache_time > timeout) {
			syslog(LOG_ERR, "timeout response_map %d %d %d %d\n", timeout, now, cit->second.cache_time, now - rit->second.cache_time);
			cJSON_Delete(cit->second.root); 	/* delete cjson instance */
			evp->response_map.erase(cit++);
			continue;
		}
		cit++;
	}
}

static int ev_handler(struct mg_connection *conn, enum mg_event ev) {
	recieve_result(conn->server_param); 	/* try recieve */
	switch (ev) {
	case MG_REQUEST:
		{
			const char *pos = conn->uri;
			int urilen = strlen(pos); 
			for (int i = 0; i < (int)(sizeof(s_uri_handler)/sizeof(s_uri_handler[0])); i++) { 
				if (urilen == s_uri_handler[i].len && !strncmp(pos, s_uri_handler[i].postfix, urilen)) { 
					//fprintf(stderr, "%s\n", pos);
					return s_uri_handler[i].request(conn, conn->server_param);
				}
			}
			return MG_FALSE;
		}
		break;
	case MG_POLL:
		{
			ev_param *evp = (ev_param *)conn->server_param;
			map<unsigned int, cjson_result>::iterator cit; 
			
			for (cit = evp->response_map.begin(); cit != evp->response_map.end(); cit++) {
				map<unsigned int, response_callback>::iterator rit = evp->request_map.find(cit->first);
				if (rit == evp->request_map.end()) {
					syslog(LOG_ERR, "LOGICAL ERROR!!! cannot find %u in request map\n", cit->first);
					continue;
				}
				if (conn != rit->second.conn)
					continue;
				
				rit->second.func(conn, cit->second.root);
				cJSON_Delete(cit->second.root); 	/* delete cjson instance */
				/* remove item had been processed */
				fprintf(stderr, "remove %s %d %d, return MG_FALSE\n", conn->uri, evp->response_map.size(), evp->request_map.size());
				evp->response_map.erase(cit);
				evp->request_map.erase(rit);
				return MG_TRUE;
			}
			return MG_MORE;
		}
		break;
	case MG_CLOSE:
		{
			ev_param *evp = (ev_param *)conn->server_param;
			map<unsigned int, response_callback>::iterator rit; 
			for (rit = evp->request_map.begin(); rit != evp->request_map.end(); rit++) {
				if (rit->second.conn != conn)
					continue;
				map<unsigned int, cjson_result>::iterator cit = evp->response_map.find(rit->first);
				if (cit != evp->response_map.end()) {
					cJSON_Delete(cit->second.root); 	/* delete cjson instance */
					evp->response_map.erase(cit);
				}
				fprintf(stderr, "remove seq %u\n", rit->first);
				evp->request_map.erase(rit);
				break;
			}
			return MG_FALSE;
		}
		break;
	default:
		break;
	}
	remove_timeout(conn->server_param);
	return MG_FALSE;
}

static int init_socket()
{
	int  sock; 
    bzero(&s_server.addr, sizeof(s_server.addr));
    s_server.addr.sin_family = AF_INET;  
    s_server.addr.sin_addr.s_addr = inet_addr("127.0.0.1");  
    s_server.addr.sin_port = htons(9999);   
	
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		syslog(LOG_ERR, "socket fail, errno %d\n", errno);
		return -1;
	}

	s_server.sock = sock;
	return 0;
}

static void set_daemon() {
	printf("start as daemon\n");
	if (daemon(1, 1) == -1) {
		fprintf(stderr, "daemon fail, errno %d\n", errno);
		exit(-1);
	}
}

int main(int argc, char *argv[]) {
	if (access(s_default_document_root, 0)) {
		fprintf(stderr, "%s not exist!\n", s_default_document_root);
		exit(-1);
	}
	if (argc <= 1 || strncmp(argv[1], "-d", 2))
		set_daemon();
		
	if (init_socket()) {
		syslog(LOG_ERR, "init socket fail\n");
		exit(-1);
	}
	
	ev_param evp;
	evp.cur_seq = 0;
	evp.clear_time = time(NULL);
	struct mg_server *server = mg_create_server(&evp, ev_handler);
	if (!server) {
		syslog(LOG_ERR, "mg_create_server fail\n");
		exit(-1);
	}
	mg_set_option(server, "listening_port", s_default_listening_port);
	mg_set_option(server, "document_root", s_default_document_root); 
	
	printf("serving [%s] on port %s\n", mg_get_option(server, "document_root"), mg_get_option(server, "listening_port"));
	fflush(stdout);  // Needed, Windows terminals might not be line-buffered 
	while (exit_flag == 0) {
		mg_poll_server(server, 1000);
	}
	printf("Exiting on signal %d ...", exit_flag);
	fflush(stdout);
	mg_destroy_server(&server);
	printf("%s\n", " done.");
   
	return 0;
}

static int ap_info_response(struct mg_connection *conn, void *param) {
	cJSON *tmp_item[4];
	cJSON *root, *cmd_item, *data_root, *mac_item, *ugwid_item, *account_item, *ssid_item;
	
	root = (cJSON *)param;
	if (!root) {
		mg_printf_data(conn, "{1}");
		return -1;
	}
	
	cmd_item = cJSON_GetObjectItem(root, "Cmd");
	data_root = cJSON_GetObjectItem(root, "Data");
	if (!cmd_item || cmd_item->type != cJSON_String || strncmp(cmd_item->valuestring, s_cmd_apinfo, strlen(s_cmd_apinfo))) {
		mg_printf_data(conn, "{2}");
		return -1;
	}
	if (!data_root || data_root->type != cJSON_Object){
		mg_printf_data(conn, "{3}");
		return -1;
	}
	
	int i = 0;
	mac_item = cJSON_GetObjectItem(data_root, "Mac");			tmp_item[i++] = mac_item;
	ugwid_item = cJSON_GetObjectItem(data_root, "Ugwid");		tmp_item[i++] = ugwid_item;
	account_item = cJSON_GetObjectItem(data_root, "Account");	tmp_item[i++] = account_item;
	ssid_item = cJSON_GetObjectItem(data_root, "Ssid");			tmp_item[i++] = ssid_item;
	for (i = 0; i < 4; i++) { 
		if (!tmp_item[i] || tmp_item[i]->type != cJSON_String) {
			syslog(LOG_ERR, "item type invalid %d\n", i);
			mg_printf_data(conn, "%s", "cannot find result");
			return -1;
		}
	}
	mg_printf_data(conn, "{\"%s\":\"%s\", \"%s\":\"%s\", \"%s\":\"%s\", \"%s\":\"%s\", \"%s\":\"%s\"}", 
		"ip", conn->remote_ip,
		"mac", mac_item->valuestring,
		"ugwid", ugwid_item->valuestring,
		"account", account_item->valuestring,
		"ssid", ssid_item->valuestring);
	/*fprintf(stderr, "---{\"%s\":\"%s\", \"%s\":\"%s\", \"%s\":\"%s\", \"%s\":\"%s\", \"%s\":\"%s\"}\n", 
		"ip", conn->remote_ip,
		"mac", mac_item->valuestring,
		"ugwid", ugwid_item->valuestring,
		"account", account_item->valuestring,
		"ssid", ssid_item->valuestring);*/
	return 0;
}

static int get_ap_info(struct mg_connection *conn, void *param) {
	cJSON *root, *data;
	int json_len, ret; 
	char *json_str;
	unsigned int seq; 
	ev_param *evp;
	
	evp = (ev_param *)param;
	seq = evp->cur_seq + 1; 
	root = cJSON_CreateObject(); 
	data = cJSON_CreateObject(); 
	cJSON_AddStringToObject(root, "Cmd", s_cmd_apinfo);
	
	cJSON_AddNumberToObject(data, "Seq", seq); 
	cJSON_AddStringToObject(data, "Ip", conn->remote_ip); 
	cJSON_AddItemToObject(root, "Data", data);
	json_str = cJSON_Print(root);
	cJSON_Delete(root); 
	json_len = strlen(json_str); 
	//printf("get_ap_info %s\n", json_str);
	ret = sendto(s_server.sock, json_str, json_len, 0, (struct sockaddr*)&s_server.addr, sizeof(struct sockaddr_in));
	free(json_str);
	if (ret != json_len) {
		syslog(LOG_ERR, "sendto fail %d %d %d errno %d\n", s_server.sock, ret, json_len, errno); 
		mg_printf_data(conn, "%s", "send to fail"); 
		return MG_FALSE;
	}
	evp->cur_seq = seq;
	response_callback rcb;
	set_response_callback(&rcb, conn, ap_info_response); 
	evp->request_map[seq] = rcb;
	fprintf(stderr, "add for ap info %d %d\n", evp->response_map.size(), evp->request_map.size());
	return MG_MORE; 
}

static int cloud_login_response(struct mg_connection *conn, void *param) {
	const char *detail = "";
	cJSON *root, *cmd_item, *data_root, *code_item, *reason_item; 
	
	root = (cJSON *)param;
	if (!root)
		return -1;
	
	cmd_item = cJSON_GetObjectItem(root, "Cmd");
	data_root = cJSON_GetObjectItem(root, "Data");
	if (!cmd_item || cmd_item->type != cJSON_String || strncmp(cmd_item->valuestring, s_cmd_aplogin, strlen(s_cmd_aplogin))) 
		return -1;
	if (!data_root || data_root->type != cJSON_Object)
		return -1;
	
	code_item = cJSON_GetObjectItem(data_root, "Code");
	reason_item = cJSON_GetObjectItem(data_root, "Detail");
	
	if (!code_item || code_item->type != cJSON_String)
		return -1;
	if (reason_item && reason_item->type == cJSON_String)
		detail = reason_item->valuestring;
	fprintf(stderr, "login res %s %s", code_item->valuestring, detail); 
	mg_printf_data(conn, "%s %s", code_item->valuestring, detail);  
	return 0;
}

static int cloud_login(struct mg_connection *conn, void *param) {
	int json_len, ret;
	char *json_str;
	cJSON *root, *data;
	unsigned int seq, *ip;
	char buf[100];
	unsigned int tmp[4];
	ev_param *evp;
	string user, password, ssid;
	
    mg_get_var(conn, "UserName", buf, sizeof(buf)); 	
	user = buf;
	mg_get_var(conn, "Password", buf, sizeof(buf)); 	
	password = buf;
	mg_get_var(conn, "Ssid", buf, sizeof(buf)); 	
	ssid = buf;
	if (user.empty() || password.empty())
		return MG_FALSE;
	if (ssid.empty())
		ssid = "error_ssid_httpauth";
	ret = sscanf(conn->remote_ip, "%d.%d.%d.%d", &tmp[0], &tmp[1], &tmp[2], &tmp[3]);
	if (ret != 4) {
		syslog(LOG_ERR, "invalid ip 2 %d %s\n", ret, conn->remote_ip);
		mg_printf_data(conn, "%s", "get remote ip fail 2");
		return MG_FALSE;
	}
	for (int i = 0; i < 4; i++)	buf[i] = tmp[i];
	ip = (unsigned int *)buf; 

	evp = (ev_param *)param;
	seq = evp->cur_seq + 1; 
	
	root = cJSON_CreateObject(); 
	data = cJSON_CreateObject(); 
	cJSON_AddStringToObject(root, "Cmd", s_cmd_aplogin);
	
	cJSON_AddNumberToObject(data, "Seq", seq);  
	cJSON_AddStringToObject(data, "Ip", conn->remote_ip); 
	cJSON_AddStringToObject(data, "UserName", user.c_str());
	cJSON_AddStringToObject(data, "Password", password.c_str());
	cJSON_AddStringToObject(data, "Ssid", ssid.c_str());
	
	cJSON_AddItemToObject(root, "Data", data);
	
	json_str = cJSON_Print(root); 
	cJSON_Delete(root);
	json_len = strlen(json_str);
	fprintf(stderr, "cloud login %s \n", json_str);
	ret = sendto(s_server.sock, json_str, json_len, 0, (struct sockaddr*)&s_server.addr, sizeof(struct sockaddr_in));
	free(json_str);
	if (ret != json_len) {
		syslog(LOG_ERR, "sendto fail %d %d %d errno %d\n", s_server.sock, ret, json_len, errno);
		mg_printf_data(conn, "%s", "202 login fail");
		return MG_FALSE;
	}
	evp->cur_seq = seq;
	response_callback rcb;
	set_response_callback(&rcb, conn, cloud_login_response); 
	evp->request_map[seq] = rcb;
	return MG_MORE; 
}	

static int sms_response(struct mg_connection *conn, void *param) {
	const char *detail = "";
	cJSON *root, *cmd_item, *data_root, *code_item, *reason_item; 
	
	root = (cJSON *)param;
	if (!root)
		return -1;
	
	cmd_item = cJSON_GetObjectItem(root, "Cmd");
	data_root = cJSON_GetObjectItem(root, "Data");
	if (!cmd_item || cmd_item->type != cJSON_String || strncmp(cmd_item->valuestring, s_cmd_smslogin, strlen(s_cmd_smslogin))) 
		return -1;
	if (!data_root || data_root->type != cJSON_Object)
		return -1;
	
	code_item = cJSON_GetObjectItem(data_root, "Code");
	reason_item = cJSON_GetObjectItem(data_root, "Detail");
	
	if (!code_item || code_item->type != cJSON_String)
		return -1;
	if (reason_item && reason_item->type == cJSON_String)
		detail = reason_item->valuestring;
	fprintf(stderr, "login res %s %s", code_item->valuestring, detail); 
	mg_printf_data(conn, "%s", detail);  
	return 0;
}

static int sms_login(struct mg_connection *conn, void *param) {
	int json_len, ret;
	char *json_str;
	cJSON *root, *data;
	unsigned int seq;
	char buf[100];
	ev_param *evp;

	string user, ssid;
	mg_get_var(conn, "UserName", buf, sizeof(buf)); 	
	user = buf;
	mg_get_var(conn, "Ssid", buf, sizeof(buf)); 	
	ssid = buf;

	
	evp = (ev_param *)param;
	seq = evp->cur_seq + 1; 
	
	root = cJSON_CreateObject(); 
	data = cJSON_CreateObject(); 
	cJSON_AddStringToObject(root, "Cmd", s_cmd_smslogin);
	
	cJSON_AddNumberToObject(data, "Seq", seq);   
	cJSON_AddStringToObject(data, "UserName", user.c_str());
	cJSON_AddStringToObject(data, "Ip", conn->remote_ip);
	cJSON_AddStringToObject(data, "Ssid", ssid.c_str());
	
	cJSON_AddItemToObject(root, "Data", data);

	json_str = cJSON_Print(root); 
	cJSON_Delete(root);
	json_len = strlen(json_str);
	fprintf(stderr, "sms login %s \n", json_str);
	
	ret = sendto(s_server.sock, json_str, json_len, 0, (struct sockaddr*)&s_server.addr, sizeof(struct sockaddr_in));
	free(json_str);
	if (ret != json_len) {
		syslog(LOG_ERR, "sendto fail %d %d %d errno %d\n", s_server.sock, ret, json_len, errno);
		mg_printf_data(conn, "%s", "202 login fail");
		return MG_FALSE;
	}
	
	evp->cur_seq = seq;
	response_callback rcb;
	set_response_callback(&rcb, conn, sms_response); 
	evp->request_map[seq] = rcb;
	return MG_MORE; 
}
