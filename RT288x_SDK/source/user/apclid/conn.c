#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "apclid.h"
#include "conn.h"
#include "xxhash.h"
#include "lz4.h"


#define TIMEOUT_CONNECT 	1000
#define TIMEOUT_RECV_HEAD	1000
#define TIMEOUT_RECV_DATA	10000
#define TIMEOUT_SEND		10000
#define TIMEOUT_IDLE		12000

#define LOG(level, fmt, args...) syslog(level, "%s: "fmt, __FUNCTION__, ##args)
//#define LOG fprintf

struct message_hdr_base {
	uint16_t msg_type;
	uint16_t version;
};

struct message_header {
	uint32_t data_len;
	uint32_t check_sum;
};

struct message_header1 {
	uint32_t data_len;
	uint32_t check_sum;
	uint32_t orig_len;
};


enum {
	MSG_REQUEST 	= 1 << 0,
	MSG_REPLY 		= 1 << 1,
	MSG_KEEPALIVE 	= 1 << 2,
};

#define RESET_SOCK(sock) do {	\
	close(sock);				\
	sock = -1;					\
} while (0)

#define ERR_IF(expr, fmt, ...) do {				\
	if (expr) {									\
		LOG(LOG_ERR, fmt " [error: %s]\n",	\
				##__VA_ARGS__, strerror(errno));\
		goto err;								\
	}											\
} while (0)

#define IS_SPACE(x) ((x) == ' ' || (x) == '\t' || (x) == '\r' || (x) == '\n')

sstr_t str_ac_addr = SSTR_NULL;

const char *extract_field(const char *buf, const char *bufend, sstr_t *out)
{
	const char *p;
	const char *begin;
	const char *end;

	for (p = buf; p != bufend; p++) {
		if (!IS_SPACE(*p))
			break;
	}

	if (p == bufend)
		return NULL;

	begin = p;

	for (p = p + 1; p != bufend; p++) {
		if (IS_SPACE(*p))
			break;
	}

	end = p;

	*out = sstr_copy_buf(begin, end - begin);

	while (p != bufend && IS_SPACE(*p)) {
		p++;
	}

	return p;
}

int dial_n(int socktype, const struct sockaddr_in *sockaddr, int timeout_ms)
{
	int sock = -1;
	
	sock = socket(sockaddr->sin_family, socktype, 0);
	ERR_IF(sock < 0, "socket()");

	int flags = fcntl(sock, F_GETFL);
	ERR_IF(flags < 0, "fcntl(F_GETFL)");

	int ret = fcntl(sock, F_SETFL, flags | O_NONBLOCK);
	ERR_IF(ret < 0, "fcntl(F_SETFL, O_NONBLOCK)");

	ret = connect(sock, (const struct sockaddr *)sockaddr, sizeof(*sockaddr));
	if (ret < 0) {
		ERR_IF(errno != EINPROGRESS, "connect()");

		struct timeval tv;
		tv.tv_sec = timeout_ms / 1000;
		tv.tv_usec = timeout_ms % 1000 * 1000;

		fd_set wset;
		FD_ZERO(&wset);
		FD_SET(sock, &wset);

		ret = select(sock + 1, NULL, &wset, NULL, &tv);
		ERR_IF(ret < 0, "select() after connect()");

		if (ret == 0) {
			close(sock);
			return 0;
		}

		ERR_IF(!FD_ISSET(sock, &wset), "select() fd_set error");

		int sockerr;
		socklen_t sockerr_len = sizeof(sockerr);
		ret = getsockopt(sock, SOL_SOCKET, SO_ERROR, &sockerr, &sockerr_len);
		ERR_IF(ret < 0 || sockerr_len != sizeof(sockerr), "getsockopt(SO_ERROR)");
		if (sockerr != 0) {
			ERR_IF((errno = sockerr), "dial_n() failed");
		}
	}

	return sock;
err:
	if (sock >= 0) {
		close(sock);
	}
	return -1;
}

int dial_p(int socktype, const char *addr, uint16_t port, int timeout_ms)
{
	struct sockaddr_in sockaddr;
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = htons(port);
	if (inet_pton(sockaddr.sin_family, addr, &sockaddr.sin_addr) != 1) {
		LOG(LOG_ERR, "bad address: %s:%d\n", addr, (int)port);
		return -1;
	}
	return dial_n(socktype, &sockaddr, timeout_ms);
}

int recvfrom_n(int sock, void *data, size_t data_len, struct sockaddr_in *addr, int timeout_ms)
{
	struct timeval tv;
	tv.tv_sec = timeout_ms / 1000;
	tv.tv_usec = timeout_ms % 1000 * 1000;

	fd_set rset;
	FD_ZERO(&rset);
	FD_SET(sock, &rset);

	int ret = select(sock + 1, &rset, NULL, NULL, &tv);
	if (ret < 0) {
		LOG(LOG_ERR, "error: %s\n", strerror(errno));
		return -1;
	}
	if (ret == 0) {
		return 0; // timeout
	}
	if (!FD_ISSET(sock, &rset)) {
		LOG(LOG_ERR, "fd_set error\n");
		return -1;
	}

	socklen_t addr_len = sizeof(*addr);
	ret = recvfrom(sock, data, data_len, 0, (struct sockaddr *)addr, &addr_len);
	if (ret < 0) {
		LOG(LOG_ERR, "error when select() done: %s\n", strerror(errno));
		return -1;
	}
	if (addr_len != sizeof(*addr)) {
		LOG(LOG_ERR, "sockaddr mismatch\n");
		return -1;
	}
	if (ret != data_len) {
		LOG(LOG_ERR, "incomplete: %d/%d\n", ret, (int)data_len);
		return -1;
	}
	return data_len;
}

static int recv_n(int sock, void *data, size_t data_len, int timeout_ms)
{
	struct timeval tv;
	tv.tv_sec = timeout_ms / 1000;
	tv.tv_usec = timeout_ms % 1000 * 1000;

	fd_set rset;
	FD_ZERO(&rset);
	FD_SET(sock, &rset);

	int data_left = (int)data_len;

	while (data_left != 0) {
		int ret = select(sock + 1, &rset, NULL, NULL, &tv);
		if (ret < 0) {
			LOG(LOG_ERR, "error: %s\n", strerror(errno));
			return -1;
		}
		if (ret == 0) {
			return 0; // timeout
		}
		if (!FD_ISSET(sock, &rset)) {
			LOG(LOG_ERR, "fd_set error\n");
			return -1;
		}

		ret = recv(sock, data, data_left, 0);
		if (ret < 0) {
			LOG(LOG_ERR, "error when select() done: %s\n", strerror(errno));
			return -1;
		}

		if (ret == 0)
			return 0;

		data = (char *)data + ret;
		data_left -= ret;
	}

	return data_len;
}

static int send_n(int sock, const void *data, size_t data_len, int timeout_ms)
{
	struct timeval tv;
	tv.tv_sec = timeout_ms / 1000;
	tv.tv_usec = (timeout_ms % 1000) * 1000;

	fd_set wset;
	FD_ZERO(&wset);
	FD_SET(sock, &wset);

	int data_left = (int)data_len;

	while (data_left != 0) {
		int ret = select(sock + 1, NULL, &wset, NULL, &tv);
		if (ret < 0) {
			LOG(LOG_ERR, "error: %s\n", strerror(errno));
			return -1;
		}
		if (ret == 0) {
			return 0; // timeout
		}
		if (!FD_ISSET(sock, &wset)) {
			LOG(LOG_ERR, "fd_set error\n");
			return -1;
		}

		ret = send(sock, data, data_left, MSG_NOSIGNAL);
		if (ret < 0) {
			LOG(LOG_ERR, "error when select() done: %s\n", strerror(errno));
			return -1;
		}

		data = (char *)data + ret;
		data_left -= ret;
	}

	return data_len;
}

static void chap_message(uint8_t *buf, uint32_t len)
{
	int i;
	extern unsigned int ap_chap;
	extern void init_ap_chap();

	if(ap_chap == 0) {
		//第一次被调用是GET MAC 的返回, 所以不要加密.
		init_ap_chap();
		return;
	}

	for (i=0; i<len; i++) {
		buf[i] = buf[i] ^ (uint8_t)(ap_chap>>(i%4));
	}
}

#define MAX_TRANS_BUFF (1024 * 1024)
static int recv_message(int sock, uint32_t *msg_type, char **data)
{
	int ret;

	struct message_hdr_base hdr;
	ret = recv_n(sock, &hdr, sizeof(hdr), TIMEOUT_RECV_HEAD);
	if(ret <= 0) {
		return ret; //time out
	}
	*msg_type = hdr.msg_type;
	if(hdr.version == 0) {
		//get mac, 特殊调用未加密
		struct message_header hdr0;
		ret = recv_n(sock, &hdr0, sizeof(hdr0), TIMEOUT_RECV_HEAD);
		if(ret <=0) {
			return ret;
		}
		if(hdr0.data_len > MAX_TRANS_BUFF) {
			LOG(LOG_ERR, "ver0 hdr len:%d\n", hdr0.data_len);
			return -1;
		}
		char *buf = malloc(hdr0.data_len);
		if (!buf) {
			LOG(LOG_ERR, "oom hdr0, size:%d\n", hdr0.data_len);
			return -1;
		}
		ret = recv_n(sock, buf, hdr0.data_len, TIMEOUT_RECV_DATA);
		if (ret <= 0) {
			free(buf);
			LOG(LOG_ERR, "hdr0 data failed %d\n", ret);
			return -1;
		}
		if (hdr0.check_sum != XXH32(buf, (int)hdr0.data_len, 0)) {
			free(buf);
			LOG(LOG_ERR, "hdr0 bad checksum\n");
			return -1;
		}

		*data = buf;
		return hdr0.data_len;
	}

	//加密协议V1版本
	struct message_header1 msghdr;
	ret = recv_n(sock, &msghdr, sizeof(msghdr), TIMEOUT_RECV_HEAD);
	if (ret <= 0) {
		return ret; // ret == 0 => timeout
	}

	if (msghdr.data_len > MAX_TRANS_BUFF) {//1M
		LOG(LOG_ERR, "message too len: %d,%d\n", msghdr.data_len, msghdr.orig_len);
		return -1;
	}

	char *buf = malloc(msghdr.data_len);
	if (buf == NULL) {
		LOG(LOG_ERR, "oom\n");
		return -1;
	}
	
	ret = recv_n(sock, buf, msghdr.data_len, TIMEOUT_RECV_DATA);
	if (ret <= 0) {
		free(buf);
		LOG(LOG_ERR, "recv data failed %d\n", ret);
		return -1;
	}

	if (msghdr.check_sum != XXH32(buf, (int)msghdr.data_len, 0)) {
		free(buf);
		LOG(LOG_ERR, "bad checksum\n");
		return -1;
	}

	if(hdr.version != 1) {
		LOG(LOG_ERR, "version[%hu]\n", hdr.version);
		free(buf);
		return -1;
	}

	if (msghdr.orig_len > MAX_TRANS_BUFF) {
		LOG(LOG_ERR, "ori len too large: %hu\n", msghdr.orig_len);
		free(buf);
		return -1;
	}
	//dechap message
	chap_message((unsigned char*)buf, msghdr.data_len);

	//ROY 解压数据(解密)
	int nsize = msghdr.orig_len * 2;
	char *nbuf = malloc(nsize);
	if (nbuf == NULL) {
		LOG(LOG_ERR, "malloc out buffer failed, size(%d)\n", nsize);
		free(buf);
		return -1;
	}
	nsize = LZ4_decompress_safe(buf, nbuf, (int)msghdr.data_len, nsize);
	if (nsize != msghdr.orig_len) {
		LOG(LOG_ERR, "decompress failed, len[%d, %d], osize[%d]\n", 
			(int)msghdr.data_len, (int)msghdr.orig_len, nsize);
		free(buf);
		return -1;
	}
	free(buf);

	if (hdr.msg_type != MSG_KEEPALIVE) {
		fprintf(stderr, "message: %x [%.*s]\n",
			(int)hdr.msg_type, (nsize < 32 ? nsize : 32), nbuf);
	}

	//返回值
	*data = nbuf;
	return nsize;
}

static int send_message(int sock, uint32_t msg_type, const char *data, size_t data_len)
{
	int ret;
	size_t msglen;
	char *msgbuf, *msgdata;
	struct message_hdr_base *hdr;
	struct message_header1 *msghdr;

	//ROY 压缩数据(加密)
	int nsize;
	int maxOsize = LZ4_compressBound(data_len);

	msglen = sizeof(struct message_hdr_base) + sizeof(struct message_header1) + maxOsize;
	msgbuf = malloc(msglen);
	if (msgbuf == NULL) {
		LOG(LOG_ERR, "(%d) oom.\n", (int)data_len);
		return -1;
	}
	hdr = (struct message_hdr_base *)msgbuf;
	msghdr = (struct message_header1 *)(msgbuf + sizeof(*hdr));

	hdr->msg_type = msg_type;
	hdr->version = 1;

	//加密数据
	msgdata = msgbuf + sizeof(*hdr) + sizeof(*msghdr);
	nsize = LZ4_compress(data, msgdata, data_len);
	if (nsize == 0) {
		LOG(LOG_ERR, "(%d) compress failed, max[%d]\n", (int)data_len, maxOsize);
		free(msgbuf);
		return -1;
	}
	chap_message((unsigned char*)msgdata, nsize);

	//压缩后覆盖之前的长度计算值.
	msglen = sizeof(*hdr) + sizeof(*msghdr) + nsize;
	msghdr->orig_len = data_len;
	msghdr->data_len = nsize;
	//LOG(LOG_DEBUG, "dlen(%d) zlen(%d) max(%d)\n", data_len, nsize, maxOsize);

	if (nsize > 0) {
		msghdr->check_sum = XXH32(msgdata, (int)nsize, 0);
	} else {
		msghdr->check_sum = 2013;
	}

	ret = send_n(sock, msgbuf, msglen, TIMEOUT_SEND);
	if (ret <= 0) {
		fprintf(stderr, "send_n failed\n");
		free(msgbuf);
		return -1;
	}

	if (msg_type != MSG_KEEPALIVE) {
		//LOG(LOG_DEBUG, "send_message(%s) OK\n", data);
	}

	free(msgbuf);
	return data_len;
}

static int connect_ac()
{
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		LOG(LOG_ERR, "error: %s\n", strerror(errno));
		return -1;
	}

	struct sockaddr_in ap_addr;
	ap_addr.sin_family = AF_INET;
	ap_addr.sin_port = htons(6666);
	ap_addr.sin_addr.s_addr = INADDR_ANY;
	if (bind(sock, (struct sockaddr *)&ap_addr, sizeof(ap_addr)) < 0) {
		LOG(LOG_ERR, "error: %s\n", strerror(errno));
		close(sock);
		return -1;
	}

	int found = 0;
	struct sockaddr_in servaddr;
	char msg[99];
	int ret = recvfrom_n(sock, msg, sizeof(msg), &servaddr, 3000);
	close(sock);
	if (ret > 0) {
		sstr_t chksum = SSTR_NULL;
		sstr_t ip = SSTR_NULL;
		const char *p = extract_field(msg, msg + sizeof(msg), &chksum);
		if (p != NULL && extract_field(p, msg + sizeof(msg), &ip) != NULL) {
			if (strtoul(chksum.data, NULL, 16) == XXH32(ip.data, (int)ip.size, 0)) {
				LOG(LOG_DEBUG, "recv addr from brd: %.*s\n", (int)ip.size, ip.data);
				//保存当前AC地址
				sstr_free(str_ac_addr);
				str_ac_addr = sstr_copy_buf(ip.data, ip.size);
				found = 1;
			}else{
				LOG(LOG_ERR, "ac addr checksum[%08X] failed: %.*s, %.*s\n", XXH32(ip.data, (int)ip.size, 0),
					(int)ip.size, ip.data, (int)chksum.size, chksum.data);
			}
		}
		sstr_free(chksum);
		sstr_free(ip);
	}
	//FIXME: use nvram conf ac_ipaddr.
	const char *ac_addr = nvram_ra_get("ac_ipaddr");
	if (strlen(ac_addr) >= 4 && ac_addr_invalid == 0) {
		//配置有效, 且没有超时.
		sstr_free(str_ac_addr);
		str_ac_addr = sstr_copy_cstr(ac_addr);
		LOG(LOG_ERR, "try addr from config:[%s]\n", ac_addr);
	}else if(found){
		//使用广播地址
		ac_addr = str_ac_addr.data;
	}else {
		ac_addr = "127.0.0.1";
		LOG(LOG_ERR, "not found server, use loopback.\n");
	}

	struct addrinfo hints;
	struct addrinfo *result, *rp;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;
	hints.ai_protocol = 0;

	ret = getaddrinfo(ac_addr, "6666", &hints, &result);
	if (ret !=0 ){
		LOG(LOG_ERR, "getaddrinfo: %s\n", gai_strerror(ret));
		return -1;
	}

	//try to connect inet addr's.
	for(rp = result; rp != NULL; rp = rp->ai_next) {
		sock = dial_n(SOCK_STREAM, (struct sockaddr_in*)rp->ai_addr, TIMEOUT_CONNECT);
		if(sock == 0) {
			//LOG(LOG_ERR, "connect timeout.\n");
			continue;
		}else if(sock > 0) {
			break;
		}
	}
	if(rp == NULL) {
		sock = -1;//closed;
		LOG(LOG_ERR, "connect ac[%s] failed.\n", ac_addr);
	}else{
		LOG(LOG_DEBUG, "connect ok[%s].\n", ac_addr);
	}
	freeaddrinfo(result);

	return sock;
}

struct request_get_handler {
	struct request_get_handler *next;
	const char *key;
	int (* cb)(sstr_t *reply);
};

struct request_set_handler {
	struct request_set_handler *next;
	const char *key;
	int (* cb)(sstr_t request, sstr_t *reply);
};

struct request_get_handler *request_get_handler_list = NULL;
struct request_set_handler *request_set_handler_list = NULL;

void register_request_get_handler(const char *key, int (* cb)(sstr_t *reply))
{
	struct request_get_handler *handler = malloc(sizeof(struct request_get_handler));
	if (handler == NULL) {
		LOG(LOG_ERR, "register request get handler oom\n");
		exit(1);
	}
	handler->next = request_get_handler_list;
	handler->key = key;
	handler->cb = cb;
	request_get_handler_list = handler;
}

void register_request_set_handler(const char *key, int (* cb)(sstr_t request, sstr_t *reply))
{
	struct request_set_handler *handler = malloc(sizeof(struct request_set_handler));
	if (handler == NULL) {
		LOG(LOG_ERR, "register request set handler oom\n");
		exit(1);
	}
	handler->next = request_set_handler_list;
	handler->key = key;
	handler->cb = cb;
	request_set_handler_list = handler;
}

enum {
	CMD_GET,
	CMD_SET,
};

static int on_request(const char *data, size_t data_len, sstr_t *reply)
{
	int ret;
	int type;
	const char *const data_end = data + data_len;
	sstr_t cmd = SSTR_NULL;
	sstr_t key = SSTR_NULL;
	sstr_t val = SSTR_NULL;

#define RET_IF(expr, retval, fmt, ...) do {		\
	if (expr) {									\
		*reply = sstr_fmt(fmt, ##__VA_ARGS__);	\
		ret = retval;							\
		goto out;								\
	}											\
} while (0)

	data = extract_field(data, data_end, &cmd);
	RET_IF(data == NULL, 201, "request cmd is NULL");

	if (strcmp(cmd.data, "get") == 0) {
		type = CMD_GET;
	} else if (strcmp(cmd.data, "set") == 0) {
		type = CMD_SET;
	} else {
		RET_IF(1, 202,  "not support cmd: [%.*s]", (int)cmd.size, cmd.data);
	}

	data = extract_field(data, data_end, &key);
	RET_IF(data == NULL, 203, "request key is NULL");

	val = sstr_copy_buf(data, data_end - data);
	if (val.size == 0) {
		RET_IF(type == CMD_SET, 204, "value to set is empty");
	} else {
		RET_IF(type == CMD_GET, 205, "bad get request");
	}

	if (type == CMD_GET) {
		struct request_get_handler *handler;
		for (handler = request_get_handler_list; handler != NULL; handler = handler->next) {
			if (strcmp(key.data, handler->key) == 0) {
				ret = handler->cb(reply);
				goto out;
			}
		}
	} else if (type == CMD_SET) {
		struct request_set_handler *handler;
		for (handler = request_set_handler_list; handler != NULL; handler = handler->next) {
			if (strcmp(key.data, handler->key) == 0) {
				ret = handler->cb(val, reply);
				goto out;
			}
		}
	}

	RET_IF(1, 206, "not found request handler for key: [%.*s]", (int)key.size, key.data);

#undef RET_IF

out:
	sstr_free(cmd);
	sstr_free(key);
	sstr_free(val);
	return ret;
}

static int handle_request(int sock, const char *data, int data_len)
{
	sstr_t reply;
	int ret = on_request(data, data_len, &reply);
	if (ret < 0) {
		LOG(LOG_ERR, "bad request: [%.*s]\n", (int)data_len, data);
	} else {
		if (send_message(sock, MSG_REPLY | (ret << 6), reply.data, reply.size) < 0)
			ret = -1;
		else
			ret = 0;
		sstr_free(reply);
	}
	return ret;
}

static int handle_reply(int sock, const char *data, int data_len)
{
	return 0;
}

void start_ap_client()
{
	int try_counter = 0;
	int sock = connect_ac();
	time_t last_active_time = time(NULL);

	for (;;) {
		if (sock < 0) {
			LOG(LOG_ERR, "reconnect[%d] to ac in 1 sec...\n", try_counter);
			sleep(1);
			sock = connect_ac();
			if (sock < 0) {
				nvram_ra_unset("ac_connected");
				try_counter ++;
				if (try_counter > 11 || (time(NULL) - last_active_time) > 15) {
					LOG(LOG_ERR, "timeout %d->%d\n", last_active_time, time(NULL));
					break;
				}
				continue;
			}
			try_counter = 0;
			last_active_time = time(NULL);
		}

		uint32_t msg_type = 0;
		char *data = NULL;
		int data_len = recv_message(sock, &msg_type, &data);
		if (data_len < 0) {
			LOG(LOG_ERR, "error\n");
			RESET_SOCK(sock);
		} else if (data_len == 0) { // timeout
			if ((time(NULL) - last_active_time) > TIMEOUT_IDLE/1000 ||
				send_message(sock, MSG_KEEPALIVE, "123456", 6) < 0) {
				RESET_SOCK(sock);
			}
		} else {
			switch (msg_type & 0x3F) {
			case MSG_KEEPALIVE:
				last_active_time = time(NULL);
				break;
			case MSG_REQUEST:
				if (handle_request(sock, data, data_len) < 0)
					RESET_SOCK(sock);
				else
					last_active_time = time(NULL);
				break;
			case MSG_REPLY:
				if (handle_reply(sock, data, data_len) < 0)
					RESET_SOCK(sock);
				else
					last_active_time = time(NULL);
				break;
			default:
				LOG(LOG_ERR, "bad msg type: %d\n", (int)msg_type);
				RESET_SOCK(sock);
			}
			free(data);
		}
	}
}
