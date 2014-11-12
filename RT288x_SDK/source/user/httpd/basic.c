/*
 * Basic skin (shtml)
 *
 * Copyright (C) 2013, Broadcom Corporation. All Rights Reserved.
 * 
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * $Id: basic.c 385828 2013-02-18 17:24:00Z $
 */

#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/sysinfo.h>
#include <assert.h>

#include "httpd.h"
#include "nvram.h"
#include "ugw.h"

char no_cache[] =
 	"Cache-Control: no-cache\r\n"
 	"Pragma: no-cache\r\n"
 	"Expires: 0";

char download_hdr[] =
	"Cache-Control: no-cache\r\n"
	"Pragma: no-cache\r\n"
	"Expires: 0\r\n"
	"Content-Type: application/download\r\n"
	"Content-Disposition: attachment ; filename=ugw.bin";

static int filter_chr(int c) 
{
	int i;
	static char *spec = "._-&:=/@ ";

	if (c>='0' && c<='9')
		return 0;
	if (c>='a' && c<='z')
		return 0;
	if (c>='A' && c<='Z')
		return 0;

	for(i=0; i<strlen(spec); i++){
		if(c==spec[i])
			return 0;
	}

	//return 1; 不做字符屏蔽, 支持中文
	return 0;
}

enum {
	S_PARSE_LINE_NULL,
	S_PARSE_LINE_KEY,
	S_PARSE_LINE_VAL,
	S_PARSE_LINE_IGN,
};

#define F_MODIFY_RECONF (1<<0)
#define F_MODIFY_IFACE	(1<<1)
#define F_MODIFY_START	(1<<2)

static int notify_modified(unsigned int mask)
{
	//这里不要重启 网口, 配置完了, 用户自己选择是否立即 重启网络.
	if(mask & F_MODIFY_RECONF) {
		logdbg("zone config modified. reconfig...\n");
		//system("nws_cli reconfig");
	}
	if(mask & F_MODIFY_IFACE){
		logdbg("vlan interfaces changed...\n");
		//system("nws_cli interfaces");
	}
	if(mask & F_MODIFY_START){
		logdbg("net work need restart interfaces addrs.\n");
		//system("nws_cli start");
	}
	
	if(mask){
		logdbg("conf updated, commit.\n");
		nvram_ra_commit();
	}
	return 0;
}

static int exec_line(char *key, char *val, int num, unsigned int *modify)
{
	char *oval;

	oval = nvram_safe_get(key);
	if (strcmp(oval, val)!=0){
		fprintf(stderr, "%4d: %s=[%s]->[%s]\n", num, key, oval, val);

		nvram_ra_set(key, val);

		//fixup 关联改动配置.
		if (strncmp(key, "cloud_account", strlen("cloud_account")) == 0 ) {
			if(strlen(val) > 0) {
				nvram_ra_set("UGWAuthEnable", "1");
			}else{
				nvram_ra_set("UGWAuthEnable", "0");
			}
		}

		*modify |= F_MODIFY_RECONF;
	}

	return 0;
}

static void post_req(char *path, FILE *stream, int len, char *boundary)
{
	unsigned int modify = 0;
	int c, line, num, status, len_key, len_val;
	//size_t r;
	char key[128], val[128];

	if(boundary)
		fprintf(stderr, "boundary: %s\n", boundary);

	line = 0;
	num = 0;
	status = S_PARSE_LINE_KEY; len_val = len_key = 0;
	memset(key, 0, sizeof(key));
	memset(val, 0, sizeof(val));
	while((c=fgetc(stream))!=EOF) {
		//putc(c, stderr);
		if(filter_chr(c)) {
			fprintf(stderr, "\tinvalid char[%x:%c]\n", c, c);
			c = '*';
		}
		switch(c){
			case '&':
				//putc('\n', stderr);
				//完成一行读入
				val[len_val] = '\0';
				len_key = 0;
				len_val = 0;
				line ++;
				exec_line(key, val, line, &modify);

				status = S_PARSE_LINE_KEY;
				break;
			case '=':
				//KEY读完
				key[len_key] = '\0';
				val[0] = '\0';
				len_val = 0;
				status = S_PARSE_LINE_VAL;
				break;
			case ' ' : //忽略空格
			case '\t':
			case '\r':
			case '\n':
				break;
			default:
				//putc((unsigned char)c, stderr);
				if(status == S_PARSE_LINE_KEY) {
					key[len_key] = c;
					len_key ++;
				}else if(status == S_PARSE_LINE_VAL) {
					val[len_val] = c;
					len_val ++;
				}
				break;
		}
		if(++num >= len)
			break;
	}
	//检查最后一行
	key[len_key] = '\0';
	val[len_val] = '\0';
	if(len_key > 0) {
		exec_line(key, val, line, &modify);
	}

	if(modify){
		notify_modified(modify);
	}

	fprintf(stderr, "%s, len: %d, line: %d\n", path, len, line);
	return;
}

static void conf_rep(char *path, FILE *stream)
{
	FILE *fp_pipe;
	char buff[1024];
	/*
	* 1. 读取nvram, 回显里面的字段, 格式换成json的array, key=value\n; 格式.
	*/
	fp_pipe = popen("nvram show", "r");
	if(!fp_pipe){
		logerr("open pipe err: %s\n", strerror(errno));
		return;
	}

	while(fgets(buff, sizeof(buff), fp_pipe) != NULL) {
		//logdbg("read: %s\n", buff);
		fputs(buff, stream);
	}

	pclose(fp_pipe);
	return;
}

static int write_pipe(FILE *stream, const char *FMT, char *cmds, int all)
{
	FILE *fp_pipe;
	char buff[MAX_NVKEY_SIZE];

	fp_pipe = popen(cmds, "r");
	if(!fp_pipe){
		logerr("popen [%s]: %s\n", cmds, strerror(errno));
		return errno;
	}
	while(fgets(buff, sizeof(buff), fp_pipe)!=NULL) {
		fprintf(stream, FMT, buff);
		if(!all){
			break;
		}
	}
	pclose(fp_pipe);

	return 0;
}

static char exec_buffer[1024];
static void exec_req(char *path, FILE *stream, int len, char *boundary)
{
	char *buff = exec_buffer;
	memset(buff, 0, sizeof(exec_buffer));

	if(len > sizeof(exec_buffer)) {
		logerr("req cmds too large.\n");
		return;
	}
	size_t rn = fread(buff, 1, len, stream);
	if(rn != len) {
		logerr("cmds read failed.%d, %d\n", rn, len);
		return;
	}
	buff[len] = '\0';
}

static void exec_rep(char *path, FILE *stream)
{
	if(strlen(exec_buffer)<=0) {
		logerr("empty cmds\n");
		return;
	}
	logdbg("exec: [%s]\n", exec_buffer);
	FILE *fp_pipe = popen(exec_buffer, "r");
	if (!fp_pipe) {
		logerr("popen err: %s\n", strerror(errno));
		return;
	}
	char buff[128];
	while(fgets(buff, sizeof(buff), fp_pipe)!=NULL) {
		fputs(buff, stream);
	}
	pclose(fp_pipe);
	fflush(stream);
}

static void
do_auth(char *userid, char *passwd, char *realm)
{
	assert(userid);
	assert(passwd);
	assert(realm);

	//logdbg("web: %s,%s,%s\n", userid, passwd, realm);

	strncpy(userid, nvram_safe_get("http_username"), AUTH_MAX);
	strncpy(passwd, nvram_safe_get("http_password"), AUTH_MAX);
	strncpy(realm, "MT7620 console", AUTH_MAX);
}

#include <fcntl.h>
#include <unistd.h>

#define MAX_BUFF_SIZE (1024 * 4)
extern int mtd_write(const char *path, const char *mtd);

enum err_do_post_recv_t {
	ERR_OK = 0,
	ERR_POST_HDR,
	ERR_POST_NO_CONT,
	ERR_POST_NO_LENGTH,
};

enum post_file_type_t {
	TYPE_POST_sys_upgrade,
	TYPE_POST_conf_restore,
};

static int recv_and_use(FILE *stream, int *total, char *boundary, int type)
{
	char upload_tmp[] = "/tmp/uploadXXXXXX";
	FILE *ffw = NULL;
	char *buff = NULL;
	int count, ret = 0;
	long flags = -1;

	//全部收上来, 校验后开始写入.
	if (!mkstemp(upload_tmp) || !(ffw = fopen(upload_tmp, "w"))) {
		logerr("mktmp failed: %s\n", strerror(errno));
		ret  = errno;
		goto __err;
	}

	if ((flags = fcntl(fileno(stream), F_GETFL)) < 0 ||
	    fcntl(fileno(stream), F_SETFL, flags | O_NONBLOCK) < 0) {
		logerr("fcntl failed: %s\n", strerror(errno));
		ret = errno;
		goto __err;
	}

	image_header_t hdr;
	int wsize = 0;

	count = safe_fread(&hdr, 1, sizeof(image_header_t), stream);
	if (count < sizeof(image_header_t)) {
		logerr("header is too small (%d bytes)\n", count);
		ret = -101;
		goto __err;
	}
	*total -= count;
	wsize += safe_fwrite(&hdr, 1, count, ffw);

	unsigned long size = MAX_BUFF_SIZE;
	buff = malloc(size);
	if(!buff){
		ret = errno;
		logerr("alloc buff failed.\n");
		goto __err;
	}
	while (total && (*total > 0)) {
		if (waitfor(fileno(stream), 5) <= 0){
			logerr("recv timeout. %d\n", *total);
			ret = -102;
			break;
		}
		count = safe_fread(buff, 1, size, stream);
		if (count<=0 && (ferror(stream) || feof(stream))) {
			logerr("recv file trans error.\n");
			ret = -103;
			break;
		}
		//recv ok
		*total -= count;

		//check boundary
		int found = 0;
		if(boundary) {
			//FIXME: trunked
			char *pos = buff;
			while(pos + strlen(boundary) < buff + count) {
				if(memcmp(pos, "----", strlen("----")) == 0) {
					logdbg("found offset: %d\n", pos - buff);
					found = 1;
					break;
				}
				pos ++;
			}
			while(found && (--pos >= buff)) {
				if((pos[0] == 0x0d) || (pos[0]==0x0d && pos[1] == 0x0a)) {
					logdbg("found eof: %s\n", boundary);
					count = pos - buff;
					break;
				}
			}
		}
		wsize += safe_fwrite(buff, 1, count, ffw);
		if(found) {
			logdbg("boundary found, actlen: %d\n", wsize);
			break;
		}
		//show
		//fprintf(stderr, "\n");
		//bcm_hexdump(stderr, buff, count);
		//logdbg("wsize: %d\n", wsize);
	}
	if(ret) 
		goto __err;

	fclose(ffw);
	ffw = NULL;

	logdbg("start write fw: %s\n", upload_tmp);

	switch(type){
		case TYPE_POST_sys_upgrade:	
			logdbg("upgrade nand file system...\n");
			snprintf(buff, MAX_NVKEY_SIZE, "upgrade.sh %s > /tmp/upgrade.log", upload_tmp);
			ret = system(buff);
		break;

		case TYPE_POST_conf_restore:
			snprintf(buff, MAX_NVKEY_SIZE, "conf_restore.sh %s > /tmp/upgrade.log", upload_tmp);
			ret = system(buff);
		break;

		default:
			logerr("unknown post file todo...%d.\n", type);
		break;
	}

__err:
	if(buff)
		free(buff);

	if(ffw)
		fclose(ffw);
	
	unlink(upload_tmp);//fixme: debug not remove it.
	return ret;
}

#define MIN(a, b)	((a) < (b)? (a): (b))

static int upgrade_ret = 0;
static int do_cgi_post(char *url, FILE *stream, int len, char *boundary, int type)
{
	char buf[4096];
	int line = 0;

	/* Look for our part */
	logdbg("file length: %d\n", len);
	while (len > 0) {
		if (!fgets(buf, MIN(len + 1, sizeof(buf)), stream)){
			logerr("recv header failed: %s\n", strerror(errno));
			return ERR_POST_HDR;
		}
		len -= strlen(buf);
		if (!strncasecmp(buf, "Content-Disposition:", 20) && strstr(buf, "name=\"file_ugw_post\"")){
			logdbg("http header ctx disp & file name ugw post found.\n");
			break;
		}
		if(line++>10){
			logerr("not found post form.\n");
			return ERR_POST_NO_CONT;
		}
	}

	/* Skip boundary and headers */
	while (len > 0) {
		if (!fgets(buf, MIN(len + 1, sizeof(buf)), stream)){
			logerr("unknown length.\n");
			return ERR_POST_NO_LENGTH;
		}
		len -= strlen(buf);
		if (!strcmp(buf, "\n") || !strcmp(buf, "\r\n")){
			logdbg("finished recv.\n");
			break;
		}
	}

	upgrade_ret = recv_and_use(stream, &len, boundary, type);

	/* Slurp anything remaining in the request */
	while (len--)
		(void) fgetc(stream);

	return 0;
}


static void sys_upgrade_cgi(char *url, FILE *stream, int len, char *boundary)
{
	do_cgi_post(url, stream, len, boundary, TYPE_POST_sys_upgrade);
}
static void sys_conf_restore_cgi(char *url, FILE *stream, int len, char *boundary)
{
	do_cgi_post(url, stream, len, boundary, TYPE_POST_conf_restore);
}

static void done_upgrade_cgi(char *url, FILE *stream)
{
	assert(url);
	assert(stream);

	if(upgrade_ret == 0){
		fprintf(stream, "upgrade successed.\n");
	}else{
		fprintf(stream, "error: %d\n", upgrade_ret);
	}
	write_pipe(stream, "%s<br>", "cat /tmp/upgrade.log", TRUE);
}

static char* conf_backup_fname = "/ugw/data/conf.tar.gz";
static void sys_conf_backup_cgi(char *url, FILE *stream)
{
	int n;
	char buff[MAX_NVKEY_SIZE];

	//1.写配置文件 xxx.tar.gz
	snprintf(buff, sizeof(buff), "conf_backup.sh %s", conf_backup_fname);
	if((n=system(buff))) {
		logerr("gen conf backup failed: %d.\n", n);
		return;
	}
	//2. do_file xxx.tar.gz
	do_file(conf_backup_fname, stream);
	unlink(conf_backup_fname);
}

static void sys_test(char *url, FILE *stream)
{
	char idx = -1;
	char *id = strstr(url, "fid="), buff[96];

	if (!id) {
		logerr("can't find factory id.\n");
		goto __finished;
	}
	id += 4;

	/* ugw-factory */
	if(strncmp("7158ed23f44f37d0286b3425aacacee5", id, 32) == 0) {
		//leguang
		idx = 0;
	}else if (strncmp("753c09ae6d41829ee0b5b631747604e7", id, 32) == 0) {
		//shenlan
		idx = 1;
	}else if (strncmp("ea2e46c6508c7fb3c467f2c22f599057", id, 32) == 0) {
		//shenlan
		idx = 2;
	}else{
		logerr("unknown factory id [%s]\n", id);
		goto __finished;
	}

	//write to eeprom
	snprintf(buff, sizeof(buff), "iwpriv ra0 e2p 110=%d", idx);
	system(buff);
	logdbg("exec: %s\n", buff);

	//read back test
	mtdpart_read("Factory", &idx, 0x110, 1);

__finished:
	fprintf(stream, "[%s]->%d\n", (id?:""), idx);
	fflush(stream);
}

struct mime_handler mime_handlers[] = {
	{ "**.htm", "text/html", NULL, NULL, do_file, do_auth },
	{ "**.html", "text/html", NULL, NULL, do_file, do_auth },
	{ "**.gif", "image/gif", NULL, NULL, do_file, NULL },
	{ "**.jpg", "image/jpeg", NULL, NULL, do_file, NULL },
	{ "**.jpeg", "image/gif", NULL, NULL, do_file, NULL },
	{ "**.png", "image/png", NULL, NULL, do_file, NULL },
	{ "**.css", "text/css", NULL, NULL, do_file, NULL },
	{ "**.js", "text/javascript", NULL, NULL, do_file, NULL },
	{ "**.au", "audio/basic", NULL, NULL, do_file, NULL },
	{ "**.wav", "audio/wav", NULL, NULL, do_file, NULL },
	{ "**.avi", "video/x-msvideo", NULL, NULL, do_file, NULL },
	{ "**.mov", "video/quicktime", NULL, NULL, do_file, NULL },
	{ "**.mpeg", "video/mpeg", NULL, NULL, do_file, NULL },
	{ "**.vrml", "model/vrml", NULL, NULL, do_file, NULL },
	{ "**.midi", "audio/midi", NULL, NULL, do_file, NULL },
	{ "**.mp3", "audio/mpeg", NULL, NULL, do_file, NULL },
	{ "**.pac", "application/x-ns-proxy-autoconfig", NULL, NULL, do_file, NULL },
	{ "**.conf", "text/plain", NULL, NULL, do_file, NULL },
	{ "conf.cgi", "text/plain", no_cache, NULL, conf_rep, do_auth },
	{ "post.cgi", "application/x-www-form-urlencoded", no_cache, post_req, NULL, do_auth},
	{ "exec.cgi", "application/x-www-form-urlencoded", no_cache, exec_req, exec_rep, do_auth},
	{ "sys_upgrade.cgi", "text/html", no_cache, sys_upgrade_cgi, done_upgrade_cgi, do_auth},
	{ "sys_conf_backup.cgi", "text/html", download_hdr, NULL, sys_conf_backup_cgi, do_auth},
	{ "sys_test.cgi**", "text/html", no_cache, NULL, sys_test, do_auth},
	{ "sys_conf_restore.cgi", "text/html", no_cache, sys_conf_restore_cgi, done_upgrade_cgi, do_auth},
	{ NULL, NULL, NULL, NULL, NULL, NULL }
};

struct ej_handler ej_handlers[] = {
	{ NULL, NULL }
};

int internal_init(void)
{
	return 0;
}
