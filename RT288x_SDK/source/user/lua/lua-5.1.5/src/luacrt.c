#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include "lua.h"
#include "luacrt.h"
typedef struct luacrt_info {
	unsigned int crc;
	unsigned int rawlen;
	char content[0];
} luacrt_info;

typedef struct luacrt {
	FILE *fp; 
} luacrt;

#define XOR(buff, len, e) do { \
	char *pos = (buff), *end = (buff) + (len); \
	for (; end > pos && end - pos >= 4; pos += 4) \
		*(unsigned int *)pos ^= (e); \
}while(0)

#define INC(buff, len) do {\
	char *pos = (buff), *end = (buff) + (len); \
	while (pos <= end) { \
		*pos = *pos + (end - pos);\
		pos++;\
	} \
}while(0)

#define DEC(buff, len) do {\
	char *pos = (buff), *end = (buff) + (len); \
	while (pos <= end) { \
		*pos = *pos - (end - pos);\
		pos++;\
	} \
}while(0)

#define HASH_CRC(buff, len, out) do {\
	int i; \
	unsigned int hash = 1315423911; \
	for (i = 0; i < len; i++) \
		hash ^= ((hash<<5) + buff[i] + (hash>>2)); \
	*out = hash; \
}while(0)

#define GOTO(flag) do {fprintf(stderr, "%s %d\n", __FILE__, __LINE__); goto flag;}while(0)

struct luacrt *luacrt_create(FILE *fp) {
	struct luacrt *cs;
	if (!fp)
		return NULL;
		
	cs = (struct luacrt *)malloc(sizeof(struct luacrt));
	if (!cs)
		return NULL;
	cs->fp = fp;
	return cs;
}

void luacrt_destroy(struct luacrt *cs) {
	free(cs);
}

const char *luacrt_enext(struct luacrt *cs, char *out, int *outlen) {
	int insize, rawlen, cmplen;
	struct luacrt_info *ci = (struct luacrt_info *)out; 
	char *raw_content = out + sizeof(struct luacrt_info);

	insize = *outlen - sizeof(struct luacrt_info);
	*outlen = 0;
	if (insize <= 0)
		GOTO(error_ret);
	if (feof(cs->fp)) 
		return NULL;
	if (ferror(cs->fp))
		GOTO(error_ret);
	rawlen = fread(raw_content, 1, insize, cs->fp);
	if (rawlen < 0)
		GOTO(error_ret);
	
	HASH_CRC(raw_content, rawlen, &ci->crc); 
	XOR(raw_content, rawlen, 0X653DAA7E);
	INC(raw_content, rawlen);
	XOR(raw_content, rawlen, 0XC99D7DDB); 

	ci->rawlen = rawlen; 
	*outlen = rawlen + sizeof(struct luacrt_info); 
	return out;
error_ret:
	*outlen = -1;
	return NULL;
}

const char *luacrt_dnext(struct luacrt *cs, char *out, int *outlen) {
	int ret, insize;
	unsigned int crc;
	struct luacrt_info expect_ci; 
	insize = *outlen;
	*outlen = 0;
	if (feof(cs->fp)) 
		return NULL;
	if (ferror(cs->fp))
		GOTO(error_ret);
	ret = fread(&expect_ci, 1, sizeof(struct luacrt_info), cs->fp);
	if (ret < 0 || ret < sizeof(struct luacrt_info))
		GOTO(error_ret); 
	if (expect_ci.rawlen <= 0 || expect_ci.rawlen > insize)
		GOTO(error_ret);
	ret = fread(out, 1, expect_ci.rawlen, cs->fp);
	if (ret != expect_ci.rawlen)
		GOTO(error_ret);
	
	XOR(out, expect_ci.rawlen, 0XC99D7DDB);
	DEC(out, expect_ci.rawlen);
	XOR(out, expect_ci.rawlen, 0X653DAA7E);
	HASH_CRC(out, expect_ci.rawlen, &crc);
	if (crc != expect_ci.crc)
		GOTO(error_ret);

	*outlen = expect_ci.rawlen;
	return out;
error_ret:
	*outlen = -1;
	return NULL;
}

int luacrt_efile(const char *infile) {
	int ret, ch;
	char *buff = NULL; 
	char outpath[256] = {0};
	struct luacrt *lct = NULL; 
	FILE *rfp = NULL, *wfp = NULL; 
	if (!infile) 
		return 0;
	
	buff = (char *)malloc(LUAL_LOAD_SIZE);
	if (!buff)
		GOTO(error_ret);
	snprintf(outpath, sizeof(outpath) - 1, "%s.tmp", infile);
	rfp = fopen(infile, "rb");
	wfp = fopen(outpath, "wb");
	if (!rfp || !wfp)
		GOTO(error_ret);
	while ((ch = getc(rfp)) != EOF && ch != LUA_SIGNATURE[0]) {
		if (EOF == putc(ch, wfp))
			GOTO(error_ret);
	}
	if (feof(rfp) || ferror(rfp))
		GOTO(error_ret);
	if (EOF == putc(ch, wfp))
		GOTO(error_ret);
	lct = luacrt_create(rfp);
	if (!lct)
		GOTO(error_ret);
	while (1) {
		int outlen = LUAL_LOAD_SIZE;
		const char *addr = luacrt_enext(lct, buff, &outlen);
		if (!addr) {
			if (outlen == -1)
				GOTO(error_ret);
			break;
		} 
		ret = fwrite(buff, 1, outlen, wfp);
		if (ret != outlen)
			GOTO(error_ret);
	} 
	fflush(wfp);
	fclose(wfp);
	fclose(rfp);
	free(buff);
	unlink(infile);
	if (rename(outpath, infile))
		return -1;
	return 0;
error_ret:
	if (buff) 	free(buff);
	if (rfp) 	fclose(rfp);
	if (wfp) 	fclose(wfp);
	if (lct)	luacrt_destroy(lct);
	unlink(outpath);
	return -1;
}





