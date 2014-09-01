#ifndef __LUA_CRYPT_H__
#define __LUA_CRYPT_H__

#include <stdio.h>
#include "luaconf.h"

#ifdef __cplusplus 
extern "C" {
#endif 
struct luacrt;
struct luacrt *luacrt_create(FILE *fp);
void luacrt_destroy(struct luacrt *cs);
const char *luacrt_enext(struct luacrt *cs, char *out, int *outlen);
const char *luacrt_dnext(struct luacrt *cs, char *out, int *outlen); 
int luacrt_efile(const char *infile);
#ifdef __cplusplus 
}
#endif 
#endif 
