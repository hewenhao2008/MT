#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

typedef struct {
	char *data;
	size_t size;
} sstr_t;

#define SSTR_NULL { NULL, 0 }

static inline sstr_t
sstr_new_n(size_t len)
{
	sstr_t s;
	s.data = malloc(len + 1);
	s.size = len;
	if (s.data == NULL) {
		fprintf(stderr, "sstr_new_n() oom\n");
		abort();
	}
	s.data[s.size] = 0;
	return s;
}

static inline void
sstr_free(sstr_t s)
{
	if (s.data == NULL) {
		if (s.size != 0) {
			fprintf(stderr, "sstr_free() bug: %p %d\n", s.data, (int)s.size);
			abort();
		}
		return;
	}
	if (s.data[s.size] != 0) {
		fprintf(stderr, "sstr_free() bug: %p %d\n", s.data, (int)s.size);
		abort();
	}
	free(s.data);
}

static inline sstr_t
sstr_copy_buf(const char *buf, size_t size)
{
	sstr_t s = sstr_new_n(size);
	memcpy(s.data, buf, size);
	s.data[size] = 0;
	return s;
}

static inline sstr_t
sstr_copy_cstr(const char *str)
{
	sstr_t s = SSTR_NULL;
	if (str != NULL) {
		s = sstr_new_n(strlen(str));
		memcpy(s.data, str, s.size + 1);
	}
	return s;
}

static inline sstr_t
sstr_move_cstr(char *str)
{
	sstr_t s = SSTR_NULL;
	if (str != NULL) {
		s.data = str;
		s.size = strlen(str);
	}
	return s;
}

static inline sstr_t
sstr_fmt(const char *fmt, ...)
{
	#define MAX_BUF_SIZE (64 * 1024)
	char *buf;
	va_list ap;
	int ret;
	sstr_t res;

	buf = malloc(MAX_BUF_SIZE);
	if (buf == NULL) {
		fprintf(stderr, "sstr_fmt: oom\n");
		abort();
	}

	va_start(ap, fmt);
	ret = vsnprintf(buf, MAX_BUF_SIZE, fmt, ap);
	va_end(ap);

	if (ret < 0 || ret >= MAX_BUF_SIZE) {
		res = sstr_copy_cstr("sprintf_m() error");
	} else {
		res = sstr_copy_cstr(buf);
	}

	free(buf);
	return res;
	#undef MAX_BUF_SIZE
}
