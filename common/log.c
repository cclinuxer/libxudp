/*
 * Copyright (c) 2021 Alibaba Group Holding Limited
 * Express UDP is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 *
 */

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <unistd.h>

#include "log.h"

int logcore(struct log *log, char *fmt, ...)
{
	char buf[1024], *pos;
	int size, ret, n;
 	va_list ap;
  	time_t t;
    	struct tm* tm_info;

	size = sizeof(buf);
	pos = buf;

	if (log->time) {
    		t = time(NULL);
    		tm_info = localtime(&t);
		n = strftime(pos, size, "[%Y-%m-%d %H:%M:%S] ", tm_info);
		size -= n;
		pos += n;
	} else if (log->time_us) {
		struct timespec tp;

		clock_gettime(CLOCK_MONOTONIC, &tp);
		n = snprintf(pos, size, "[%ldus] ",
			     tp.tv_sec * 1000 * 1000 + tp.tv_nsec / 1000);
		size -= n;
		pos += n;
	}

	if (log->prefix_len) {
		memcpy(pos, log->prefix, log->prefix_len);
		pos += log->prefix_len;
		size -= log->prefix_len;
	}

	va_start(ap, fmt);
	pos  += vsnprintf(pos, size, fmt, ap);
	va_end(ap);

	if (log->cb) {
		if (*(pos - 1) == '\n')
			--pos;

		*pos = 0;

		ret = log->cb(buf, pos - buf, log->data);
	} else  {
		ret = write(1, buf, pos - buf);
	}

	return ret;
}
