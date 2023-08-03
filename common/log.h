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

#ifndef  __LOG_H__
#define __LOG_H__
#include <stdarg.h>
#include <stdbool.h>

enum {
	LOG_LEVEL_ERR,
	LOG_LEVEL_WARN,
	LOG_LEVEL_INFO,
	LOG_LEVEL_DEBUG,
};

typedef int (*log_cb)(char *buf, int size, void *data);

struct log {
	int     level;
	void   *data;
	log_cb  cb;
	char   *prefix;
	int     prefix_len;
	bool    time;
	bool    time_us;
};


int logcore(struct log *log, char *fmt, ...);

#define logerr(log, fmt, ...)    \
	if (LOG_LEVEL_ERR <= log->level) \
		logcore(log, fmt, ##__VA_ARGS__)

#define logwrn(log, fmt, ...)    \
	if (LOG_LEVEL_WARN <= log->level) \
		logcore(log, fmt, ##__VA_ARGS__)

#define loginfo(log, fmt, ...)    \
	if (LOG_LEVEL_INFO <= log->level) \
		logcore(log, fmt, ##__VA_ARGS__)

#define logdebug(log, fmt, ...)    \
	if (LOG_LEVEL_DEBUG <= log->level) \
		logcore(log, fmt, ##__VA_ARGS__)


#define log_enable(log, l) (LOG_LEVEL_##l <= log->level)


#endif


