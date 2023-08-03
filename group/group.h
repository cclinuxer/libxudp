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

#ifndef  __GROUP_H__
#define __GROUP_H__

#include <errno.h>
#include <libgen.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <net/ethernet.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <time.h>
#include <sys/types.h>
#include <poll.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <net/if.h>
#include <linux/if_xdp.h>
#include <linux/if_link.h>

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>

#include "list.h"
#include "queue.h"
#include "common.h"
#include "channel.h"
#include "config.h"
#include "group_api.h"

#undef logerr
#define logerr(x, fmt, ...)    \
	if (LOG_LEVEL_ERR <= __xudp_log(x)->level) \
		logcore(__xudp_log(x), fmt, ##__VA_ARGS__)

#undef loginfo
#define loginfo(x, fmt, ...)    \
	if (LOG_LEVEL_INFO <= __xudp_log(x)->level) \
		logcore(__xudp_log(x), fmt, ##__VA_ARGS__)

#undef logdebug
#define logdebug(x, fmt, ...)    \
	if (LOG_LEVEL_DEBUG <= __xudp_log(x)->level) \
		logcore(__xudp_log(x), fmt, ##__VA_ARGS__)

struct xudp_group;

struct rxch {
	struct xdpsock xsk;
	struct xudp_group *group;
	bool unaligned;
};

struct xudp_group_nic {
	struct list_head list;
	int ifindex;
	int xsk_n;
	struct rxch rxch[0];
};

#endif


