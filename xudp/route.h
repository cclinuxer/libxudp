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

#ifndef  __ROUTE_H__
#define __ROUTE_H__

#include "list.h"
#include "log.h"
typedef __u32 u32;

typedef unsigned char u8;

struct route_rt8 {
	struct list_head list;

	u32 prefix;
	char rt8[];
};

struct route_rule {
	__be32 pref_src;
	__be32 next_hop;
	int ifid;
	int index;
	struct route_rt8 *rt8;
	void *data;


	u32 dst_h;
	__be32 dst;
	char dst_len;

	// for the same next_hop and dst_len
	struct route_rule *next;
	bool issub;
};

struct route {
	struct list_head rt8;
	struct log *log;

	char *rt24;
	struct route_rule *rules;
	u8 rules_n;
};

struct route_rule *route_lookup(struct route *r, u32 dst);
struct route *route_init(struct log *log);
void route_free(struct route *r);
#endif


