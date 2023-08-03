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

#include <sys/mman.h>
#include <string.h>
#include <malloc.h>

#include "common.h"
#include "log.h"
#include "ifapi.h"
#include "route.h"
#include "list.h"
#include "xudp_types.h"


#define rt24_num (1<<24)
#define rt24_rule_num (1<<8)

#define debug 0

#if debug
#define IP(a, b, c, d) ntohl((a << 24) + (b << 16) + (c << 8) + d)
#define IPX(a, b, c, d) ((a << 24) + (b << 16) + (c << 8) + d)
#define IPS(i) i>>24,i>>16&0xff,i>>8&0xff,i&0xff
#define IPSH(i)  IPS(ntohl(i))

static u8 route_get(struct route *r, u32 dst)
{
	struct nl_route *nr;

	list_for_each_entry(nr, &r->nr, list) {
		if ((dst & nr->mask) == nr->dst_h)
			return nr->index + 1;
	}

	return 0; // not found goto default
}
#endif

static void logdebug_route(struct route *r, u32 hash, u8 off,
			   struct route_rule *rule)
{
	char buf_dst[20];
	char buf_src[20];
	char buf_next[20];
	const char *dst, *src, *next;

	dst  = inet_ntop(AF_INET, &rule->dst,      buf_dst,  sizeof(buf_dst));
	src  = inet_ntop(AF_INET, &rule->pref_src, buf_src,  sizeof(buf_src));
	next = inet_ntop(AF_INET, &rule->next_hop, buf_next, sizeof(buf_next));

	logdebug(r->log, "route: %s/%d src %s via %s dev %d index: %d "
		 "data: %p\n",
		 dst, rule->dst_len, src, next, rule->ifid,
		 rule->index, rule->data);
}

static int route_init_rt8(struct route *r, struct route_rule *rule, u8 def)
{
	u32 len, off, prefix;
	struct route_rt8 *rt8;

	prefix = rule->dst_h >> 8;

	list_for_each_entry(rt8, &r->rt8, list) {
		if (rt8->prefix == prefix)
			goto found;
	}

	rt8 = malloc(sizeof(*rt8) + (1<<8));
	memset(rt8, def, sizeof(*rt8) + (1<<8));
	rt8->prefix = prefix;
	list_insert(&r->rt8, &rt8->list);

found:
	rule->rt8 = rt8;

	off = rule->dst_h & 0xff;
	len = 1 << (32 - rule->dst_len);

	memset(rt8->rt8 + off, rule->index, len);
	return 0;
}

static int route_get_osroute(struct list_head *osroute, struct log *log)
{
	int ret;

	ret = nl_route(osroute, log);
	if (ret < 0) {
		logerr(log, "get sys route fail\n");
		return -1;
	}

	// save one for default
	if (ret > rt24_rule_num - 1) {
		logerr(log, "too many route rule\n");
		nl_route_free(osroute);
		return -1;
	}

	ret += 1;

	return ret;
}

static int route_init_rule(struct route *r)
{
	struct nl_route *nr;
	struct route_rule *r1, *r2;
	int i, j, n, size;
	struct list_head osroute;
	bool got_default = false;

	INIT_LIST_HEAD(&osroute);

	n = route_get_osroute(&osroute, r->log);
	if (n < 0)
		return -1;

	size = n * sizeof(*r->rules);
	r->rules = malloc(size);
	memset(r->rules, 0, size);

	list_for_each_entry(nr, &osroute, list) {
		++r->rules_n;

		if (!nr->dst_len)
			got_default = true;

		r1 = r->rules + nr->index;

		r1->index    = nr->index;
		r1->dst      = nr->dst;
		r1->dst_h    = nr->dst_h;
		r1->dst_len  = nr->dst_len;
		r1->ifid     = nr->ifid;
		r1->pref_src = nr->pref_src;
		r1->next_hop = nr->next_hop;
	}

	if (!got_default)
		++r->rules_n;

	nl_route_free(&osroute);

	for (i = 0; i < r->rules_n; ++i) {
		r1 = r->rules + i;

		logdebug_route(r, 0, 0, r1);

		if (r1->issub)
			continue;

		/* check for the same dst rules */
		for (j = i + 1; j < r->rules_n; ++j) {
			r2 = r->rules + j;

			if (r2->dst_len != r1->dst_len)
				continue;

			if (r2->dst != r1->dst)
				continue;

			r2->issub = true;
			r2->next = r1->next;
			r1->next = r2;
		}

	}

	loginfo(r->log, "route: got %d rules from system.\n\n", r->rules_n);

	return 0;
}

static int route_init_rt24(struct route *r)
{
	struct route_rule *r1;
	u32 num, off;
	int i;

	for (i = r->rules_n - 1; i >= 0; --i) {
		r1 = r->rules + i;

		if (log_enable(r->log, DEBUG))
			logdebug_route(r, 0, 0, r1);

		if (r1->dst_len == 0)
			continue;

		if (r1->issub)
			continue;

		off = r1->dst_h >> 8;
		if (r1->dst_len >= 24) {
			num = 1;
			route_init_rt8(r, r1, r->rt24[off]);

		} else {
			num = (1 << (24 - r1->dst_len));
		}

		logdebug(r->log, "route: init rt24. hash: %u off: %d num: %d\n",
			 off, r1->index, num);

		memset(r->rt24 + off, r1->index, num);
	}

	return 0;
}

struct route_rule *route_lookup(struct route *r, u32 dst)
{
	struct route_rule *rule;
	u32 hash;
	u8 off;

	hash = dst >> 8;

	off = r->rt24[hash];

	rule = r->rules + off;

	if (log_enable(r->log, DEBUG))
		logdebug_route(r, hash, off, rule);

	if (rule->rt8) {
		hash = dst & 0xff;
		off = rule->rt8->rt8[hash];
		rule = r->rules + off;

		logdebug(r->log, "route lookup1. hash: %d off: %d\n", hash, off);
	}

	/* lookup done */
	return rule;
}

struct route *route_init(struct log *log)
{
	struct route *r;
	int ret;

	zobj(r);

	r->rt24 = anon_map(rt24_num * sizeof(*r->rt24));
	if (MAP_FAILED == r->rt24) {
		free(r);
		logerr(log, "route init alloc by mmap fail.\n");
		return NULL;
	}

	r->log = log;

	INIT_LIST_HEAD(&r->rt8);

	ret = route_init_rule(r);

	if (ret)
		return NULL;

	route_init_rt24(r);

	return r;
}

void route_free(struct route *r)
{
	struct route_rt8 *rt8, *safe;

	munmap(r->rt24, rt24_num * sizeof(*r->rt24));

	list_for_each_entry_safe(rt8, safe, &r->rt8, list) {
		free(rt8);
	}

	free(r->rules);
	free(r);
}

#if debug
static int show(struct route *r, u8 a, u8 b, u8 c, u8 d)
{
	struct route_rule *rule;

	u32 ip;

	rule = route_lookup(r, IPX(a,b,c,d));
	printf("lookup: %d.%d.%d.%d next_hop: %d.%d.%d.%d src: %d.%d.%d.%d dev: %d\n", a, b, c, d, IPSH(rule->next_hop), IPSH(rule->pref_src), rule->ifid);

	rule = r->rules + route_get(r, IPX(a,b,c,d));
	printf("        %d.%d.%d.%d next_hop: %d.%d.%d.%d src: %d.%d.%d.%d dev: %d\n", a, b, c, d, IPSH(rule->next_hop), IPSH(rule->pref_src), rule->ifid);

}

int main()
{
	struct route *r;
	struct log log = {};
	u32 ip;

	log.level = LOG_LEVEL_DEBUG;

	r = route_init(&log);

	show(r, 192, 168, 100, 1);
	show(r, 192, 168, 122, 1);
	show(r, 1, 1, 1, 1);
	show(r, 10, 1, 1, 1);
	show(r, 11,160,229,128);
	show(r, 11,160,229,28);
}
#endif
