#include <sys/mman.h>
#include <string.h>
#include <malloc.h>

#include "common.h"
#include "log.h"
#include "ifapi.h"
#include "route6.h"
#include "list.h"
#include "xudp_types.h"
#include "ip6.h"

#define RT_MAIN_NUM (1<<24)
#define RT_SUB_NUM (1<<8)
#define RULES_MAX (1<<16)

static int ru_sub_prefix_len(struct route_rule6 *ru)
{
	int l;

	if (ru->dst_len <= 24)
		return 0;

	l = ru->dst_len & (~0x7);
	if (l == ru->dst_len)
		return l - 8;

	return l;
}

static void log_os_rule(struct nl_route *nr, struct log *log)
{
	char buf_dst[INET6_ADDRSTRLEN + 1];
	char buf_src[INET6_ADDRSTRLEN + 1];
	char buf_via[INET6_ADDRSTRLEN + 1];

	inet_ntop(AF_INET6, &nr->dst6,      buf_dst, sizeof(buf_dst));
	inet_ntop(AF_INET6, &nr->next_hop6, buf_via, sizeof(buf_via));
	inet_ntop(AF_INET6, &nr->pref_src6, buf_src, sizeof(buf_src));

	loginfo(log, "os route: %d %s/%d via %s src %s dev %d\n",
		nr->index, buf_dst, nr->dst_len, buf_via, buf_src,
		nr->ifid);
}

static struct route_rule6* route6_get_osrules(struct route6 *r6, struct log *log)
{
	struct route_rule6 *rules, *ru;
	bool got_default = false;
	struct list_head osrules;
	struct nl_route *nr;
	int ret, n, size;

	INIT_LIST_HEAD(&osrules);

	ret = nl_route6(&osrules, log);
	if (ret < 0) {
		logerr(log, "get sys route fail\n");
		return NULL;
	}

	n = ret;

	// save one for default
	if (ret > RULES_MAX - 1) {
		nl_route_free(&osrules);
		logerr(log, "too many route rule\n");
		return NULL;
	}

	n += 1;

	size = n * sizeof(struct route_rule6);
	rules = malloc(size);
	if (!rules)
		return NULL;

	memset(rules, 0, size);

	// copy from os route
	list_for_each_entry(nr, &osrules, list) {
		++r6->rules_n;

		if (!nr->dst_len)
			got_default = true;

		ru = rules + nr->index;

		log_os_rule(nr, log);

		ru->index    = nr->index;
		ru->dst_len  = nr->dst_len;
		ru->ifid     = nr->ifid;

		ip6_cpy(&ru->dst, &nr->dst6);
		ip6_cpy(&ru->pref_src, &nr->pref_src6);
		ip6_cpy(&ru->next_hop, &nr->next_hop6);

		if (ip6_is_zero(&ru->next_hop))
			ru->with_next_hop = false;
		else
			ru->with_next_hop = true;
	}

	loginfo(r6->log, "route: got %d rules from system.\n", r6->rules_n);

	if (!got_default) // rules[0] is empty, no default route
		++r6->rules_n;

	nl_route_free(&osrules);

	return rules;
}

static struct route_map6 *route6_map_get(struct route6 *r6,
					 struct route_rule6 *ru)
{
	struct route_rule6 *t;
	struct route_map6 *m;
	int len, i;

	len = ru->dst_len & (~0x7);

	for (; len >= 24; len = len - 8) {
		for (i = r6->rules_n - 1; i >= 1; --i) {
			t = r6->rules + i;
			if (!t->map)
				continue;

			m = t->map;
			if (m->dst_len != len)
				continue;

			if (ip6_cmp(m->dst, &ru->dst, len))
				return m;
		}
	}

	return r6->map;
}

static void mapset(struct route_map6 *m, rt_map_item v, u32 off, u32 num)
{
	int i;

	for (i = 0; i < num; ++i)
		m->map[off + i] = v;
}

static void log_map_new(struct route_map6 *m, struct log *log, int def)
{
	struct in6_addr dst = {};
	char buf[100];

	ip6_copy_prefix(&dst, m->dst, m->dst_len);

	inet_ntop(AF_INET6, &dst, buf, sizeof(buf));

	logdebug(log, "create new  map(%p) %s/%d def: %d\n", m, buf, m->dst_len,
		 def);
}

static void log_map_set(struct log *log, struct route_map6 *m,
			struct route_rule6 *ru, u32 off,
			u32 num, u32 ref)
{
	char buf[100];

	inet_ntop(AF_INET6, m->dst, buf, sizeof(buf));

	logdebug(log, "set ru %d to map(%p) %s/%d off: %x num: %d\n",
		 ru->index, m, buf, m->dst_len, off, num);
}

static struct route_map6 *route6_map_new(struct route6 *r6, int def,
					 struct in6_addr *dst, u8 len)
{
	struct route_map6 *m;
	int size, num;

	m = malloc(sizeof(*m));
	if (!m)
		return NULL;

	num = len == 0 ? RT_MAIN_NUM : RT_SUB_NUM;

	size = sizeof(rt_map_item) * num;

	m->map = malloc(size);
	if (!m->map)
		return NULL;

	memset(m->map, 0, size);

	m->dst     = dst;
	m->dst_len = len;
	m->ref     = 0;
	m->def     = def;

	log_map_new(m, r6->log, def);

	return m;
}

static int route6_map_set(struct route6 *r6, struct route_map6 *m,
			  struct route_rule6 *ru)
{
	int map_size;
	u32 off, num;

	map_size = m->dst_len ? 8 : 24;

	off = ip6_slice(&ru->dst, m->dst_len, map_size);

	if (ru->dst_len > m->dst_len + map_size) {
		ru->map = route6_map_new(r6, m->map[off], &ru->dst,
					 ru_sub_prefix_len(ru));
		if (!ru->map)
			return -1;

		if (route6_map_set(r6, ru->map, ru))
			return -1;

		num = 1;
		m->map[off] = ru->index;
	} else {
		num = 1 << (m->dst_len + map_size - ru->dst_len);
		mapset(m, ru->index, off, num);
	}

	m->ref += 1;

	log_map_set(r6->log, m, ru, off, num, m->ref);

	return 0;
}

static void route6_map_free(struct route6 *r6, bool noref)
{
	struct route_rule6 *ru;
	u32 i;

	for (i = r6->rules_n - 1; i >= 1; --i) {
		ru = r6->rules + i;
		if (ru->issub)
			continue;

		if (ru->map) {
			if (noref && ru->map->ref)
				continue;

			free(ru->map->map);
			free(ru->map);
		}

		ru->map = NULL;
	}
}

static int route6_map_init(struct route6 *r6)
{
	struct route_rule6 *ru;
	struct route_map6 *m;
	u32 i;

	m = route6_map_new(r6, 0, &r6->rules[0].dst, 0);
	if (!m)
		return -1;

	r6->map = m;

	for (i = r6->rules_n - 1; i >= 1; --i) {
		ru = r6->rules + i;
		if (ru->issub)
			continue;

		m = route6_map_get(r6, ru);
		if (route6_map_set(r6, m, ru))
			return -1;
	}

	route6_map_free(r6, true);

	return 0;
}

static int route6_check_rules(struct route6 *r6)
{
	struct route_rule6 *r1, *r2;
	int i, j;

	// found the same dst
	for (i = 0; i < r6->rules_n; ++i) {
		r1 = r6->rules + i;
		if (r1->issub)
			continue;

		/* check for the same dst rules */
		for (j = i + 1; j < r6->rules_n; ++j) {
			r2 = r6->rules + j;

			if (r2->dst_len != r1->dst_len)
				continue;

			if (!ip6_eq(&r2->dst, &r1->dst))
				continue;

			r2->issub = true;
			r2->next = r1->next;
			r1->next = r2;
		}
	}

	return 0;
}

struct route6 *route6_init(struct log *log)
{
	struct route6 *r6;
	int ret;

	zobj(r6);
	if (!r6)
		return NULL;

	r6->log = log;

	r6->rules = route6_get_osrules(r6, r6->log);
	if (!r6->rules) {
		free(r6);
		return NULL;
	}

	route6_check_rules(r6);

	ret = route6_map_init(r6);
	if (ret) {
		route6_free(r6);
		return NULL;
	}

	return r6;
}

void route6_free(struct route6 *r6)
{
	route6_map_free(r6, false);
	free(r6->rules);
	free(r6);
}

