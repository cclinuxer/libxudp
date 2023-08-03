#ifndef  __ROUTE6_H__
#define __ROUTE6_H__

#include "list.h"
#include "log.h"
#include "ip6.h"

typedef u16 rt_map_item;

#define ip6_prefix24(ip) ((ip[0] << 16) + (ip[1] << 8) + ip[2])
#define ip6_slice8(ip, pl) (ip[pl >> 3])

struct route_map6 {
	rt_map_item *map;
	struct in6_addr *dst;
	u8 dst_len;
	int ref;
	u32 def;
};

struct route_rule6 {
	struct in6_addr dst;
	u8 dst_len;
	bool with_next_hop;

	struct in6_addr pref_src;
	struct in6_addr next_hop;

	int ifid;
	int index;

	void *data;

	// for the same next_hop and dst_len
	struct route_rule6 *next;
	struct route_map6 *map;

	bool issub;
};

struct route6 {
	struct log *log;

	struct route_map6 *map;

	struct route_rule6 *rules;

	u32 rules_n;
};

static inline struct route_rule6 *route6_lookup(struct route6 *r6, struct in6_addr *dst)
{
	struct route_rule6 *rule;
	rt_map_item item;
	u32 hash;

	hash = ip6_prefix24(dst->s6_addr);

	item = r6->map->map[hash];

	while (true) {
		rule = r6->rules + item;

		if (!rule->map)
			return rule;

		hash = ip6_slice8(dst->s6_addr, rule->map->dst_len);
		item = rule->map->map[hash];

		if (item == 0)
			return r6->rules + rule->map->def;

		if (item == rule->index)
			return rule;
	}
}

struct route6 *route6_init(struct log *log);
void route6_free(struct route6 *r6);
#endif


