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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <linux/types.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>

#include "ifapi.h"
#include "neigh.h"
#include "xudp_types.h"
#include "ip6.h"

/* this just for test, aliyun ecs not can set config.noarp. */

struct ipmac {
	union {
		__be32 addr;
		struct in6_addr addr6;
	};
	unsigned char  mac[6];
};

static struct ipmac cache[10];
static int cache_n;
static pthread_spinlock_t lock;

int ping(const char *ip);

int neigh_init()
{
	return pthread_spin_init(&lock, PTHREAD_PROCESS_SHARED);
}

static int ng_dst_eq(struct ipmac *p, void *dst, int family)
{
	if (family == AF_INET)
		return p->addr == *(__be32*)dst;

	return ip6_eq(&p->addr6, (struct in6_addr*)dst);
}

static unsigned char *__neigh_get(void* dst, int family, struct log *log)
{
	int i;
	struct ipmac *p;
	unsigned char mac[6];


	for (i = 0; i < cache_n; ++i) {
		p = cache + i;

		if (ng_dst_eq(p, dst, family))
			return p->mac;
	}

	if (cache_n >= sizeof(cache)/sizeof(cache[0])) {
		logdebug(log, "tmp: arp limit %d\n", cache_n);
		return NULL;
	}

	pthread_spin_lock(&lock);

	for (i = 0; i < cache_n; ++i) {
		p = cache + i;

		if (ng_dst_eq(p, dst, family)) {
			pthread_spin_unlock(&lock);
			return p->mac;
		}
	}

	p = &cache[cache_n];

	if (family == AF_INET) {
		char ip[20] = {};
		struct in_addr a;

		a.s_addr = *(__be32*)dst;

		strcpy(ip, inet_ntoa(a));

		logdebug(log, "neigh: get arp. ping sent. for %s\n", ip);
		ping(ip);

		if (nl_neigh(*(__be32*)dst, mac, log)) {
			pthread_spin_unlock(&lock);
			logdebug(log, "neigh: get arp fail\n");
			return NULL;
		}

		p->addr = *(__be32 *)dst;

	} else {
		if (nl_neigh6((struct in6_addr *)dst, mac, log)) {
			pthread_spin_unlock(&lock);
			logdebug(log, "neigh: get arp fail\n");
			return NULL;
		}
		ip6_cpy(&p->addr6, dst);
	}

	memcpy(p->mac, mac, 6);
	++cache_n;

	pthread_spin_unlock(&lock);
	return p->mac;
}

unsigned char *neigh_get(__be32 addr, struct log *log)
{
	return __neigh_get(&addr, AF_INET, log);
}

unsigned char *neigh6_get(struct in6_addr *addr, struct log *log)
{
	return __neigh_get(addr, AF_INET6, log);

}
