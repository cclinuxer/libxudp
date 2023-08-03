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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "route.h"
#include "log.h"
#include "xudp.h"

#define IP(a, b, c, d) ntohl((a << 24) + (b << 16) + (c << 8) + d)
#define IPX(a, b, c, d) ((a << 24) + (b << 16) + (c << 8) + d)
#define IPS(i) i>>24,i>>16&0xff,i>>8&0xff,i&0xff
#define IPSH(i)  IPS(ntohl(i))

int main(int argc, char **argv)
{
	struct log log = {};
	struct route_rule *rule;
	struct route *r;
	u32 dst;

	log.level = XUDP_LOG_DEBUG;


	r = route_init(&log);

	if (!r) {
		printf("route init fail\n");
		return -1;
	}

	if (argc == 2) {
		dst = inet_addr(argv[1]);
		rule = route_lookup(r, ntohl(dst));

		printf("\nlookup: %s id: %d next_hop: %d.%d.%d.%d src: %d.%d.%d.%d dev: %d\n",
		       argv[1], rule->index,
	       	       IPSH(rule->next_hop), IPSH(rule->pref_src), rule->ifid);
	}

	return 0;
}
