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

#ifndef  __IFAPI_H__
#define __IFAPI_H__

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <linux/sockios.h>
#include <linux/ethtool.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include <netlink/netlink.h>
#include <linux/netlink.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <time.h>
#include "log.h"
#include "list.h"

int ifgetchannels(const char *name, int *rx, int *tx);
int ifgetringsize(const char *name, int *rx, int *tx);

int nl_xdp_set(int ifindex, int fd, __u32 flags, struct log *log);
void nl_xdp_off(int ifindex, struct log *log);

typedef __u8 u8;

struct nl_addr {
	struct nl_addr *next;
	unsigned char prefixlen;
	int family;
	union {
		__be32 addr;
		struct in6_addr addr6;
	};
};

struct nl_info{
	struct nl_info *next;

	struct nl_info *master;
	bool isbond;
	bool ismaster;

	int ref;

	char ifname[IFNAMSIZ];
	int  ifindex;
	unsigned char mac[6];
	unsigned int mtu;
	unsigned int xdp_prog_id;

	struct nl_addr *addr;

        unsigned short ifi_type;   /* Device type */
        unsigned int   ifi_flags;  /* Device flags  */
};

typedef __u32 u32;

struct nl_route {
	struct list_head list;

	u32 mask;
	u32 dst_h;

	union {
		__be32 dst;
		struct in6_addr dst6;
	};

	union {
		__be32 pref_src;
		struct in6_addr pref_src6;
	};

	union {
		__be32 next_hop;
		struct in6_addr next_hop6;
	};

	char dst_len;
	int ifid;
	unsigned char index;
};

int nl_link(struct nl_info **ni, int ifindex, struct log *log);
int nl_link_byname(struct nl_info **_ni, const char *name, struct log *log);
int nl_neigh(__be32 addr, unsigned char *mac, struct log *log);
int nl_neigh6(struct in6_addr *addr, unsigned char *mac, struct log *log);
int __nl_route(struct list_head *head, u8 family, struct log *log);
#define nl_route(head, log) __nl_route(head, AF_INET, log)
#define nl_route6(head, log) __nl_route(head, AF_INET6, log)

void nl_route_free(struct list_head *head);
/* free nl_info
 *
 * force true: free all nl_info
 *       false: free all no ref nl_info, and return the left item
 *
 *
 * */
struct nl_info *nl_info_free(struct nl_info *ia, bool force);
#endif


