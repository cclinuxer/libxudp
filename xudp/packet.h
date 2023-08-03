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

#ifndef  __PACKET_H__
#define __PACKET_H__
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>

#include <arpa/inet.h>
#include "log.h"
typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;
typedef __u8 u8;

struct packet_info {
	u8 family;
	unsigned char *dmac;
	unsigned char *smac;
	union {
		struct sockaddr_in *to;
		struct sockaddr_in6 *to6;
	};
	union {
		struct sockaddr_in *from;
		struct sockaddr_in6 *from6;
	};
	union {
		struct sockaddr_in _from;
		struct sockaddr_in6 _from6;
	};

	char *head;
	char *data;

	char *payload;
	int payload_size;

	char *packet;
	int len;
};

void xudp_packet_udp(struct packet_info *info);
void xudp_packet_udp_payload(struct packet_info *info);

#define XUDP_TX_HEADROOM (sizeof(struct ethhdr) + 2 + \
			  sizeof(struct ipv6hdr) + \
			  sizeof(struct udphdr))
#endif


