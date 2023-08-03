/*
 * BSD 2-Clause License
 *
 * Copyright (c) 2021, Alibaba Group Holding Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <sys/socket.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <stdbool.h>
#include <stddef.h>

#include "bpf/bpf_helpers.h"

#include "bpf_endian.h"
#include "bpf_helper_defs.h"

#include "kern.h"
#include "ip6.h"
#include "packet_parse.h"

#define SEC(NAME) __attribute__((section(NAME), used))

char _license[] SEC("license") = "Dual BSD/GPL";

#define bpf_map struct bpf_map_def SEC("maps")

/* these will defined by libxudp */
bpf_map map_dict;
/* current xsk fd */
bpf_map map_xskmap;
/* all xsk fd */
bpf_map map_xskmap_set;

bpf_map map_info = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(struct kern_info),
	.max_entries = 1,
};

/* this used by xskmap_rr */
bpf_map map_rr = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(unsigned int),
	.max_entries = 1,
};

/* that will be defined by libxudp */
bpf_map map_ipport = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(struct kern_ipport),
	.max_entries = 1,
};


/* 0:    stats switch
 * 1:    stats packet count
 * 2:    net namespace id
 * 3:    xudp map num
 * 4-50: map id
 *
 * */

bpf_map map_stats = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 100,
};

struct xudp_ctx {
	struct xdp_md *xdp;

	struct pkthdrs hdrs;

	struct kern_info *info;

	u32 nic_offset;
	u32 rx_queue_index;
};

static int xskmap_dispatch(struct xudp_ctx *ctx);

#define access_ok(ctx, p) ((void *)(p + 1) <= (void *)(long)ctx->xdp->data_end)

static int __parse_packet(struct xudp_ctx *ctx)
{
	void *pkt, *end;

	pkt = (void *)(long)ctx->xdp->data;
	end = (void *)(long)ctx->xdp->data_end;

	return packet_parse(&ctx->hdrs, pkt, end);
}

static bool check_ipport(struct xudp_ctx *ctx)
{
	struct kern_ipport *ipport;
	struct pkthdrs *hdrs;
	int key = 0, i = 0;

	ipport = bpf_map_lookup_elem(&map_ipport, &key);
	if (!ipport)
		return false;

	hdrs = &ctx->hdrs;

	if (hdrs->family == AF_INET) {
#pragma unroll
		for (i = 0; i < MAX_IPPORT_NUM; ++i) {
			if (i >= ipport->ipport_n)
				return false;

			if (ipport->port[i] == ctx->hdrs.udp->dest) {
				if (ipport->addr[i] == ctx->hdrs.iph->daddr)
					return true;
				if (!ipport->addr[i])
					return true;
			}
		}
	} else {
		if (!access_ok(ctx, &ctx->hdrs.iph6->daddr))
			return false;
#pragma unroll
		for (i = 0; i < MAX_IPPORT_NUM; ++i) {
			if (i >= ipport->ipport6_n)
				return false;

			if (ipport->port6[i] == ctx->hdrs.udp->dest) {
				if (ip6_eq(&ipport->addr6[i], &ctx->hdrs.iph6->daddr))
					return true;
				if (ip6_is_zero(&ipport->addr6[i]))
					return true;
			}
		}
	}

	return false;
}

static int xudp_hash(struct xudp_ctx *ctx)
{
	int hash, i;

	if (ctx->hdrs.family == AF_INET)
		return (ctx->hdrs.iph->saddr >> 16) +
			(ctx->hdrs.iph->saddr & 0xffff)  +
			ctx->hdrs.udp->source;

	hash = ctx->hdrs.udp->source;

#pragma unroll
	for (i = 0; i < sizeof(ctx->hdrs.iph6->saddr)/4; ++i)
		hash += *((int *)&(ctx->hdrs.iph6->saddr) + i);

	return hash;
}

static int xskmap_go(struct xudp_ctx *ctx, unsigned int group_id)
{
	int key;

	group_id = group_id % ctx->info->group_num;

	key = ctx->nic_offset;
	key += ctx->rx_queue_index * ctx->info->group_num;
	key += group_id;

	/* when xsk is null, return XDP_PASS */
	return bpf_redirect_map(&map_xskmap, key, XDP_PASS);
}

static int stats_go(struct xudp_ctx *ctx)
{
	u32 key, *p, *value;

	key = 0;
	value = bpf_map_lookup_elem(&map_stats, &key);
	if (!value || !*value)
		return XDP_ABORTED;

	p = (u32 *)(ctx->hdrs.udp + 1);

	if (!access_ok(ctx, p))
		return XDP_DROP;

	key = 1;
	value = bpf_map_lookup_elem(&map_stats, &key);
	if (!value)
		return XDP_ABORTED;

	/* record stats request. */
	*value += 1;

	key = bpf_ntohl(*p);

	return xskmap_go(ctx, key);
}

static int xskmap_dict_go(struct xudp_ctx *ctx, u32 key)
{
	struct kern_dict_item *item;
	int ret;

	item = bpf_map_lookup_elem(&map_dict, &key);
	if (!item || !item->active)
		return -1;

	if (item->offset >= ctx->info->offset) {
		if (item->reuse != ctx->info->reuse - 1) {
			item->active = 0;
			return -1;
		}
	} else {
		if (item->reuse != ctx->info->reuse) {
			item->active = 0;
			return -1;
		}
	}

	key = ctx->nic_offset;
	key += item->offset;
	key += ctx->rx_queue_index;

	/* when xsk is null, return XDP_PASS */
	ret= bpf_redirect_map(&map_xskmap_set, key, XDP_PASS);

	/* that mean the xsk has been released, so that item should been set to
	 * noactive. */
	if (ret == XDP_PASS) {
		item->active = 0;
		return -1;
	}
	return ret;
}

static int xskmap_rr(struct xudp_ctx *ctx)
{
	unsigned int *rr;
	int key = 0;

	rr = bpf_map_lookup_elem(&map_rr, &key);
	if (!rr)
		return XDP_PASS;

	*rr = *rr + 1;

	return xskmap_go(ctx, *rr);
}

SEC("xdp_sock")
static int xdp_sock_prog(struct xdp_md *xdp)
{
	struct kern_info *info;
	struct xudp_ctx ctx;
	int ret, key;

	key = 0;
	info = bpf_map_lookup_elem(&map_info, &key);
	if (!info)
		return XDP_PASS;

	if (xdp->ingress_ifindex >= MAX_NIC_INDEX)
		return XDP_PASS;

	ctx.nic_offset = info->nic_xskmap_offset[xdp->ingress_ifindex];

	ctx.xdp = xdp;
	ctx.info = info;
	ctx.rx_queue_index = xdp->rx_queue_index;

	if (!__parse_packet(&ctx))
		return XDP_PASS;

	if (!check_ipport(&ctx))
		return XDP_PASS;

	if (ctx.hdrs.family == AF_INET && ctx.hdrs.iph->daddr == ctx.hdrs.iph->saddr)
		return stats_go(&ctx);

	ret = xskmap_dispatch(&ctx);

	return ret;
}

