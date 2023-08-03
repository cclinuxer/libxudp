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

#ifndef  __KERN_H__
#define __KERN_H__
#include <linux/in6.h>

/* this is for user space c code. ebpf code should include helpers.h */

#define MAX_NIC_INDEX 400
#define MAX_IPPORT_NUM 10
#define MAX_CLUSTER_SLOT_NUM 256

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef __u64 u64;

struct kern_info {
	u16 reuse;
	u32 offset;

	int group_num;
	int nic_xskmap_offset[MAX_NIC_INDEX];
	int nic_xskmap_set_offset[MAX_NIC_INDEX];
};

struct kern_dict_item {
	u8  active;
	u16 reuse;
	u32 offset;
};

struct kern_ipport {
	__be32 addr[MAX_IPPORT_NUM];
	__be16 port[MAX_IPPORT_NUM];

	int ipport_n;

	struct in6_addr addr6[MAX_IPPORT_NUM];
	__be16 port6[MAX_IPPORT_NUM];

	int ipport6_n;
};

#define XUDP_MAP_STATS     0
#define XUDP_MAP_STATS_NUM 1
#define XUDP_MAP_NS        2
#define XUDP_MAP_NUM       3
#define XUDP_MAP_TS        4
#define XUDP_MAP_ID        50

#define MAP_XSKMAP       "map_xskmap"
#define MAP_STATS        "map_stats"
#define MAP_XSKMAP_SET   "map_xskmap_set"
#define MAP_INFO         "map_info"
#define MAP_DICT         "map_dict"
#define MAP_IPPORT       "map_ipport"

#ifdef XUDP_DEBUG
// cat /sys/kernel/debug/tracing/trace_pipe
#define printk(fmt, ...) \
{\
	const char f[] = fmt;\
	bpf_trace_printk(f, sizeof(f), ##__VA_ARGS__);\
}
#else
#define printk(fmt, ...)
#endif

#endif
