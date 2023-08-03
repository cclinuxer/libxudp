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

#ifndef  __TYPES_H__
#define __TYPES_H__

#define TX_BATCH_SIZE 100

enum{
	XDP_OFFSET_RX,
	XDP_OFFSET_TX,
	XDP_OFFSET_FR,
	XDP_OFFSET_CR,
};

struct xdp_ring_offset_v1 {
	__u64 producer;
	__u64 consumer;
	__u64 desc;
};

struct xdp_mmap_offsets_v1 {
	struct xdp_ring_offset_v1 rx;
	struct xdp_ring_offset_v1 tx;
	struct xdp_ring_offset_v1 fr;
	struct xdp_ring_offset_v1 cr;
};


struct xdp_ring_offset_v2 {
	__u64 producer;
	__u64 consumer;
	__u64 desc;
	__u64 flags;
};

struct xdp_mmap_offsets_v2 {
	struct xdp_ring_offset_v2 rx;
	struct xdp_ring_offset_v2 tx;
	struct xdp_ring_offset_v2 fr; /* Fill */
	struct xdp_ring_offset_v2 cr; /* Completion */
};
#define XSK_V1 1
#define XSK_V2 2


#ifndef XDP_OPTIONS
#define XDP_OPTIONS			8

struct xdp_options {
	__u32 flags;
};
#endif


#ifndef XDP_OPTIONS_ZEROCOPY
/* Flags for the flags field of struct xdp_options */
#define XDP_OPTIONS_ZEROCOPY (1 << 0)
#endif

#endif


