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

#ifndef  __XUDP_TYPES_H__
#define __XUDP_TYPES_H__

#include <errno.h>
#include <libgen.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <net/ethernet.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <time.h>
#include <sys/types.h>
#include <poll.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <net/if.h>
#include <linux/if_xdp.h>
#include <linux/if_link.h>

#include <linux/ip.h>
#include <linux/udp.h>

#include "packet.h"
#include "bpf.h"
#include "xudp.h"
#include "kern_ops.h"
#include "list.h"
#include "config.h"
#include "types.h"
#include "log.h"
#include "common.h"
#include "queue.h"
#include "ip6.h"
#include "kern.h"
#include "channel.h"
#include "group_api.h"
#include "dump.h"

struct xdp_umem {
	/* list for nic */
	struct list_head list;

	int queue_id;
	int sfd;
	bool shared;

	char *frames;
	u64   frames_size;
	struct xdp_umem_uqueue fq;
	struct xdp_umem_uqueue cq;

	int version;

	u32 cq_used;
	u32 cq_cache_max;
	u32 headroom;
	u32 tx_proc_n;
};

struct txch {
	struct xdpsock xsk;

	struct xdp_umem *umem;

	struct tx_frame_info *frame;
	/* alloc to user */
	u64 frame_alloc;
	/* the frame holded by tx */
	u64 frame_queue;
	u64 frame_sent;

    	u32 need_commit;

	bool zc;

	/* fast link */
	struct xudp_nic *nic;
};

struct xudp_nicxsk{
	/* list for xskmap */
	struct list_head list;

	struct xudp_nic    *nic;
	struct xudp_xskmap *xskmap;

	struct xsk_group  *xsk_group;
	u32 xsk_group_size;
};

struct xudp_xskmap{
	struct xudp_xskmap *next;

	int id;
	u16 arrayid;
	int channels_n;

	int mapfd;// bpf xsk map fd

	struct list_head nicxsk;

	struct xudp *x;

	bool freed;
};

struct xudp_nic {
	struct xudp_nic *next;

	struct xudp *x;

	int nic_index;
	int queue;
	int txring_n;

	struct nl_info *ni;


	int link_fd;

	/* this addr include the port and ip. ip may be 0.0.0.0 */
	struct sockaddr_in *addr;
	struct sockaddr_in6 *addr6;

	int addr4_n;
	int addr6_n;

	int tx_n;

	struct xdp_umem **umem;
};

struct xudp {
	/* this must first one */
	struct dump dump;

	bool       udp_alloc;
	int        udp_fd;

	struct bpf bpf;
	bool       bpf_need_free;

	int stats_map;

	int flags;
	u32 group_counter;

	struct txch *tx_xsk;

	/* nic */
	struct xudp_nic *nic;
	int nic_n;
	int queue_n;

	struct log     *log;
	struct nl_info *nlinfo;

	/* read mostly */
	struct route  *route;
	struct route6 *route6;
	int tx_batch_num;
	int frame_size;
	int noarp;

	struct xudp_conf conf;

	bool map_xskmaps_active;
	bool map_dict_active;

	pthread_spinlock_t  xskmap_set_lock;
	struct kern_info kern_info;
	u32 map_xskmap_set_num;

	struct list_head dummy_xsk;

	/* save all groups without isolate */
	struct xudp_group **groups;
};

#endif


