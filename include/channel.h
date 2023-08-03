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

#ifndef  __CHANNEL_H__
#define __CHANNEL_H__

#include "xudp.h"
#include "list.h"
#include "queue.h"
#include "dump.h"

struct xsk_stats {
	u64 send_ebusy;
	u64 send_again;
	u64 send_err;
	u64 send_success;

	u64 no_cq;
	u64 no_tx;

	u64 rx_npkts;
	u64 tx_npkts;
};

struct xsk_stats_output {
	/* normal vals */
	u64 nanosecond;

	int ch_id;
	int g_id;
	int group_num;
	int is_tx;

	/* stats */
	struct xsk_stats stats;

	u64 xsk_rx_dropped;
	u64 xsk_rx_invalid_descs;
	u64 xsk_tx_invalid_descs;

	int kern_tx_num;
};

struct xdpsock {
	struct list_head list;

	int sfd;

	/* group id*/
    	int gid;

	/* id of queue of nic */
	int ifindex;
	int queue_id;
	bool istx;

	struct xdp_uqueue ring;

	struct xsk_stats stats;
	char *frames;

	struct xdp_umem_uqueue *fq; // used by rx

	int headroom;

	struct xdpsock *tx_xsk;

	xudp *x;

	struct xudp_group *group;
};

struct xudp_group {
	xudp *x;
	int gid;
	struct list_head nics;
	int xsk_n;
	struct xdpsock *tx_xsk;

	int map_offset;
	void *dump;
};

void dump(struct dump *d, struct xudp_group *g, char *pkt, int len);
void dump_free(struct dump *d, struct xudp_group *g);

static inline void dump_check(xudp *x, struct xudp_group *g, char *pkt, int len)
{
	struct dump *d = (struct dump *)x;

	if (d->active == XUDP_DUMP_ACTIVE) {
		dump(d, g, pkt, len);
	} else {
		if (g->dump)
			dump_free(d, g);
	}
}
#endif


