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
 * Group and xudp have a weak reference relationship, which can be released
 * easily and can be released without calling any interface. This is very
 * convenient for many scenarios, such as under the master/worker model, the
 * worker can exit directly without affecting the overall libxudp. And the life
 * cycle of the group is the same as that of the worker.
 */

#include <sys/capability.h>
#include "group.h"
#include "kern.h"
#include "bpf.h"

/* check for the CAP of the current process */
static int xudp_group_cap()
{
	struct __user_cap_header_struct hdr;
	struct __user_cap_data_struct data;

	hdr.version = _LINUX_CAPABILITY_VERSION_1;
	hdr.pid = getpid();
	capget(&hdr, &data);

	if (data.effective & XUDP_CAP)
		return 0;

	if (!(data.permitted & XUDP_CAP))
		return -1;

	data.effective |= XUDP_CAP;
	return capset(&hdr, &data);
}

static struct xdpsock *xsk_rx_init(xudp *x, struct xdpsock *xsk)
{
	int sfd, ret;

	sfd = socket(PF_XDP, SOCK_RAW, 0);
	if (sfd < 0) {
		logerr(x, "create AF_XDP fail. %s.\n", strerror(errno));
		return NULL;
	}

	xsk->sfd = sfd;

	/* call xudp group api to setup the ring */
	if (__xudp_xsk_ring_setup(x, &xsk->ring.ring, sfd))
		return NULL;

	ret = __xudp_xsk_bind(x, xsk->ifindex, xsk->queue_id, sfd);
	if (ret < 0) {
		logerr(x, "AF_XDP fd bind fail. %s\n", strerror(errno));
		return NULL;
	}

	/* These variables will be used frequently later, copy in advance. */
	xsk->frames   = __xudp_umem_get_frames(x,   xsk->ifindex, xsk->queue_id);
	xsk->fq       = __xudp_umem_get_fq(x,       xsk->ifindex, xsk->queue_id);
	xsk->headroom = __xudp_umem_get_headroom(x, xsk->ifindex, xsk->queue_id);

        logdebug(x, "xsk create to dev(%d: %d %p). rx size: %d %s\n",
	       	 xsk->ifindex, xsk->queue_id, xsk,
		 xsk->ring.ring.size,
	       	 strerror(errno));

	return xsk;
}

static int xudp_group_init_nic_xsk(struct xudp_group *g,
				   struct xudp_group_nic *gnic)
{
	struct xdpsock *xsk;
	struct rxch *rxch;
	int i;

	for (i = 0; i < gnic->xsk_n; ++i) {
		rxch = gnic->rxch + i;
		xsk = &rxch->xsk;

		rxch->group = g;

		xsk->sfd      = -1;

		xsk->queue_id = i;
		xsk->ifindex  = gnic->ifindex;

		xsk->gid      = g->gid;

		xsk->x        = g->x;
		xsk->group    = g;
		xsk->tx_xsk   = __xudp_rx_ref_tx(g->tx_xsk);
		rxch->unaligned = __xudp_group_unaligned(g->x);

		xsk = xsk_rx_init(g->x, xsk);
		if (!xsk)
			return -1;
	}

	return 0;
}

static int xudp_group_init_xsk(struct xudp_group *g, int nicid)
{
	struct xudp_group_nic *gnic;
	int size, n, ifindex;

	ifindex = __xudp_nic_ifindex(g->x, nicid);

	n = __xudp_nic_queue_num(g->x, ifindex);

	size = sizeof(*gnic) + sizeof(struct rxch) * n;
	gnic = malloc(size);
	if (!gnic) {
		logerr(g->x, "fail alloc for gnic.\n");
		return -1;
	}

	memset(gnic, 0, size);

	gnic->xsk_n = n;
	gnic->ifindex =  ifindex;

	list_insert(&g->nics, &gnic->list);
	g->xsk_n += n;

	return xudp_group_init_nic_xsk(g, gnic);
}

static int xudp_group_kern_set(xudp *x, int offset, struct xdpsock *xsk)
{
	return __xudp_kern_xsk_set(x, offset, xsk->sfd,
				   xsk->ifindex, xsk->queue_id, xsk->gid);
}

static int xudp_group_kern(xudp *x, struct xudp_group *g)
{
	struct xudp_group_nic *gnic;
	struct xdpsock *xsk;
	int offset, ret, i;

	offset = 0;
	if (__xudp_dict_active(x)) {
		ret = __xudp_kern_xsk_alloc(x, g->xsk_n, &offset);
		if (ret < 0) {
			logerr(x, "group alloc for kern xsk fail\n");
			return -1;
		}

		g->map_offset = offset;
	}

	list_for_each_entry(gnic, &g->nics, list) {
		for (i = 0; i < gnic->xsk_n; ++i) {
			xsk = &(gnic->rxch + i)->xsk;
			if (xudp_group_kern_set(x, offset, xsk) < 0) {
				logerr(x, "group kern set err\n");
				return -1;
			}
		}
	}

	return 0;
}

void xudp_group_free(struct xudp_group *g)
{
	struct xudp_group_nic *gnic, *t;
	struct xdpsock *xsk;
	struct rxch *rxch;
	int i;

	if (g->tx_xsk)
		xudp_txch_put(g->tx_xsk);

	list_for_each_entry_safe(gnic, t, &g->nics, list) {
		list_del(&gnic->list);

		for (i = 0; i < gnic->xsk_n; ++i) {
			rxch = gnic->rxch + i;
			xsk = &rxch->xsk;

			if (xsk->x && xsk->sfd != -1)
				__xudp_xsk_free(xsk);
		}

		free(gnic);
	}

	free(g);
}

/* create one new group */
struct xudp_group *xudp_group_new(xudp *x, int gid)
{
	struct xudp_group *g;
	int i, nic_num;
	int ret;

	if (gid >= __xudp_group_num(x)) {
		logerr(x, "gid too big\n");
		return NULL;
	}

	/* Check the cap permissions required by socket(AF_XDP,...). If
	 * possible, try to recover from the permitted permissions to
	 * effective.
	 *
	 * If the current process does not have the corresponding cap
	 * permission, it will fail when calling socket(AF_XDP, ..) finally.
	 */
	xudp_group_cap();

	g = malloc(sizeof(*g));
	if (!g) {
		logerr(x, "alloc for group fail.\n");
		return NULL;
	}

	memset(g, 0, sizeof(*g));

	g->x = x;
	g->gid = gid;
	g->tx_xsk = xudp_txch_get(x, gid);
	if (!g->tx_xsk) {
		logerr(x, "group get tx fail\n");
		goto err;
	}
	g->tx_xsk->group = g;

	INIT_LIST_HEAD(&g->nics);

	/* init rx xdp socket */
	nic_num = __xudp_nic_num(x);
	for (i = 0; i < nic_num; ++i) {
		if (xudp_group_init_xsk(g, i))
			goto err;
	}

	/* config for xdp map */
	ret = xudp_group_kern(x, g);
	if (ret)
		goto err;

	return g;
err:
	xudp_group_free(g);
	return NULL;
}

int xudp_dict_set_group_key(struct xudp_group *g, int key)
{
	struct kern_dict_item item = {};
	struct kern_info *info;
	int map, ret;

	if (!__xudp_dict_active(g->x))
		return 0;

	map = __xudp_get_bpf_map(g->x, MAP_DICT);
	if (map < 0) {
		logerr(g->x, "xudp_dict_set_group_key not found map_dict\n");
		return -1;
	}

	info = __xudp_kern_info(g->x);

	item.offset = g->map_offset;
	item.reuse  = info->reuse;
	item.active = 1;

	ret = bpf_map_update_elem(map, &key, &item, 0);
	if (ret) {
		loginfo(g->x, "dict update fail: key: %d group_id: %d. %s\n",
	       	       	key, g->gid, strerror(errno));
	} else {
		loginfo(g->x, "dict update success: key: %d group_id: %d\n",
	       	       	key, g->gid);
	}

	return ret;
}

xudp_channel *xudp_group_channel_first(struct xudp_group *g)
{
	struct xudp_group_nic *gnic;

	gnic = list_first_entry(&g->nics, struct xudp_group_nic, list);

	return &gnic->rxch->xsk;
}

xudp_channel *xudp_group_channel_next(xudp_channel *ch)
{
	struct xudp_group_nic *gnic;
	struct xudp_group *g;
	struct xdpsock *xsk;
	struct rxch *rxch;
	int found = 0, i;

	if (ch->istx)
		return NULL;

	rxch = (struct rxch *)ch;
	g = rxch->group;

	list_for_each_entry(gnic, &g->nics, list) {
		for (i = 0; i < gnic->xsk_n; ++i) {
			xsk = &(gnic->rxch + i)->xsk;
			if (found)
				return xsk;

			if (xsk == ch)
				found = 1;
		}
	}

	return g->tx_xsk;
}

xudp_channel *xudp_group_get_tx(xudp_group *g)
{
	return g->tx_xsk;
}

