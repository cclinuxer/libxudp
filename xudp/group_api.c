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

#include "xudp_types.h"

int __xudp_group_num(xudp *x)
{
	return x->conf.group_num;
}

int __xudp_group_unaligned(xudp *x)
{
	return x->conf.unaligned;
}

int __xudp_nic_num(xudp *x)
{
	return x->nic_n;
}

int __xudp_dict_active(xudp *x)
{
	return x->map_dict_active;
}

struct kern_info *__xudp_kern_info(xudp *x)
{
	return &x->kern_info;
}

static struct xudp_nic *xudp_get_nic(xudp *x, int ifindex)
{
	struct xudp_nic *n;

	for (n = x->nic; n; n = n->next) {
		if (n->nic_index == ifindex)
			return n;
	}

	return NULL;
}

int __xudp_nic_ifindex(xudp *x, int nicid)
{
	struct xudp_nic *n;
	int i = 0;

	for (n = x->nic; n; n = n->next) {
		if (i == nicid)
			return n->nic_index;
		++i;
	}

	return 0;
}

int __xudp_nic_queue_num(xudp *x, int ifindex)
{
	struct xudp_nic *n;

	n = xudp_get_nic(x, ifindex);

	if (!n)
		return 0;

	return n->queue;
}

static struct xdp_umem *umem_get(xudp *x, int ifindex, int queue_id)
{
	struct xudp_nic *n;

	n = xudp_get_nic(x, ifindex);
	if (!n)
		return NULL;

	return n->umem[queue_id];
}

char *__xudp_umem_get_frames(xudp *x, int ifindex, int queue_id)
{
	struct xdp_umem *umem;

	umem = umem_get(x, ifindex, queue_id);
	if (!umem)
		return NULL;

	return umem->frames;
}

struct xdp_umem_uqueue *__xudp_umem_get_fq(xudp *x, int ifindex, int queue_id)
{
	struct xdp_umem *umem;

	umem = umem_get(x, ifindex, queue_id);
	if (!umem)
		return NULL;

	return &umem->fq;
}

int __xudp_umem_get_headroom(xudp *x, int ifindex, int queue_id)
{
	struct xdp_umem *umem;

	umem = umem_get(x, ifindex, queue_id);
	if (!umem)
		return 0;

	return umem->headroom;
}

int __xudp_get_bpf_map(xudp *x, char *name)
{
	return bpf_map_get(&x->bpf, name);
}

struct log *__xudp_log(xudp *x)
{
	return x->log;
}

struct xdpsock *__xudp_rx_ref_tx(struct xdpsock *tx)
{
	return tx->tx_xsk;
}

