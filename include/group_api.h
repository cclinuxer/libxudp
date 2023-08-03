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

#ifndef  __GROUP_API_H__
#define __GROUP_API_H__

#include "log.h"

int __xudp_group_num(xudp *x);
int __xudp_group_unaligned(xudp *x);
int __xudp_nic_num(xudp *x);
int __xudp_nic_queue_num(xudp *x, int nicid);
struct log *__xudp_log(xudp *x);

int __xudp_xsk_ring_setup(xudp *x, struct ring *r, int sfd);
struct kern_info *__xudp_kern_info(xudp *x);
int __xudp_nic_ifindex(xudp *x, int nicid);
int __xudp_nic_queue_num(xudp *x, int ifindex);
int __xudp_xsk_bind(xudp *x, int ifindex, int queue_id, int sfd);
char *__xudp_umem_get_frames(xudp *x, int ifindex, int queue_id);
struct xdp_umem_uqueue *__xudp_umem_get_fq(xudp *x, int ifindex, int queue_id);
int __xudp_umem_get_headroom(xudp *x, int ifindex, int queue_id);
int __xudp_get_bpf_map(xudp *x, char *name);
struct log *__xudp_log(xudp *x);
int __xudp_kern_xsk_alloc(xudp *x, int num, int *offset);
int __xudp_kern_xsk_set(xudp *x, int offset, int sfd,
			int ifindex, int queue_id, int gid);
int __xudp_dict_active(xudp *x);

void __xudp_xsk_free(struct xdpsock *xsk);

xudp_channel *xudp_group_get_tx(xudp_group *g);
struct xdpsock *__xudp_rx_ref_tx(struct xdpsock *tx);
#endif


