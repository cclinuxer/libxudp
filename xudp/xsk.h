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

#ifndef  __XSKMAP_H__
#define __XSKMAP_H__

int xudp_tx_xsk_init(xudp *x);
void xudp_tx_xsk_free(xudp *x);
int xudp_umem_check(xudp *x);
int xudp_group_create_all(xudp *x);

int xsk_cq_cache_init(xudp *x, struct txch *txch,
		      struct xdp_umem *umem);


#endif


