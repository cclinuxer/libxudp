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

#ifndef  __QUEUE_H__
#define __QUEUE_H__

#include <pthread.h>
#include <common.h>

#define umem_lock(x) pthread_spin_lock(&(x)->lock)
#define umem_unlock(x) pthread_spin_unlock(&(x)->lock)

typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;
typedef __u8 u8;

struct ring {
	u32 mask;
	u32 size;

	u32 cached_prod;
	u32 cached_cons;

	u32 *producer;
	u32 *consumer;
	u64 *flags;

	void *map;
	u64 map_size;

	union {
		u64 *addr;
		struct xdp_desc *desc;
	};
};

struct xdp_umem_uqueue {
	struct ring ring;

	pthread_spinlock_t lock;
};

struct xdp_uqueue {
	struct ring ring;
};

/* umem fq, cq options */

static inline u32 ring_free(struct ring *r, u32 n)
{
	u32 free_entries = r->cached_cons - r->cached_prod;

	if (free_entries >= n)
		return free_entries;

	/* Refresh the local tail pointer */
	r->cached_cons = *r->consumer + r->size;

	return r->cached_cons - r->cached_prod;
}

static inline u32 ring_avali(struct ring *r, u32 n)
{
	u32 entries = r->cached_prod - r->cached_cons;

	if (entries == 0) {
		r->cached_prod = *r->producer;
		entries = r->cached_prod - r->cached_cons;
	}

	return (entries > n) ? n : entries;
}

static inline u32 ring_left(struct ring *r)
{
	return *r->producer - *r->consumer;
}

static inline void ring_update_produce(struct ring *r)
{
	u_smp_wmb();
	*r->producer = r->cached_prod;
}

static inline void ring_update_consume(struct ring *r)
{
	u_smp_wmb();
	*r->consumer = r->cached_cons;
}

static inline u32 ring_next_con(struct ring *r)
{
	return r->cached_cons++ & r->mask;
}

static inline u32 ring_next_pro(struct ring *r)
{
	return r->cached_prod++ & r->mask;
}

static inline int fq_enq_nolock(struct xdp_umem_uqueue *fq,
					 struct xdp_desc *d,
					 size_t nb, u32 headroom)
{
	u32 i, idx;
	struct ring *r = &fq->ring;

	if (ring_free(r, nb) < nb)
		/* that will not happen */
		return -ENOSPC;

	for (i = 0; i < nb; i++) {
		idx = ring_next_pro(r);
		fq->ring.addr[idx] = d[i].addr - headroom;
	}

	ring_update_produce(r);

	return 0;
}

static inline int fq_enq(struct xdp_umem_uqueue *fq,
			 struct xdp_desc *d,
			 size_t nb, u32 headroom)
{
	int ret;
	umem_lock(fq);
	ret = fq_enq_nolock(fq, d, nb, headroom);
	umem_unlock(fq);
	return ret;
}

static inline size_t cq_deq(struct xdp_umem_uqueue *cq,
			    u64 *d, size_t nb)
{
	u32 idx, i, entries;
	struct ring *r = &cq->ring;

	umem_lock(cq);

	entries = ring_avali(r, nb);

	u_smp_rmb();

	if (entries > 0) {
		for (i = 0; i < entries; i++) {
			idx = ring_next_con(r);
			d[i] = cq->ring.addr[idx];
		}

		ring_update_consume(r);
	}

	umem_unlock(cq);

	return entries;
}

static inline int xq_enq(struct xdp_uqueue *uq,
			 const struct xdp_desc *descs,
			 unsigned int ndescs)
{
	struct ring *r = &uq->ring;
	unsigned int i, idx;

	if (ring_free(r, ndescs) < ndescs)
		return -ENOSPC;

	for (i = 0; i < ndescs; i++) {
		idx = ring_next_pro(r);

		r->desc[idx].addr = descs[i].addr;
		r->desc[idx].len  = descs[i].len;
	}

	ring_update_produce(r);
	return 0;
}

static inline int xq_deq(struct xdp_uqueue *uq,
			 struct xdp_desc *descs,
			 int ndescs)
{
	struct ring *r = &uq->ring;
	unsigned int idx;
	int i, entries;

	entries = ring_avali(r, ndescs);

	u_smp_rmb();

	for (i = 0; i < entries; i++) {
		idx = ring_next_con(r);
		descs[i] = r->desc[idx];
	}

	if (entries > 0)
		ring_update_consume(r);

	return entries;
}

#endif


