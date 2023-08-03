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

#include <sys/time.h>
#include <sys/shm.h>
#include <stdio.h>
#include "group.h"
#include "dump.h"


static struct dump_ring *get_dump_ring(struct dump *d, struct xudp_group *g)
{
	struct dump_ring *r;
	void *p;

	if (d->prepare) {
		if (g->dump)
			return g->dump;

		p = ((void *)d) + d->prepare;

		g->dump = p;

		return g->dump;
	}

	if (!g->dump) {
at:
		p = shmat(d->shmid, NULL, 0);
		if ((void *)-1 == p)
			return NULL;

		g->dump = p;
		r = g->dump;
	} else {
		r = g->dump;

		if (r->shmid != d->shmid) {
			shmdt(g->dump);
			goto at;
		}
	}

	return r;
}

static void dump_pkt(struct dump_ring *r, char *pkt, int len)
{
	struct dump_header header;
	struct timeval tv;
	int pkt_size, left;
	u64 pos;
	void *p;

	pkt_size = sizeof(struct dump_header) + len;
	pos = r->prod;

	if (pos + pkt_size - r->cons > r->size) {
		++r->drop;
		return;
	}

	gettimeofday(&tv, NULL);

	header.len     = len;
	header.tv_sec  = tv.tv_sec;
	header.tv_usec = tv.tv_usec;

	pos  = pos % r->size;
	p    = r->pkt  + pos;
	left = r->size - pos;

	if (left >= sizeof(header) + len) {
		memcpy(p, &header, sizeof(header));
		memcpy(p + sizeof(header), pkt, len);

	} else if (left >= sizeof(header)) {
		memcpy(p, &header, sizeof(header));

		left -= sizeof(header);

		memcpy(p + sizeof(header), pkt, left);
		memcpy(r->pkt, pkt + left, len - left);

	} else {
		memcpy(p, &header, left);

		memcpy(r->pkt, ((void *)&header) + left, sizeof(header) - left);
		memcpy(r->pkt + sizeof(header) - left, pkt, len);
	}

	u_smp_wmb();

	r->prod += pkt_size;
}

void dump_free(struct dump *d, struct xudp_group *g)
{
	struct dump_ring *r;

	if (d->prepare) {
		r = g->dump;
		madvise(r->pkt, r->size, MADV_DONTNEED);

	} else {
		shmdt(g->dump);
	}

	g->dump = NULL;
}

void dump(struct dump *d, struct xudp_group *g, char *pkt, int len)
{
	struct dump_ring *r;

	r = get_dump_ring(d, g);
	if (!r)
		return;

	pthread_spin_lock(&r->lock);
	dump_pkt(r, pkt, len);
	pthread_spin_unlock(&r->lock);
}

