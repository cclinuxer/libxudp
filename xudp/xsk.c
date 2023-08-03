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

#include <pthread.h>

#include "xudp_types.h"
#include "kern.h"
#include "ifapi.h"
#include "channel.h"
#include "xsk.h"

#define XSKMAP_GROUP_ACTIVE_NONE -1
#define XSKMAP_GROUP_ACTIVE_ALL  -2

#define xsk_map(size, fd, offset) mmap(NULL, size,           \
                		       PROT_READ|PROT_WRITE,                      \
		        	       MAP_SHARED | MAP_POPULATE, \
                		       fd, offset);
#define xsk_set_skopt(fd, opt, val) setsockopt(fd, SOL_XDP, opt, &val, sizeof(val));


static void xudp_xsk_free(struct xdpsock *xsk);

static u32 xsk_cq_cache_max(xudp *x)
{
	return MIN(x->conf.sndnum / 2, 256);
}

static u32 umem_tx_txch_num(struct xudp_nic *nic, int qid)
{
	int tx_proc_n;

	tx_proc_n = nic->tx_n / nic->queue;
	if (qid < (nic->tx_n % nic->queue))
		++tx_proc_n;

	return tx_proc_n;
}

static int umem_calc_for_cq(xudp *x, struct xudp_nic *nic, u32 sndnum, int qid)
{
	u32 tx_proc_n, sn;

	tx_proc_n = umem_tx_txch_num(nic, qid);

	if (!tx_proc_n)
		return 2;// cq can not be 0

	/* (xsk tx num + xsk user cache) * share process + dev tx num
	 * (ethtool -g dev to get the dev tx num)
	 *
	 * We must guarantee
	 *     1. All other tx proc cq caches are full
	 *     2. All tx proc tx is full
	 *     3. The channel ring of the network card corresponding to
	 *	  umem is full
	 *  We can still get the item from cq
	 *
	 *
	 * */
	sn = (sndnum + xsk_cq_cache_max(x)) * tx_proc_n;
	sn += nic->txring_n;

	sn = get_power_of_2(sn);

	return sn;
}

static int ring_setup(struct ring *r, int fd,
		      int num, int type, struct log *log)
{
	void *map;
	int s, size, ret, version;
	u64 flag = 0;
	struct xdp_mmap_offsets_v1 *offs1;
	struct xdp_mmap_offsets_v2 *offs, _offs;
	struct xdp_ring_offset_v2 *off = NULL;

	socklen_t optlen;

	optlen = sizeof(_offs);

	ret = getsockopt(fd, SOL_XDP, XDP_MMAP_OFFSETS, &_offs, &optlen);
	if (ret)
		return -1;

	if (optlen == sizeof(struct xdp_mmap_offsets_v1))
		version = XSK_V1;
	else
		version = XSK_V2;

	offs = &_offs;

	if (version >= XSK_V2) {
		switch(type) {
		case XDP_OFFSET_RX:
			off = &offs->rx;
			flag = XDP_PGOFF_RX_RING;
			break;
		case XDP_OFFSET_TX:
			off = &offs->tx;
			flag = XDP_PGOFF_TX_RING;
			break;
		case XDP_OFFSET_FR:
			off = &offs->fr;
			flag = XDP_UMEM_PGOFF_FILL_RING;
			break;
		case XDP_OFFSET_CR:
			off = &offs->cr;
			flag = XDP_UMEM_PGOFF_COMPLETION_RING;
			break;
		}
	} else {
		offs1 = (struct xdp_mmap_offsets_v1*)offs;
		switch(type) {
		case XDP_OFFSET_RX:
			off = (struct xdp_ring_offset_v2 *)&offs1->rx;
			flag = XDP_PGOFF_RX_RING;
			break;
		case XDP_OFFSET_TX:
			off = (struct xdp_ring_offset_v2 *)&offs1->tx;
			flag = XDP_PGOFF_TX_RING;
			break;
		case XDP_OFFSET_FR:
			off = (struct xdp_ring_offset_v2 *)&offs1->fr;
			flag = XDP_UMEM_PGOFF_FILL_RING;
			break;
		case XDP_OFFSET_CR:
			off = (struct xdp_ring_offset_v2 *)&offs1->cr;
			flag = XDP_UMEM_PGOFF_COMPLETION_RING;
			break;
		}
	}

	size = 0;
	switch(type) {
	case XDP_OFFSET_RX:
	case XDP_OFFSET_TX:
		size = sizeof(struct xdp_desc);
		break;

	case XDP_OFFSET_FR:
	case XDP_OFFSET_CR:
		size = sizeof(u64);
		break;
	}

	s = off->desc + num * size;
	map = xsk_map(s, fd, flag);
	if (map == MAP_FAILED)
		return -1;

	r->map      = map;
	r->map_size = s;
	r->mask     = num - 1;
	r->size     = num;
	r->producer = map + off->producer;
	r->consumer = map + off->consumer;

	if (version >= XSK_V2)
		r->flags = map + off->flags;

	switch(type) {
	case XDP_OFFSET_FR:
		r->cached_cons = num;
		r->addr = map + off->desc;
		break;

	case XDP_OFFSET_CR:
		r->addr = map + off->desc;
		break;

	case XDP_OFFSET_RX:
		r->desc = map + off->desc;
		break;

	case XDP_OFFSET_TX:
		r->cached_cons = num;
		r->desc = map + off->desc;
		break;
	}
	return 0;
}

int __xudp_xsk_ring_setup(xudp *x, struct ring *r, int sfd)
{
	int ret;

	ret = xsk_set_skopt(sfd, XDP_RX_RING, x->conf.rcvnum);
	if (ret)
		return ret;

	return ring_setup(r, sfd, x->conf.rcvnum, XDP_OFFSET_RX, x->log);
}

static bool xsk_is_zc(int fd, struct log *log)
{
	struct xdp_options opts = {};
	int ret;
	socklen_t len;

	len = sizeof(opts);
	ret = getsockopt(fd, SOL_XDP, XDP_OPTIONS, &opts, &len);
	if (ret) {
		logdebug(log, "getsockopt XDP_OPTIONS fail: %s\n", strerror(errno));
		return false;
	}

	return opts.flags & XDP_OPTIONS_ZEROCOPY;
}

static struct xdp_umem *__umem_configure(xudp *x, int sfd, u32 size,
					 u32 fq_num, u32 cq_num, int *err)
{
	struct xdp_umem_reg mr = {};
	struct xdp_umem *umem;
	struct xdp_desc d;
	u64 i, bufsize;
	void *bufs;
	int ret;

	bufsize = size * (fq_num + cq_num);

    	bufs = anon_map(bufsize);
	if (bufs == MAP_FAILED || bufs == NULL) {
		logerr(x->log, "umem configure map alloc %lu\n", bufsize);
		*err = -XUDP_ERR_UMEM_INIT_ALLOC;
		return NULL;
	}

	if ((u64)bufs % getpagesize()) {
		munmap(bufs, bufsize);
		logerr(x->log, "umem configure map not align\n");
		*err = -XUDP_ERR_UMEM_INIT_ALIGN;
        	return NULL;
	}

    	umem = anon_map(sizeof(*umem));
	if (umem == MAP_FAILED || umem == NULL) {
		munmap(bufs, bufsize);
		logerr(x->log, "umem configure map alloc for *umem\n");
		*err = -XUDP_ERR_UMEM_INIT_ALLOCS;
		return NULL;
	}

	mr.addr       = (__u64)bufs;
	mr.headroom   = x->conf.headroom;
	mr.len        = bufsize;
	mr.chunk_size = size;
#if XDP_UMEM_UNALIGNED_CHUNK_FLAG
	if (x->conf.unaligned)
		mr.flags = XDP_UMEM_UNALIGNED_CHUNK_FLAG;
#endif

	loginfo(x->log, "create umem: fq: %d cq: %d size: %d, headroom=%d, chunk_size=%d\n",
		fq_num, cq_num, mr.len, mr.headroom, mr.chunk_size);

	ret = xsk_set_skopt(sfd, XDP_UMEM_REG,             mr);
	if (ret) {
		logerr(x->log, "umem configure XDP_UMEM_REG\n");
		*err = -XUDP_ERR_UMEM_INIT_REG;
		goto err;
	}

	ret = xsk_set_skopt(sfd, XDP_UMEM_FILL_RING,       fq_num);
	if (ret) {
		logerr(x->log, "umem configure XDP_UMEM_FILL_RING\n");
		*err = -XUDP_ERR_UMEM_INIT_F;
		goto err;
	}

	ret = xsk_set_skopt(sfd, XDP_UMEM_COMPLETION_RING, cq_num);
	if (ret) {
		logerr(x->log, "umem configure XDP_UMEM_COMPLETION_RING\n");
		*err = -XUDP_ERR_UMEM_INIT_C;
		goto err;
	}

	ret = ring_setup(&umem->fq.ring, sfd, fq_num, XDP_OFFSET_FR, x->log);
	if (ret) {
		logerr(x->log, "umem configure XDP_OFFSET_FR\n");
		*err = -XUDP_ERR_UMEM_INIT_FR;
		goto err;
	}

	ret = ring_setup(&umem->cq.ring, sfd, cq_num, XDP_OFFSET_CR, x->log);
	if (ret) {
		logerr(x->log, "umem configure XDP_OFFSET_CR\n");
		*err = -XUDP_ERR_UMEM_INIT_CR;
		goto err;
	}

	pthread_spin_init(&umem->fq.lock, PTHREAD_PROCESS_SHARED);
	pthread_spin_init(&umem->cq.lock, PTHREAD_PROCESS_SHARED);

	umem->frames      = bufs;
	umem->frames_size = mr.len;
	umem->headroom = mr.headroom;
	umem->sfd = -1;

	/* prepare for fq */
	umem->fq.ring.cached_cons = fq_num;

	for (i = 0; i < umem->fq.ring.size; ++i)
	{
		d.addr = i * size;
		ret = fq_enq_nolock(&umem->fq, &d, 1, 0);
		if (ret) {
			logerr(x->log, "umem configure fq_enq_nolock\n");
			*err = -XUDP_ERR_UMEM_INIT_ENQ;
			goto err;
		}
	}

	u_smp_wmb();
	*umem->fq.ring.producer = umem->fq.ring.cached_prod;
	*umem->fq.ring.consumer = umem->fq.ring.cached_cons;

	return umem;

err:
	if (umem->fq.ring.map)
		munmap(umem->fq.ring.map, umem->fq.ring.map_size);

	if (umem->cq.ring.map)
		munmap(umem->cq.ring.map, umem->cq.ring.map_size);

	munmap(bufs, bufsize);
	munmap(umem, sizeof(*umem));
	return NULL;
}

static struct xdp_umem *umem_configure(xudp *x, int sfd, struct xudp_nic *nic,
				       int queue_id, int *err)
{
	u32 rn, sn, group_num, rcvnum, sndnum;
	struct xdp_umem *umem;

	group_num = x->conf.group_num;
	rcvnum = x->conf.rcvnum;
	sndnum = x->conf.sndnum;

	sn = umem_calc_for_cq(x, nic, sndnum, queue_id);

	rn = rcvnum * group_num;
	rn = get_power_of_2(rn);

	*err = 0;

	umem = __umem_configure(x, sfd, x->conf.frame_size, rn, sn, err);
	if (!umem) {
		logerr(x->log, "umem configure err\n");
		return NULL;
	}

	umem->cq_cache_max = xsk_cq_cache_max(x);
	umem->queue_id = queue_id;
	umem->tx_proc_n = umem_tx_txch_num(nic, queue_id);

	nic->umem[queue_id] = umem;

	return umem;
}

static void umem_free_one(struct xdp_umem *umem)
{
	munmap(umem->fq.ring.map, umem->fq.ring.map_size);
	munmap(umem->cq.ring.map, umem->cq.ring.map_size);

	munmap(umem->frames, umem->frames_size);
	munmap(umem, sizeof(*umem));
}

void umem_free_many(xudp *x)
{
	struct xudp_nic *n;
	struct xdp_umem *umem;
	int i;

	for (n = x->nic; n; n = n->next) {

		for (i = 0; i < n->queue; ++i) {
			umem = n->umem[i];
			if (umem)
				umem_free_one(umem);
			n->umem[i] = NULL;
		}
	}
}

static struct xdp_umem *umem_get(xudp *x, struct txch *txch, int *err)
{
	struct xdp_umem *umem;
	struct xudp_nic *nic;

	nic = txch->nic;

	umem = nic->umem[txch->xsk.queue_id];
	if (umem)
		return umem;

	return umem_configure(x, txch->xsk.sfd, txch->nic,
			      txch->xsk.queue_id, err);
}

static void xudp_xsk_unbind(struct xdpsock *xsk)
{
	if (xsk->ring.ring.map)
		munmap(xsk->ring.ring.map, xsk->ring.ring.map_size);

	if (xsk->sfd > -1)
		close(xsk->sfd);
}

static void xudp_xsk_free(struct xdpsock *xsk)
{
	xudp_xsk_unbind(xsk);
	xsk->ring.ring.map = NULL;
	xsk->sfd = -1;
}

void __xudp_xsk_free(struct xdpsock *xsk)
{
	xudp_xsk_free(xsk);
}

static int xudp_xsk_bind(xudp *x, struct xdp_umem *umem, int sfd,
			 int ifindex, int queueid)
{
	struct sockaddr_xdp sxdp = {};
	int ret, i;
	bool shared;

	sxdp.sxdp_family   = PF_XDP;
	sxdp.sxdp_ifindex  = ifindex;
	sxdp.sxdp_queue_id = queueid;

	if (umem->sfd == -1) {
		shared = false;
		if (x->flags & XDP_ZEROCOPY)
			sxdp.sxdp_flags = XDP_ZEROCOPY;
	} else {
		sxdp.sxdp_flags = XDP_SHARED_UMEM;
		sxdp.sxdp_shared_umem_fd = umem->sfd;
		shared = true;
	}

	for (i = 0; i < 3; ++i)
	{
    		ret = bind(sfd, (struct sockaddr *)&sxdp, sizeof(sxdp));

    		if (!ret) {
			errno = 0; // ret == 0, errno may not 0, why?
			goto success;
		}

		if (errno == EBUSY && (x->flags & XDP_ZEROCOPY)) {
			struct timespec s;

			logwrn(x->log,
			       "xsk bind to dev(%d: %d) ret -EBUSY.\n",
			       ifindex, queueid);

			s.tv_nsec = 1000 * 1000 * 10;
			s.tv_sec = 0;
			nanosleep(&s, NULL);
			continue;
		}

        	logerr(x->log, "xsk bind to dev(%d: %d) fail. %s\n",
		       ifindex, queueid, strerror(errno));
		return -XUDP_ERR_BPF_TX_BIND;
	}

	if (errno == EBUSY && (x->flags & XDP_ZEROCOPY))
		return -XUDP_ERR_BPF_TX_BIND_BUSY;

	return -XUDP_ERR_BPF_TX_BIND;


success:
	if (!shared)
		umem->sfd = sfd;

	return 0;
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

static struct xdp_umem *__umem_get(xudp *x, int ifindex, int queue_id)
{
	struct xudp_nic *n;
	struct xdp_umem *umem;

	n = xudp_get_nic(x, ifindex);
	if (!n)
		return NULL;

	umem = n->umem[queue_id];
	if (umem)
		return umem;
	return NULL;
}

// for group
int __xudp_xsk_bind(xudp *x, int ifindex, int queueid, int sfd)
{
	struct xdp_umem *umem;
	struct xudp_nic *n;
	int err;

	umem = __umem_get(x, ifindex, queueid);
	if (!umem) {
		if (x->conf.isolate_group)
			return -1;

		for (n = x->nic; n; n = n->next) {
			if (n->nic_index == ifindex)
				goto found;
		}

		return -1;

found:
		umem = umem_configure(x, sfd, n, queueid, &err);
		if (!umem)
			return -1;

	}
	return xudp_xsk_bind(x, umem, sfd, ifindex, queueid);
}

static int xsk_bind_tx_dev(xudp *x, struct txch *txch)
{
	int ret;

	ret = xudp_xsk_bind(x, txch->umem, txch->xsk.sfd,
			    txch->nic->nic_index, txch->xsk.queue_id);
	if (ret < 0)
		return ret;

	txch->zc = xsk_is_zc(txch->xsk.sfd, x->log);
	if (x->flags & XDP_ZEROCOPY) {
		if (!txch->zc) {
			logerr(x->log, "tx xsk bind zc fail.\n");
			xudp_xsk_free(&txch->xsk);
			return -XUDP_ERR_BPF_TX_BIND_NOZC;
		}
	}

        logdebug(x->log,
		 "xsk create to dev(%d: %d: %p). tx size: %d "
		 "%s zero copy: %s\n",
	       	 txch->nic->nic_index,
		 txch->xsk.queue_id,
		 &txch->xsk,
		 txch->xsk.ring.ring.size,
	       	 strerror(errno),
		 txch->zc? "true": "false");

	return 0;
}

static int xsk_tx_init(xudp *x, struct txch *txch)
{
	int sfd, ret, sndnum, v, err;

	ret = -1;
	txch->xsk.sfd = -1;

	sfd = socket(PF_XDP, SOCK_RAW, 0);
	if (sfd < 0)
		return -errno;

	txch->xsk.sfd = sfd;
	txch->xsk.x   = x;

	sndnum = x->conf.sndnum;

	v = sndnum * x->conf.frame_size;
	ret = setsockopt(sfd, SOL_SOCKET, SO_SNDBUF, &v, sizeof(int));
	if (ret < 0)
		goto err;

	txch->umem = umem_get(x, txch, &ret);
	if (!txch->umem) {
		goto err;
	}

	if (xsk_cq_cache_init(x, txch, txch->umem)) {
		logerr(x->log, "xsk alloc cq_cached fail\n");
		ret =  -XUDP_ERR_BPF_CQ_CACHE_INIT;
		goto err;
	}

	ret = xsk_set_skopt(sfd, XDP_TX_RING, sndnum);
	if (ret)
		goto err;

	ret = ring_setup(&txch->xsk.ring.ring, sfd, sndnum, XDP_OFFSET_TX, x->log);
	if (ret)
		goto err;

	ret = -XUDP_ERR_BPF_TX_BIND;
	err = xsk_bind_tx_dev(x, txch);
	if (err)
		goto err;

	return 0;
err:
	xudp_xsk_free(&txch->xsk);
	return ret;
}

int xudp_tx_xsk_init(xudp *x)
{
	struct txch *txch, *p;
	struct xudp_nic *n;
	int size, num, i, err;

	/* every group need one tx */
	num = x->conf.group_num;

	size = sizeof(struct txch) * num;
	p = anon_map(size);
	x->tx_xsk = p;

	while (true) {
		for (n = x->nic; n; n = n->next) {
			for (i = 0; i < n->queue; ++i) {
				if (!num)
					goto ok;

				txch = p++;

				txch->nic      = n;

				txch->xsk.istx     = true;
				txch->xsk.queue_id = i;
				txch->xsk.gid      = txch - x->tx_xsk;
				txch->xsk.tx_xsk   = &txch->xsk;
				txch->xsk.sfd      = -1;

				++n->tx_n;

				--num;
			}
		}
	}
ok:

	num = x->conf.group_num;

	for (i = 0; i < num; ++i) {
		txch = x->tx_xsk + i;
		err = xsk_tx_init(x, txch);
		if (err)
			return err;
	}

	return 0;
}

static int xudp_create_dummy_xsk(xudp *x, struct xudp_nic *nic,
				 int queue_id)
{
	struct xdp_umem *umem = NULL;
	int sfd, zc, val = 1;
	struct xdpsock *xsk = NULL;
	int ret;

	sfd = -1;

	xsk = malloc(sizeof(*xsk));
	if (!xsk)
		return -1;

	memset(xsk, 0, sizeof(*xsk));
	xsk->sfd = -1;

	sfd = socket(PF_XDP, SOCK_RAW, 0);
	if (sfd < 0)
		goto err;

	xsk->sfd = sfd;

	umem = umem_configure(x, sfd, nic, queue_id, &ret);
	if (!umem)
		goto err;

	ret = xsk_set_skopt(sfd, XDP_RX_RING, val);
	if (ret)
		goto err;

	ret = ring_setup(&xsk->ring.ring, sfd, val, XDP_OFFSET_RX, x->log);
	if (ret)
		goto err;

	zc = xudp_xsk_bind(x, umem, sfd, nic->nic_index, queue_id);

	if (zc < 0)
		goto err;

	list_insert(&x->dummy_xsk, &xsk->list);

	return 0;

err:
	xudp_xsk_free(xsk);

	if (umem)
		umem_free_one(umem);

	if (xsk)
		free(xsk);

	return -1;
}

/* Make sure that each dev channel has been bound with umem. If channel is
 * without umem, create a rx xdpsock with a size of 1.
 * */
int xudp_umem_check(xudp *x)
{
	struct xdp_umem *umem;
	struct xudp_nic *n;
	int i;

	for (n = x->nic; n; n = n->next) {
		for (i = 0; i < n->queue; ++i) {
			umem = n->umem[i];
			if (umem)
				goto found;

			if (xudp_create_dummy_xsk(x, n, i))
				return -1;
found:
			continue;
		}
	}

	return 0;

}

void xudp_tx_xsk_free(xudp *x)
{
	struct txch *txch;
	int i;

	if (!x->tx_xsk)
		return;

	for (i = 0; i < x->conf.group_num; ++i) {
		txch = x->tx_xsk + i;
		xudp_xsk_unbind(&txch->xsk);
	}

	munmap(x->tx_xsk, sizeof(struct txch) * x->conf.group_num);
}

int xudp_group_create_all(xudp *x)
{
	struct xudp_group *g;
	int i;

	x->groups = malloc(sizeof(g) * x->conf.group_num);

	for (i = 0; i < x->conf.group_num; ++i) {
		g = xudp_group_new(x, i);

		if (!g) {
			logerr(x->log, "xudp create group fail. gid: %d\n", i);
			free(x->groups);
			x->groups = NULL;
			return -1;
		}


		x->groups[i] = g;
	}

	return 0;
}

