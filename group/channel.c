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
#include "group.h"
#include "ip6.h"
#include "kern.h"
#include "bpf.h"
#include "packet_parse.h"

static inline void *xq_get_data(struct xdpsock *xsk, u64 addr)
{
#if XDP_UMEM_UNALIGNED_CHUNK_FLAG
	struct rxch *rxch;
	int offset;

	rxch = container_of(xsk, struct rxch, xsk);

	if (!rxch->unaligned)
		return &xsk->frames[addr];

	offset = addr >> XSK_UNALIGNED_BUF_OFFSET_SHIFT;
	addr = addr & XSK_UNALIGNED_BUF_ADDR_MASK;

	addr = addr + offset;

	return &xsk->frames[addr];
#else
	return &xsk->frames[addr];
#endif
}

static inline void umem_fq_put(struct xdpsock *xsk,
			       struct xdp_desc *d,
			       size_t nb)
{
	fq_enq(xsk->fq, d, nb, xsk->headroom);
}

int xudp_channel_get_fd(xudp_channel *ch)
{
	if (ch->istx)
		ch = ch->tx_xsk;
	return ch->sfd;
}

int xudp_channel_get_groupid(xudp_channel *ch)
{
	if (ch->istx)
		ch = ch->tx_xsk;
	return ch->gid;
}

int xudp_channel_is_tx(xudp_channel *ch)
{
	return ch->istx;
}

static int xudp_fill_msg(struct xdpsock *xsk, char *pkt,
			 struct xdp_desc *desc, struct pkthdrs *hdrs,
			 xudp_msg *m, int flags)
{
	struct sockaddr_in6 *in6;
	struct sockaddr_in *in;
	struct iphdr *iph;
	struct ipv6hdr *iph6;
	struct udphdr *udp;
	char *body;
	int len;

	iph = hdrs->iph;
	iph6 = hdrs->iph6;
	udp = hdrs->udp;

	body = (void *)(udp + 1);
	len = htons(udp->len) - sizeof(*udp);

	memset(&m->peer_addr, 0, sizeof(m->peer_addr));
	memset(&m->local_addr, 0, sizeof(m->local_addr));

	if (hdrs->family == AF_INET) {
		in = (struct sockaddr_in *)&m->peer_addr;
		in->sin_family      = AF_INET;
		in->sin_port        = udp->source;
		in->sin_addr.s_addr = iph->saddr;

		in = (struct sockaddr_in *)&m->local_addr;
		in->sin_family      = AF_INET;
		in->sin_port        = udp->dest;
		in->sin_addr.s_addr = iph->daddr;
	} else {
		in6 = (struct sockaddr_in6 *)&m->peer_addr;
		in6->sin6_family = AF_INET6;
		in6->sin6_port  = udp->source;
		in6->sin6_addr  = iph6->saddr;

		in6 = (struct sockaddr_in6 *)&m->local_addr;
		in6->sin6_family = AF_INET6;
		in6->sin6_port   = udp->dest;
		in6->sin6_addr   = iph6->daddr;
	}

	m->frame = pkt;
	m->headroom = xsk->headroom;

	if (flags & XUDP_FLAG_COPY) {
		if (len < m->size)
			m->size = len;

		memcpy(m->p, body, m->size);
	} else {
		m->recycle1 = desc->addr;
		m->recycle2 = (u64)xsk;
		m->p        = body;
		m->size     = len;
	}

	return 0;
}

static int xudp_group_stats(struct xdpsock *tx_xsk,
			    struct xudp_group *g, int fd)
{
	struct xsk_stats_output stats, *s;
	struct xdp_statistics xdp_stats;
	struct xdpsock *xsk;
	socklen_t len;
	int ret;

	s = &stats;

	s->g_id = g->gid;
	s->ch_id = 0;
	s->group_num = __xudp_group_num(tx_xsk->x);

	xudp_group_channel_foreach(xsk, g)
	{
		s->is_tx = false;

		if (xudp_channel_is_tx(xsk)) {
			xsk = xsk->tx_xsk;
			s->is_tx = true;
		}

		memcpy(&s->stats, &xsk->stats, sizeof(xsk->stats));
		memset(&xdp_stats, 0, sizeof(xdp_stats));

		len = sizeof(xdp_stats);
		getsockopt(xsk->sfd, SOL_XDP, XDP_STATISTICS, &xdp_stats, &len);

		s->xsk_rx_dropped       = xdp_stats.rx_dropped;
		s->xsk_rx_invalid_descs = xdp_stats.rx_invalid_descs;
		s->xsk_tx_invalid_descs = xdp_stats.tx_invalid_descs;

		s->kern_tx_num = 0;
		if (s->is_tx) {
			s->kern_tx_num = *xsk->ring.ring.producer - *xsk->ring.ring.consumer;
		}

		ret = send(fd, (void *)s, sizeof(*s), 0);
		if (ret < 0) {
			logerr(tx_xsk->x, "stats send. %s\n", strerror(errno));
			break;
		}

		++s->ch_id;
	}

	return 0;
}

static int xudp_stats_req_check(struct xdpsock *xsk,
				struct iphdr *iph,
				struct udphdr *udp)
{
	struct sockaddr_in addr;
	int fd, err;

	if (iph->saddr != iph->daddr)
		return 0;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return 1;

	addr.sin_family      = AF_INET;
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	addr.sin_port        = udp->source;

	err = connect(fd, (struct sockaddr *)&addr, (socklen_t)sizeof(addr));
	if (err) {
		close(fd);
		return 1;
	}

	xudp_group_stats(xsk, xsk->group, fd);
	close(fd);
	return 1;
}

static int xudp_nic_recv_channel(struct xdpsock *xsk, xudp_msghdr *hdr,
				 int flags)
{
	struct xdp_desc descs[BATCH_SIZE];
	unsigned int rcvd, i, bytes;
	struct pkthdrs hdrs = {};
	int num, ret;
	xudp_msg *m;
	char *pkt;

	bytes = 0;

	num = MIN(sizeof(descs)/sizeof(descs[0]), hdr->total - hdr->used);

	rcvd = xq_deq(&xsk->ring, descs, num);
	if (!rcvd) {
        	errno = EAGAIN;
		return -1;
    	}

	for (i = 0; i < rcvd; i++) {
		if (i + 1 < rcvd) {
			pkt = xq_get_data(xsk, descs[i + 1].addr);
			__builtin_prefetch(pkt, 0, 3);
		}

		pkt = xq_get_data(xsk, descs[i].addr);

		ret = packet_parse(&hdrs, pkt, pkt + descs[i].len);

		if (ret < 0 || xudp_stats_req_check(xsk, hdrs.iph, hdrs.udp)) {
			if (!(flags & XUDP_FLAG_COPY))
				umem_fq_put(xsk, &descs[i], 1);

			continue;
		}

		m = hdr->msg + hdr->used++;

		xudp_fill_msg(xsk, pkt, &descs[i], &hdrs, m, flags);

		dump_check(xsk->x, xsk->group, pkt, descs[i].len);

		bytes += m->size;
	}

	if (flags & XUDP_FLAG_COPY)
		umem_fq_put(xsk, descs, rcvd);

	xsk->stats.rx_npkts += rcvd;

	logdebug(xsk->x,
		 "recv from %p %d patckets. bytes: %d\n",
		 xsk, rcvd, bytes);

	return bytes;
}

int xudp_recv_channel(xudp_channel *ch, xudp_msghdr *hdr, int flags)
{
	if (ch->istx) {
        	errno = EAGAIN;
		return -1;
	}

	hdr->used = 0;
	return xudp_nic_recv_channel(ch, hdr, flags);
}

int xudp_recycle(xudp_msghdr *hdr)
{
	struct xdpsock *xsk;
	xudp_msg *m;
	int i;
	struct xdp_desc d;

	for (i = 0; i < hdr->used; ++i) {
		m = hdr->msg + i;
		xsk = (void *)m->recycle2;

		d.addr = m->recycle1;
		umem_fq_put(xsk, &d, 1);
	}
	return 0;
}


