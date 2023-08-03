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

#include <string.h>

#include "packet.h"
#include "checksum.h"

#define IP_XUDP_TTL 64
#define IP_DF 0x4000
#define IP_VIT ((4 << 12) | (5 << 8) | (0 & 0xff))

#define CSUM_MANGLED_0 ((u16)0xffff)

typedef unsigned char u8;

//#ifdef __x86_64__
//static inline void *__movsb(void *d, const void *s, size_t n)
//{
//  	asm volatile ("rep movsb"
//                      : "=D" (d),
//                      "=S" (s),
//                      "=c" (n)
//                      : "0" (d),
//                      "1" (s),
//                      "2" (n)
//                      : "memory");
//  	return d;
//}
//#define memcpy __movsb
//#endif

static void xudp_checksum_half(struct iphdr *iph)
{
#define IP_HALF_SUM (ntohs(IP_VIT) +                           \
		     ntohs((IP_XUDP_TTL << 8) + IPPROTO_UDP) + \
		     ntohs(IP_DF));
	u32 sum;
	u16 *p;

	sum = IP_HALF_SUM;

	sum += iph->tot_len;

	p = (u16 *)&iph->saddr;

	sum += *p++;
	sum += *p++;
	sum += *p++;
	sum += *p;

	sum = (sum & 0xFFFF) + (sum >> 16);
	sum += sum >> 16;

	iph->check = (u16)~sum;
}

static void iph_build(struct iphdr *iph, u32 size,
		      struct sockaddr_in *src, struct sockaddr_in *dst)
{
	/* ip */
	// version, ihl, tos
	*((__be16 *)iph) = htons(IP_VIT);

	iph->tot_len  = htons(sizeof(*iph) + size);
	iph->id       = 0;
	iph->frag_off = htons(IP_DF);
	iph->ttl      = IP_XUDP_TTL;
	iph->protocol = IPPROTO_UDP;
	iph->saddr    = src->sin_addr.s_addr;
	iph->daddr    = dst->sin_addr.s_addr;

	xudp_checksum_half(iph);
}

static inline void ip6_flow_hdr(struct ipv6hdr *hdr, unsigned int tclass,
				__be32 flowlabel)
{
	*(__be32 *)hdr = htonl(0x60000000 | (tclass << 20) | flowlabel);
}

static void iph_build6(struct ipv6hdr *iph6, u32 size,
		       struct sockaddr_in6 *src,
		       struct sockaddr_in6 *dst)
{
	ip6_flow_hdr(iph6, 0, (0x3 << 16) + src->sin6_port);

	iph6->payload_len = htons(size);
	iph6->nexthdr     = IPPROTO_UDP;
	iph6->hop_limit   = IP_XUDP_TTL;
	iph6->saddr       = src->sin6_addr;
	iph6->daddr       = dst->sin6_addr;
}

static void udp_csum6(struct udphdr *udp, u32 size,
		      struct in6_addr *saddr, struct in6_addr *daddr)
{
	u32 sum;

	sum = do_csum((unsigned char *)udp, size);
	sum = udp6_hdr_csum(sum, saddr, daddr, size);

	udp->check = csum_fold(sum);

	if (udp->check == 0)
		udp->check = CSUM_MANGLED_0;
}

static void udp_build(struct udphdr *udp, u32 size, __be16 sport, __be16 dport)
{
	udp->source = sport;
	udp->dest = dport;
	udp->len = htons(size);

	udp->check = 0; // must
}

static void copy_eth(unsigned char *dst, unsigned char *src)
{
	u32 *d1 = (u32 *)dst;
	u32 *s1 = (u32 *)src;
	u16 *d2 = (uint16_t *)(dst + sizeof(u32));
	u16 *s2 = (uint16_t *)(src + sizeof(u32));

	*d1 = *s1;
	*d2 = *s2;
}

static void eth_build(struct ethhdr *eth,
		      unsigned char *smac, unsigned char *dmac,
		      u16 prot)
{
	/* eth */
	copy_eth(eth->h_source, smac);
	copy_eth(eth->h_dest, dmac);

	eth->h_proto = htons(prot);
}

#define IPV4_HEADROOM \
	(sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr))

#define IPV6_HEADROOM \
	(sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct udphdr))

void xudp_packet_udp(struct packet_info *info)
{
	struct ethhdr  *eth;
	struct iphdr   *iph;
	struct ipv6hdr *iph6;
	struct udphdr  *udp;
	u32 size;

	size = sizeof(*udp) + info->payload_size;

	if (info->family == AF_INET) {
		eth = (void *)(info->data - IPV4_HEADROOM);
		iph = (void *)(eth + 1);
		udp = (void *)(iph + 1);

		eth_build(eth, info->smac, info->dmac, ETH_P_IP);
		iph_build(iph, size, info->from, info->to);
		udp_build(udp, size, info->from->sin_port, info->to->sin_port);

		info->len = info->payload_size + IPV4_HEADROOM;
	} else {
		eth = (void *)(info->data - IPV6_HEADROOM);
		iph6 = (void *)(eth + 1);
		udp = (void *)(iph6 + 1);

		eth_build(eth, info->smac, info->dmac, ETH_P_IPV6);
		iph_build6(iph6, size, info->from6, info->to6);
		udp_build(udp, size, info->from6->sin6_port, info->to6->sin6_port);
		/* udp over ipv6, checksum is must.
		 *
		 * https://datatracker.ietf.org/doc/html/rfc2460#section-8.1
		 */
		udp_csum6(udp, size, &info->from6->sin6_addr, &info->to6->sin6_addr);

		info->len = info->payload_size + IPV6_HEADROOM;
	}

	info->packet = (void *)eth;
}

void xudp_packet_udp_payload(struct packet_info *info)
{
	info->data = info->head + XUDP_TX_HEADROOM;

	memcpy(info->data, info->payload, info->payload_size);

	xudp_packet_udp(info);
}
