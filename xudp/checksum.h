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

#ifndef __CHECKSUM_H_
#define __CHECKSUM_H_

# define likely(x)	__builtin_expect(!!(x), 1)
# define unlikely(x)	__builtin_expect(!!(x), 0)

#define __force
#define X86 1

#ifdef X86
typedef unsigned int u32;


//      │     ip_fast_csum():
//  0.14 │       mov    (%rax),%esi
// 28.82 │       sub    $0x4,%ecx
//       │     ↓ jbe    cb
//  0.01 │       add    0x4(%rax),%esi
//  0.47 │       adc    0x8(%rax),%esi
//  0.60 │       adc    0xc(%rax),%esi
//  0.56 │ b0:   adc    0x10(%rax),%esi
//  0.54 │       lea    0x4(%rax),%rax
//  0.00 │       dec    %ecx
//       │     ↑ jne    b0
//       │       adc    $0x0,%esi
//  0.49 │       mov    %esi,%ecx
//  0.00 │       shr    $0x10,%esi
//  0.58 │       add    %cx,%si
//  0.59 │       adc    $0x0,%esi
//  0.54 │       not    %esi

/**
 * ip_fast_csum - Compute the IPv4 header checksum efficiently.
 * iph: ipv4 header
 * ihl: length of header / 4
 */
static inline __sum16 ip_fast_csum(const void *iph, unsigned int ihl)
{
	unsigned int sum;

	asm(	"  movl (%1), %0\n"
		"  subl $4, %2\n"
		"  jbe 2f\n"
		"  addl 4(%1), %0\n"
		"  adcl 8(%1), %0\n"
		"  adcl 12(%1), %0\n"
		"1: adcl 16(%1), %0\n"
		"  lea 4(%1), %1\n"
		"  decl %2\n"
		"  jne	1b\n"
		"  adcl $0, %0\n"
		"  movl %0, %2\n"
		"  shrl $16, %0\n"
		"  addw %w2, %w0\n"
		"  adcl $0, %0\n"
		"  notl %0\n"
		"2:"
	/* Since the input registers which are loaded with iph and ipl
	   are modified, we must also specify them as outputs, or gcc
	   will assume they contain their original values. */
	: "=r" (sum), "=r" (iph), "=r" (ihl)
	: "1" (iph), "2" (ihl)
	: "memory");
	return (__force __sum16)sum;
}
#endif

typedef unsigned char u8;
typedef unsigned short u16;

static inline u16 checksum(u8 *p, u32 num, u32 sum)
{
    int i;

    if (num % 2 == 1)
    {
    	    --num;
            sum += p[num] << 8;
    }

    for (i = 0; i < num; i += 2)
    {
        sum += p[i] << 8;
        sum += p[i+1];
    }

    u32 l = sum & 0x0000FFFF;
    u32 h = sum >> 16;
    u16 checksum = l + h;

    return ~checksum;
}

static inline u16 udp_checksum(u8 *u, __be32 saddr, __be32 daddr, u16 size)
{
	u32 sum = 0;
	u8 *p;
	__be32 l;

	p = (u8 *)&saddr;

	sum += p[0] << 8;
	sum += p[1];

	sum += p[2] << 8;
	sum += p[3];

	p = (u8 *)&daddr;

	sum += p[0] << 8;
	sum += p[1];

	sum += p[2] << 8;
	sum += p[3];

	sum += IPPROTO_UDP;


	l = htons(size);

	p = (u8 *)&l;

	sum += p[0] << 8;
	sum += p[1];

	return checksum(u, size, sum);
}

#define sum32(sum, val) { \
	int carry; \
	sum += val; \
	carry = sum < val; \
	sum += carry; \
}

static inline u32 udp6_hdr_csum(u32 sum, struct in6_addr *saddr,
				struct in6_addr *daddr, u32 size)
{
	sum32(sum, saddr->s6_addr32[0]);
	sum32(sum, saddr->s6_addr32[1]);
	sum32(sum, saddr->s6_addr32[2]);
	sum32(sum, saddr->s6_addr32[3]);

	sum32(sum, daddr->s6_addr32[0]);
	sum32(sum, daddr->s6_addr32[1]);
	sum32(sum, daddr->s6_addr32[2]);
	sum32(sum, daddr->s6_addr32[3]);

	sum32(sum, htonl(size));
	sum32(sum, htonl(IPPROTO_UDP));

	return sum;
}

static inline u32 do_csum(unsigned char *buf, u32 size)
{
	u32 sum = 0;

	while (size >= 4) {
		sum32(sum, *(u32 *)buf);
		buf += 4;
		size -= 4;
	}

	sum = (sum & 0xffff) + (sum >> 16);

	if (size & 2) {
		sum += *(u16 *)buf;
		buf += 2;
	}

	if (size & 1) {
#ifdef __LITTLE_ENDIAN
		sum += *buf;
#else
		sum += (*buf << 8);
#endif
	}

	return sum;
}

static inline u32 do_csum_v1(char *buf, u32 size)
{
	u32 sum = 0;

	while (size >= 4) {
		sum32(sum, *(u32 *)buf);
		buf += 4;
		size -= 4;
	}

	if (size) {
		char t[4] = {0};

		switch(size) {
		case 3:
			t[2] = *(buf + 2);
		case 2:
			t[1] = *(buf + 1);
		case 1:
			t[0] = *buf;
		}

		sum32(sum, *(u32 *)t);
	}

	return sum;
}

static inline u16 csum_fold(u32 sum)
{
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return (u16)~sum;
}
#endif
