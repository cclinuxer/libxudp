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

#ifndef  __COMMON_H__
#define __COMMON_H__

#include <stdbool.h>
#include <linux/types.h>

#define barrier() __asm__ __volatile__("": : :"memory")
#ifdef __aarch64__
#define u_smp_rmb() __asm__ __volatile__("dmb ishld": : :"memory")
#define u_smp_wmb() __asm__ __volatile__("dmb ishst": : :"memory")
#else
#define u_smp_rmb() barrier()
#define u_smp_wmb() barrier()
#endif

#define WRITE_ONCE(x, val) (*((volatile typeof(x) *)(&(x))) = (val));

#define zobj(x) {\
	x = malloc(sizeof(*x)); \
	if (x) \
		memset(x, 0, sizeof(*x)); \
}

#define anon_map(size) mmap(NULL, size,           \
                	    PROT_READ|PROT_WRITE,                      \
		            MAP_SHARED | MAP_ANONYMOUS | \
			    MAP_POPULATE | MAP_LOCKED , \
                	    0, 0);

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define MIN(a, b) (a > b ? b: a)

#define MTU 1500
#define PAGE_SIZE (4 * 1024)

#define atomic_inc(v) __sync_add_and_fetch(v, 1)
#define atomic_dec(v) __sync_sub_and_fetch(v, 1)
#define xchg(p, o, n) __sync_bool_compare_and_swap(p, o, n)

#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))

static inline __attribute__((const)) bool is_power_of_2(unsigned long n)
{
	return (n != 0 && ((n & (n - 1)) == 0));
}

static inline unsigned int get_power_of_2(unsigned int n)
{
	unsigned int i, t;
	if (!is_power_of_2(n)) {
		for (i = 1; i < 31; ++i) {
			t = ~((1 << i) - 1);
			if ((t & n) == 0) {
				return 1 << i;
			}
		}
	}
	return n;
}

static inline int align(int value, int ag)
{
	if (value % ag)
		return (value / ag + 1) * ag;

	return value;
}

#endif


