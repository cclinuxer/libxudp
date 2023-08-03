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

#ifndef  __DUMP_H__
#define __DUMP_H__

#include <sys/shm.h>
#include <linux/types.h>
#include <common.h>

#define XUDP_SHM_OFFSET 64
#define XUDP_SHM_MAGIC "libxudp-shm-magic"

typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;
typedef __u8 u8;

enum {
	XUDP_DUMP_NOACTIVE,
	XUDP_DUMP_ACTIVE,
};

struct dump {
	u64 active;
	u64 shmid;
	u64 prepare;
};

struct dump_ring {
	pthread_spinlock_t lock;
	u64 size;
	u64 shmid;

	u64 prod;
	u64 cons;

	u64 drop;

	char pkt[];
};

struct dump_header {
	int len;
	u32 tv_sec;
	u32 tv_usec;
};

#endif


