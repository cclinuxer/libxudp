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

#ifndef  __LIB_H__
#define __LIB_H__
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <signal.h>
#include <locale.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <pthread.h>

#include "xudp.h"

struct ch {
	struct th *th;
	int fd;
	xudp_channel *ch;
	xudp_msghdr  *msghdr;
	struct libconf *libconf;
};

struct libconf {
	xudp_conf conf;
	int cluster_id;
	xudp *x;
	int fork;
	int fork_loop;
	int group;
	int exit_directly;
	int nobody;
	int nowait;
	int dict_key_offset;

	void (*handler)(struct ch *ch);
	void (*handler_msg)(struct ch *ch, xudp_msg *m);
	void (*def_handler_msg)(struct ch *ch, xudp_msg *m);
};

struct th {
	struct th *next;
	pthread_t     thread;
	pid_t          pid;
	xudp         *x;
	xudp_channel *ch;
	int           id;
	struct th    *default_thch;
	int cluster_id;
	bool ready;
};

#define FORK_STATUS_EXIT 100
#define FORK_STATUS_AGAIN 101



int process(void);
int mkkey(struct th *th);
int stdinit(struct libconf *libconf);
void stdwait();
int stdmain(struct libconf *libconf);
#endif


