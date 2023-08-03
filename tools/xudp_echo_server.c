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

#include "xudp.h"
#include <sys/epoll.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

struct connect{
	xudp *x;
	xudp_channel *ch;
	void (*handler)(struct connect *);
};

static bool gloop = true;

void handler(struct connect *c)
{
	xudp_msg *m;
	xudp_channel *ch = c->ch;
	int n, i, ret;

    	xudp_def_msg(hdr, 100);

	while (true) {
        	hdr->used = 0;

		n = xudp_recv_channel(ch, hdr, 0);
		if (n < 0)
			break;

		for (i = 0; i < hdr->used; ++i) {
            		m = hdr->msg + i;

			printf("recv msg: %.*s", m->size, m->p);

			ret = xudp_send_channel(ch, m->p, m->size, (struct sockaddr *)&m->peer_addr, 0);

			if (ret < 0) {
				printf("xudp_send_one fail. %d\n", ret);
			}
		}


		xudp_recycle(hdr);

		xudp_commit_channel(ch);
	}
}

static int epoll_add(xudp *x, int efd)
{
	struct epoll_event e;
	struct connect *c;
	xudp_channel *ch;
	xudp_group *g;
	int fd;

	e.events = EPOLLIN;

	g = xudp_group_get(x, 0);

	xudp_group_channel_foreach(ch, g) {

		fd = xudp_channel_get_fd(ch);

		c = malloc(sizeof(*c));
		c->ch = ch;
		c->x = x;
		c->handler = handler;

		e.data.ptr = c;

		epoll_ctl(efd, EPOLL_CTL_ADD, fd, &e);
	}

	return 0;
}

static int loop(int efd)
{
	struct connect *c;
	struct epoll_event e[1024];
	int n, i;

	while (gloop) {
		n = epoll_wait(efd, e, sizeof(e)/sizeof(e[0]), -1);

		if (n == 0)
			continue;

		if (n < 0) {
			//printf("epoll wait error: %s\n", strerror(errno));
			continue;
		}

		for (i = 0; i < n; ++i) {
			c = e[i].data.ptr;
			c->handler(c);
		}
	}
	return 0;
}

static void int_exit(int sig)
{
	(void)sig;
	gloop = 0;
}

int main(int argc, char *argv[])
{
	xudp *x;
	int efd, ret;
	char *addr, *port;
	int size;
	struct addrinfo *info;

	xudp_conf conf = {};

	if (argc != 3) {
		addr = "0.0.0.0";
		port = "8080";
	} else {
		addr = argv[1];
		port = argv[2];
	}

	ret = getaddrinfo(addr, port, NULL, &info);
	if (ret) {
		printf("addr format err\n");
		return -1;
	}

	conf.group_num     = 1;
	conf.log_with_time = true;
	conf.log_level = XUDP_LOG_WARN;

	x = xudp_init(&conf, sizeof(conf));
	if (!x) {
		printf("xudp init fail\n");
		return -1;
	}

	if (info->ai_family == AF_INET) {
		printf("AF_INET addr.\n");
		size = sizeof(struct sockaddr_in);
	} else {
		printf("AF_INET6 addr.\n");
		size = sizeof(struct sockaddr_in6);
	}

	ret = xudp_bind(x, (struct sockaddr *)info->ai_addr, size, 1);
	if (ret) {
		xudp_free(x);
		printf("xudp bind fail %d\n", ret);
		return -1;
	}

	efd = epoll_create(1024);

	epoll_add(x, efd);

	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);
	signal(SIGABRT, int_exit);

	loop(efd);
	xudp_free(x);
}
