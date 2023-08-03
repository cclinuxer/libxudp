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

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <pwd.h>

#include "lib.h"

static struct libconf *global_libconf;
static struct th *th_head;
static struct th *th_tail;
static bool loop = true;

int mkkey(struct th *th)
{
	int key;

	key = th->id + global_libconf->dict_key_offset;

	return key;
}

static void int_exit(int sig)
{
	printf("recv sig %d. exit\n", sig);
	(void)sig;
	loop = 0;
}

static int epoll_add(xudp *x, int efd, struct th *th)
{
	struct ch *ch;
	xudp_channel *xh;
	xudp_group *g;
	struct epoll_event e;
	int cn, i;

	e.events = EPOLLIN | EPOLLOUT | EPOLLET;

	if (global_libconf->conf.isolate_group)
		g = xudp_group_new(x, th->id);
	else
		g = xudp_group_get(x, th->id);

	if (!g) {
		printf("create group fail\n");
		return -1;
	}

	xudp_group_channel_foreach(xh, g) {

		ch = malloc(sizeof(*ch));

		ch->ch = xh;
		ch->fd = xudp_channel_get_fd(ch->ch);
		ch->th = th;
		ch->msghdr = xudp_alloc_msg(100);
		ch->libconf = global_libconf;

		e.data.ptr = ch;

		/* this just work when flow dispatch == dict */
		xudp_dict_set_group_key(g, mkkey(th));

		epoll_ctl(efd, EPOLL_CTL_ADD, ch->fd, &e);
	}

	return 0;
}

static void handler_msg(struct ch *ch, xudp_msg *m)
{
	int ret, n;
	char buf[100];

	n = snprintf(buf, sizeof(buf), "%d/%d/%d",
		     ch->th->id,
		     ch->libconf->conf.group_num,
		     ch->libconf->conf.group_num);

	ret = xudp_send_channel(ch->ch, buf, n, (struct sockaddr *)&m->peer_addr, 0);

	if (ret < 0) {
		printf("xudp_send_one fail. %d\n", ret);
	}
}

static void handler_recv(struct ch *ch)
{
	int n, i, ret;
	xudp_msg *m;

	xudp_def_msg(hdr, 100);

	while (true) {
		n = xudp_recv_channel(ch->ch, hdr, 0);
		if (n < 0)
			break;

		for (i = 0; i < hdr->used; ++i) {
            		m = hdr->msg + i;
			ch->libconf->handler_msg(ch, m);
		}

		xudp_recycle(hdr);
		xudp_commit_channel(ch->ch);
	}
}

static int epoll_loop(int efd)
{
	struct ch *ch;
	struct epoll_event e[1024];
	int n, i;

	while (loop) {
		n = epoll_wait(efd, e, sizeof(e)/sizeof(e[0]), 100);

		if (n == 0)
			continue;

		if (n < 0) {
			//printf("epoll wait error: %s\n", strerror(errno));
			continue;
		}

		for (i = 0; i < n; ++i) {
			ch = e[i].data.ptr;
			ch->libconf->handler(ch);
		}
	}
}

static void *handler(void *_)
{
	int efd;
	struct th *th = _;
	xudp *x;

	x = th->x;

	efd = epoll_create(1024 * 2);

	epoll_add(x, efd, th);

	th->ready = true;

	epoll_loop(efd);

	return NULL;
}

static int fork_process(struct th *t)
{
	int pid;

	pid = fork();
	if (0 == pid) {
		if (global_libconf->nobody) {
			struct passwd *pw;
			pw = getpwnam("nobody");
			setuid(pw->pw_uid);
		}

		printf("start new process pid: %d gid: %d\n", getpid(), t->id);
		handler(t);
		exit(0);
	} else {
		t->pid = pid;
	}

}

/* start fork process or thread */
int process(void)
{
	struct th *t;
	int thread_n;
	int i;
	bool ready = false;

	xudp *x = global_libconf->x;

	thread_n = global_libconf->conf.group_num;

	for (i = 0; i < thread_n; ++i) {
		t = mmap(NULL, sizeof(*t), \
			 PROT_READ|PROT_WRITE,                      \
			 MAP_ANONYMOUS | MAP_SHARED | MAP_POPULATE,
			 -1, 0);
		t->id         = i;
		t->x          = x;
		t->next       = NULL;
		t->ready      = false;

		if (!th_head)
			th_head  = t;
		else
			th_tail->next = t;

		th_tail = t;

		if (global_libconf->fork) {
			fork_process(t);

		} else {
			pthread_create(&t->thread, 0, handler, t);
		}
	}

	while(!ready) {
		ready = true;

		for (t = th_head; t; t = t->next) {
			if (!t->ready) {
				ready = false;
				break;
			}
		}
	}

	printf("service ok.\n"); // notify pytest case service ok
}

int stdinit(struct libconf *libconf)
{
	int ret = 0, i;
	xudp_conf *conf;
	struct sockaddr_storage addr[2] = {};
	struct sockaddr_in *s4;
	struct sockaddr_in6 *s6;
	xudp *x;

	conf = &libconf->conf;

	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);
	signal(SIGABRT, int_exit);
	signal(SIGKILL, int_exit);

	x = xudp_init(conf, sizeof(*conf));
	if (!x) {
		fprintf(stderr, "xudp_init %d\n", ret);
		exit(-1);
	}

	libconf->x = x;
	global_libconf = libconf;

	s4 = (struct sockaddr_in *)&addr[0];
	s4->sin_family      = AF_INET;
	s4->sin_addr.s_addr = inet_addr("0.0.0.0");
	s4->sin_port        = htons(3486);

	s6 = (struct sockaddr_in6 *)&addr[1];
	s6->sin6_family      = AF_INET6;
	s6->sin6_port        = htons(3487);

	ret = inet_pton(AF_INET6, "::", &s6->sin6_addr);
	if (!ret) {
		fprintf(stderr, "ipv6 addr error %d\n", ret);
		exit(-1);
	}

	ret = xudp_bind(x, (struct sockaddr *)addr, sizeof(addr[0]), 2);
	if (ret) {
		fprintf(stderr, "xudp_bind %d\n", ret);
		exit(-1);
	}
}

static struct th *get_th_by_pid(int pid)
{
	struct th *t;
	for (t = th_head; t; t = t->next) {
		if (t->pid == pid)
			return t;
	}

	return NULL;
}

static void stdwait_fork(struct libconf *libconf)
{
	int pid, status;
	struct th *t;

	while (loop) {

		pid = wait(&status);
		if (pid < 0)
			continue;

		status = WEXITSTATUS(status);
		//if (status == FORK_STATUS_EXIT) {
		//	for (t = th_head; t; t = t->next) {
		//		if (t->pid == pid)
		//			continue;

		//		kill(t->pid, SIGINT);
		//	}
		//	exit(0);
		//}

		if (status == FORK_STATUS_EXIT) {
			printf("fork process exit with FORK_STATUS_EXIT. %d\n", pid);
			//pass
		}

		if (status == FORK_STATUS_AGAIN) {
			printf("fork process exit with FORK_STATUS_AGAIN. %d\n", pid);
			t = get_th_by_pid(pid);
			fork_process(t);
		}
	}
}

void stdwait()
{
	struct libconf *libconf;
	struct th *t;

	libconf = global_libconf;

	if (libconf->exit_directly) {
		xudp_free(libconf->x);
		return;
	}

	if (libconf->fork) {
		stdwait_fork(libconf);
	} else {
		for (t = th_head; t; t = t->next)
			pthread_join(t->thread, NULL);
	}

	xudp_free(libconf->x);
}

int stdmain(struct libconf *libconf)
{
	int err;

	// close libc printf buf
	setbuf(stdout,	NULL);

	err = stdinit(libconf);
	if (err)
		return err;

	if (!libconf->handler)
		libconf->handler = handler_recv;

	if (!libconf->handler_msg)
		libconf->handler_msg = handler_msg;

	libconf->def_handler_msg = handler_msg;

	process();

	if (!libconf->nowait)
		stdwait();

	return 0;
}
