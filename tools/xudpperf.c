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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <signal.h>
#include <locale.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <pthread.h>
#include <syscall.h>
#include <sys/time.h>
#include <unistd.h>

#include "xudp.h"

static int64_t recv_n;
static int64_t sent_n;
static int64_t g_latency;
static int64_t g_on_line;

static int64_t cpu_foo;
static int64_t g_err_cq;
static int64_t g_err_tx;
static int64_t g_err_inval;
static int64_t g_err_send;
static int64_t g_err_nosend;
static int64_t g_ev_in;
static int64_t g_ev_out;
static int64_t g_err_commit;
static int64_t g_err_dev_busy;


#define WORK_MODE_ECHO 1
#define WORK_MODE_RECV 2
#define WORK_MODE_SEND 3
#define WORK_MODE_PP 4
#define WORK_MODE_PP_FLOOD 5


struct th{
	pthread_t     thread;
	xudp         *x;
	xudp_channel *ch;
	int           id;
	xudp_msghdr  *msghdr;
	struct th    *default_thch;
	xudp_group *group;
};

static struct {
	int work_mode;
	bool stats;
	int sport;
	char *dev;

	char               smac[6];
	struct sockaddr_in addr[10];
	struct sockaddr_in dst;
	struct sockaddr_in bind; // this for rand src port
	int                addr_n;
	int log_level;
	int msglen;
	int tx_batch_num;
	bool force_copy;
	int npkt;
	volatile bool loop;
	bool tx_rand_port;
	int flood;
	int noxdp;
	int noarp;
	int headroom;
	int (*send_func)(struct th *th, int *done);
	int frame_size;
	bool poll;
}conf;


static void alarm_handler(int sig)
{
	if (conf.stats) {
		printf("\n");
	}
	if (conf.work_mode == WORK_MODE_PP_FLOOD) {
		if (!recv_n)
			goto end;

		printf("recv num: %ld total latency: %ld on line: %ld latency: %ld\n",
		       recv_n, g_latency, g_on_line, g_latency / recv_n);
		goto end;

	}
	printf("app recv: %ldw(%ld) sent: %ld "
	       "send err: %ld(cq: %ld tx: %ld inval: %ld nosend: %ld commit: %ld dev_busy: %ld) "
	       "ev:(in: %ld out: %ld) foo: %ld\n",
	       recv_n/10000, recv_n,
	       sent_n,
	       g_err_send,
	       g_err_cq,
	       g_err_tx,
	       g_err_inval,
	       g_err_nosend,
	       g_err_commit,
	       g_err_dev_busy,
	       g_ev_in,
	       g_ev_out,
	       cpu_foo
	       );

	g_err_cq     = 0;
	g_err_tx     = 0;
	g_err_inval  = 0;
	recv_n       = 0;
	sent_n       = 0;
	cpu_foo      = 0;
	g_err_send   = 0;
	g_err_nosend = 0;
	g_err_commit = 0;
	g_ev_in = 0;
	g_ev_out = 0;
	g_err_dev_busy = 0;

end:
	alarm(1);
}

static void int_exit(int sig)
{
	(void)sig;
	printf("recv sig: %d. set loop = 0\n", sig);
	conf.loop = 0;
}

static int echo_epoll_wait(xudp *x, int efd, void (handle)(struct th *))
{
	struct epoll_event e[1024];
	int n, i;

	while (conf.loop) {
		n = epoll_wait(efd, e, sizeof(e)/sizeof(e[0]), 1000);

		if (n == 0)
			continue;

		if (n < 0) {
			//printf("epoll wait error: %s\n", strerror(errno));
			continue;
		}

		for (i = 0; i < n; ++i) {

			if (e[i].events & EPOLLIN)
				g_ev_in += 1;

			if (e[i].events & EPOLLOUT)
				g_ev_out += 1;

			if (e[i].events & (EPOLLOUT | EPOLLIN))
				handle(e[i].data.ptr);
		}

	}
	return 0;
}

static int epoll_add(xudp *x, int efd, struct th *th)
{
	struct epoll_event e;
	xudp_channel *ch;
	xudp_group *g;
	struct th *thch;
	int gid;
	int fd;

	gid = th->id;

	g = xudp_group_get(x, gid);

	e.events = EPOLLIN | EPOLLOUT | EPOLLET;

	xudp_group_channel_foreach(ch, g) {

		fd = xudp_channel_get_fd(ch);

		thch = malloc(sizeof(*thch));
		thch->msghdr = xudp_alloc_msg(100);

		e.data.ptr = thch;
		thch->ch = ch;
		thch->group = g;

		th->default_thch = thch;

		epoll_ctl(efd, EPOLL_CTL_ADD, fd, &e);
	}

	return 0;
}

static void handler_recv(struct th *th)
{
	int n;

	xudp_def_msg(hdr, 100);

	while (true) {
		n = xudp_recv_channel(th->ch, hdr, 0);
		if (n < 0)
			break;

		xudp_recycle(hdr);
		recv_n += hdr->used;
	}
}

static void __handler_send_err(int ret)
{
	g_err_send++;

	if (ret == -XUDP_ERR_CQ_NOSPACE)
		g_err_cq++;

	if (ret == -XUDP_ERR_TX_NOSPACE)
		g_err_tx++;

	if (ret == -XUDP_ERR_PACKET_TOO_BIG)
		g_err_inval++;

	if (ret == -XUDP_ERR_COMMIT_AGAIN)
	{
		g_err_commit += 1;
		sent_n += 1;
	}
}

static void __handler_echo(xudp_channel *ch)
{
	int n = 1, i, ret, send = 0, err_cq = 0, err_tx = 0, err_inval = 0;
	xudp_msg *m;

	xudp_def_msg(hdr, 100);

	while (n) {
		n = xudp_recv_channel(ch, hdr, 0);
		if (n < 0) {
			if (conf.poll)
				continue;
			break;
		}

		recv_n += hdr->used;

		for (i = 0; i < hdr->used; ++i) {
			m = hdr->msg + i;
			ret = xudp_send_channel(ch, m->p, m->size,
						(struct sockaddr *)&m->peer_addr, 0);
			if (ret < 0) {
				if (ret == -2003)
					++err_cq;
				if (ret == -2005)
					++err_tx;
				if (ret == -1)
					++err_inval;
				break;
			}
			++send;
		}

		xudp_recycle(hdr);

		if (hdr->used)
			xudp_commit_channel(ch);
	}
	sent_n += send;
	g_err_cq += err_cq;
	g_err_tx += err_tx;
	g_err_inval += err_inval;

}

static void handler_echo(struct th *th)
{
	xudp_channel *ch;


	ch = th->ch;

	__handler_echo(ch);
}


static int send_one_by_one(struct th *th)
{
	int ret = 0;
	char buf[1500];
	xudp_channel *ch;

	ch = th->ch;


	while (conf.npkt--)
	{
		ret = xudp_send_channel(ch, buf, conf.msglen, (struct sockaddr *)&conf.dst, 0);
		if (ret < 0)
		{
			__handler_send_err(ret);
		}
		sent_n += 1;
		xudp_commit_channel(ch);
		sleep(1);
	}
	return ret;

}

static int ch_send(xudp_channel *ch)
{
	char buf[1500];
	int ret;
	int flag = 0;
	struct xudp_addr addr;
	struct sockaddr *a = (struct sockaddr *)&conf.dst;

	if (conf.tx_rand_port) {
		++conf.bind.sin_port;
		if (conf.bind.sin_port > 50000)
			conf.bind.sin_port = 8080;

		flag = flag | XUDP_FLAG_SRC_PORT;

		struct sockaddr_in *in;

		memcpy(&addr.to, &conf.dst, sizeof(conf.dst));
		in = (struct sockaddr_in *)&addr.from;
		in->sin_port = htons(conf.bind.sin_port);
		a = (struct sockaddr *)&addr;
	}

	ret = xudp_send_channel(ch, buf, conf.msglen, a, flag);

	return ret;
}

static int ch_send_frame(struct th *th, int *done)
{
	int n, m, i;
	xudp_def_msg(hdr, 100);

	n = xudp_frame_alloc(th->group, hdr, 0);
	if (n < 0)
		return hdr->err;

	for (i = 0; i < n; ++i) {
		hdr->msg[i].size = conf.msglen;
	}

	hdr->total = n;

	m = xudp_frame_send(th->group, hdr, (struct sockaddr *)&conf.dst, 0);

	xudp_frame_free(th->group, hdr);

	*done = m;

	return hdr->err;
}

static int __ch_send_ch(xudp_channel *ch, int *done)
{
	char buf[1500];
	int ret;
	int flag = 0;
	struct xudp_addr addr;
	struct sockaddr *a = (struct sockaddr *)&conf.dst;

	if (conf.tx_rand_port) {
		++conf.bind.sin_port;
		if (conf.bind.sin_port > 50000)
			conf.bind.sin_port = 8080;

		flag = flag | XUDP_FLAG_SRC_PORT;

		struct sockaddr_in *in;

		memcpy(&addr.to, &conf.dst, sizeof(conf.dst));
		in = (struct sockaddr_in *)&addr.from;
		in->sin_port = htons(conf.bind.sin_port);
		a = (struct sockaddr *)&addr;
	}

	ret = xudp_send_channel(ch, buf, conf.msglen, a, flag);
	if (ret > 0) {
		*done = 1;
		return 0;
	}

	return ret;

}

static int ch_send_th(struct th *th, int *done)
{
	return __ch_send_ch(th->ch, done);
}

static int __flood_ch_send(xudp_channel *ch)
{
	int ret;
	int sent = 0;

	while (conf.loop) {
		ret = ch_send(ch);
		if (ret < 0)
			break;


		++sent;
		if (sent > 10000) {
			__sync_fetch_and_add(&sent_n, sent);
			sent = 0;
		}

	}
	if (sent) {
		__sync_fetch_and_add(&sent_n, sent);
	} else
		cpu_foo += 1;
	return 0;
}

static void *flood_thread(void *_)
{
	struct th *th = _;
	xudp_group *g;
	xudp_channel *ch;


	g = xudp_group_get(th->x, th->id);

	xudp_group_channel_foreach(ch, g) {
		break;
	};

	while (conf.loop)
		__flood_ch_send(ch);

	return NULL;
}

static int flood_send(xudp *x)
{
	struct th *th;

	int i;

	for (i = 0; i < conf.flood; i++) {
		th = malloc(sizeof(*th));
		th->id = i;
		th->x = x;
		pthread_create(&th->thread, 0, flood_thread, (void*)th);
	}

	while (conf.loop)
		sleep(100);

	return 0;
}

static int ___handler_pp_flood(xudp_channel *ch)
{
	struct timeval *tp, now;
	int64_t latency;
	xudp_msg *m;
	int i, ret, n, sent;

	xudp_def_msg(hdr, 100);

	while (true) {
		sent = 0;
		gettimeofday(&now, NULL);
		while (g_on_line < conf.npkt) {

			ret = xudp_send_channel(ch, (char *)&now, sizeof(now), (struct sockaddr *)&conf.dst, 1);

			if (ret < 0) {
				__handler_send_err(ret);
				break;
			}
			sent = 1;
			g_on_line += 1;
		}

		if (sent)
			xudp_commit_channel(ch);

		while (true) {
			n = xudp_recv_channel(ch, hdr, 0);
			if (n < 0)
				break;

			gettimeofday(&now, NULL);
			for (i = 0; i < hdr->used; ++i) {

				m = hdr->msg + i;
				tp = (struct timeval *)m->p;
				latency = (now.tv_sec - tp->tv_sec) * 1000 * 1000  + now.tv_usec - tp->tv_usec;

				g_latency += latency;
				++recv_n;
				g_on_line -= 1;
			}

			xudp_recycle(hdr);
		}
	}

	return 0;
}

static int __handler_pp_flood(xudp_channel *ch)
{
	___handler_pp_flood(ch);

	return 0;
}


static int __handler_pp(xudp_channel *ch)
{
	int done, n, ret;
	int64_t num = 0, usec;
	struct timeval start, now;

	xudp_def_msg(hdr, 100);

	gettimeofday(&start, NULL);

	while (num < conf.npkt) {
		ret = __ch_send_ch(ch, &done);
		if (ret) {
			printf("send fail.");
			return -1;
		}

		xudp_commit_channel(ch);

		sent_n += 1;


		while (true) {
			n = xudp_recv_channel(ch, hdr, 0);
			if (n < 0)
				continue;

			xudp_recycle(hdr);
			break;
		}
		recv_n += 1;
		++num;
	}

	gettimeofday(&now, NULL);

	usec = (now.tv_sec - start.tv_sec) * 1000 * 1000;
	usec += now.tv_usec - start.tv_usec;

	if (num != 0){
		printf("pp avg usec: %ld\n", usec / num);
	}else {
		printf("pp avg usec: 0\n");
	}
	return 0;
}

static int __handler_send(struct th *th)
{
	int ret;
	int send = 0;
	int done = 0;
	xudp_channel *ch;

	ch = th->ch;

	while (conf.loop) {
		done = 0;
		ret = conf.send_func(th, &done);

		if (done) {
			++send;
			sent_n += done;

		}
		if (ret < 0) {
			__handler_send_err(ret);
			goto end;
		}
	}

	xudp_commit_channel(ch);

	if (!send)
		g_err_nosend += 1;
end:
	return ret;
}

static void handler_send(struct th *th)
{
	if (-1 != conf.npkt) {
		send_one_by_one(th);
		exit(0);
	}
	__handler_send(th);
}


static void *thread_handler(void *_)
{
	int efd;
	struct th *th = _;
	xudp *x;

	x = th->x;

	if (conf.poll) {
		xudp_group *g;
		xudp_channel *ch;

		g = xudp_group_get(x, th->id);

		ch = xudp_group_channel_first(g);

		switch(conf.work_mode) {
		case WORK_MODE_ECHO:
			__handler_echo(ch);
			break;
		case WORK_MODE_PP:
			__handler_pp(ch);
			break;
		case WORK_MODE_PP_FLOOD:
			__handler_pp_flood(ch);
			break;
		}

		return NULL;
	}

	efd = epoll_create(1024 * 2);

	epoll_add(x, efd, th);

	switch(conf.work_mode) {
	case WORK_MODE_ECHO:
		echo_epoll_wait(x, efd, handler_echo);
		break;

	case WORK_MODE_RECV:
		echo_epoll_wait(x, efd, handler_recv);
		break;

	case WORK_MODE_SEND:
		handler_send(th->default_thch);
		echo_epoll_wait(x, efd, handler_send);
		break;
	}
	return NULL;

}

static void copy_addr(char *addr, struct sockaddr_in *in)
{
	char *p;
	int port = 8080;
	char buf[16] = {0};


	p = strstr(addr, ":");
	if (p) {
		port = atoi(p + 1);
		memcpy(buf, addr, p - addr);
	} else {
		memcpy(buf, addr, strlen(addr));
	}

	in->sin_family = AF_INET;
	in->sin_addr.s_addr = inet_addr(buf);
	in->sin_port = htons(port);
}

static void parse_argv(int argc, char **argv)
{
	int i;
	char *k, *v;

	conf.sport = 8080;
	conf.log_level = XUDP_LOG_WARN;
	conf.msglen = 24;
	conf.npkt = -1;
	conf.loop = true;
	conf.bind.sin_port = 8080;
	conf.send_func = ch_send_th;
	conf.flood = 0;
	conf.headroom = 256;

	for (i = 1; i < argc; ++i) {
		k = argv[i];
		if (k[0] != '-') {
			if (0 == strcmp(k, "echo")) {
				conf.work_mode = WORK_MODE_ECHO;
				continue;
			}
			if (0 == strcmp(k, "recv")) {
				conf.work_mode = WORK_MODE_RECV;
				continue;
			}
			if (0 == strcmp(k, "send")) {
				conf.work_mode = WORK_MODE_SEND;
				continue;
			}
			if (0 == strcmp(k, "pp")) {
				conf.work_mode = WORK_MODE_PP;
				conf.poll = true;
				continue;
			}
			if (0 == strcmp(k, "pp-flood")) {
				conf.work_mode = WORK_MODE_PP_FLOOD;
				conf.poll = true;
				continue;
			}
			printf("Invalid work mode(%s), should be: echo, recv, send, pp.\n", k);
			exit(-1);

			continue;
		}

		if (0 == strcmp(k, "-h")) {
			printf(
			       "xudpperf <mode> [option]\n"
			       "\n"
			       " mode: send, recv\n"
			       "\n"
			       "options:\n"
			       "    -h      print this help message\n"
			       "    -l      <msg len>\n"
			       "    --flood <tx num> flood sent packets without epoll\n"
			       "    --dst   <ip:port> \n"
			       "    --src   <ip:port> set bind local addr. default 0.0.0.0:8080 \n"
			       "    --noarp use EE:FF:FF:FF:FF:FF as the dst mac addr.\n"
			       "    --log   set log level. error,warn,info,debug\n"
			       );
			exit(0);
		}

		if (0 == strcmp(k, "-s")) {
			conf.stats = 1;
			continue;
		}

		if (0 == strcmp(k, "--force-copy")) {
			conf.force_copy = 1;
			continue;
		}
		if (0 == strcmp(k, "--noxdp")) {
			conf.noxdp = 1;
			continue;
		}
		if (0 == strcmp(k, "--noarp")) {
			conf.noarp = 1;
			continue;
		}

		if (0 == strcmp(k, "--poll")) {
			conf.poll = 1;
			continue;
		}

		if (0 == strcmp(k, "--tx-zc")) {
			conf.send_func = ch_send_frame;
			continue;
		}
		if (0 == strcmp(k, "--tx-rand-port")) {
			conf.tx_rand_port = 1;
			continue;
		}


		v = argv[++i];

		if (0 == strcmp(k, "--flood")) {
			conf.flood = atoi(v);
			continue;
		}

		if (0 == strcmp(k, "-n")) {
			conf.npkt = atoi(v);
			continue;
		}

		if (0 == strcmp(k, "-l")) {
			conf.msglen = atoi(v);
			continue;
		}
		if (0 == strcmp(k, "--frame")) {
			conf.frame_size = atoi(v);
			continue;
		}
		if (0 == strcmp(k, "--dst")) {
			copy_addr(v, &conf.dst);
			continue;
		}
		if (0 == strcmp(k, "--src")) {
			copy_addr(v, &conf.addr[conf.addr_n++]);
			continue;
		}
		if (0 == strcmp(k, "--tx-batch-num")) {
			conf.tx_batch_num = atoi(v);
			continue;
		}
		if (0 == strcmp(k, "--headroom")) {
			conf.headroom = atoi(v);
			continue;
		}

		if (0 == strcmp(k, "--log")) {
			if (0 == strcmp(v, "error")) {
				conf.log_level = XUDP_LOG_ERR;
				continue;
			}
			if (0 == strcmp(v, "warn")) {
				conf.log_level = XUDP_LOG_WARN;
				continue;
			}
			if (0 == strcmp(v, "info")) {
				conf.log_level = XUDP_LOG_INFO;
				continue;
			}
			if (0 == strcmp(v, "debug")) {
				conf.log_level = XUDP_LOG_DEBUG;
				continue;
			}
			printf("Invalid log level, should be: error, warn, info, debug.\n");
			exit(-1);
		}

		printf("invalid option: %s\n", k);
		exit(-1);
	}
	if (!conf.addr_n) {
		v = "0.0.0.0:8080";
		copy_addr(v, &conf.addr[conf.addr_n++]);
		printf("set default src addr: %s\n", v);
	}
}

int main(int argc, char **argv)
{
	struct th *th;
	int ret = 0;
	xudp_conf xc = {};

	xudp *x;

	parse_argv(argc, argv);

	xc.group_num     = conf.flood;
	xc.log_level     = conf.log_level;
	xc.log_with_time = true;
	xc.force_copy    = conf.force_copy;
	xc.noxdp         = conf.noxdp;
	xc.noarp         = conf.noarp;
	xc.headroom      = conf.headroom;
	xc.frame_size    = conf.frame_size;
	if (conf.tx_batch_num)
		xc.tx_batch_num = conf.tx_batch_num;

	x = xudp_init(&xc, sizeof(xc));
	if (!x) {
		fprintf(stderr, "xudp_init %d\n", ret);
		return ret;
	}

	ret = xudp_bind(x, (struct sockaddr *)conf.addr, sizeof(struct sockaddr_in), conf.addr_n);

	if (ret) {
		fprintf(stderr, "xudp_bind %d\n", ret);
		return ret;
	}

	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);
	signal(SIGABRT, int_exit);

	signal(SIGALRM, alarm_handler);
	alarm(1);

	if (conf.flood) {
		flood_send(x);
		return 0;
	}

	th = malloc(sizeof(*th));
	th->x = x;
	th->id = 0;

	thread_handler(th);
	xudp_free(x);

	return 0;
}


