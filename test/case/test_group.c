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

#include "lib.h"
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <malloc.h>

int get_res(int pid)
{
	char buf[1024];
	char *p;
	int fd;

	if (pid == -1)
		pid = getpid();

	sprintf(buf, "/proc/%d/statm", pid);

	fd = open(buf, O_RDONLY);
	read(fd, buf, 1024);

	p = buf;
	while (*p++ != ' ');

	close(fd);

	return atoi(p) * 4 * 1024;
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

			ret = xudp_send_channel(ch->ch, m->p, m->size, (struct sockaddr *)&m->peer_addr, 0);

			if (ret < 0) {
				printf("xudp_send_one fail. %d\n", ret);
			}
		}

		xudp_recycle(hdr);
		xudp_commit_channel(ch->ch);
	}
}

int main(int argc, char **argv)
{
	struct libconf libconf = {};
	int pid;

	libconf.conf.group_num = 1;
	libconf.conf.force_xdp = true;
	libconf.handler        = handler_recv;
	libconf.fork = 1;


	return 0;
}
