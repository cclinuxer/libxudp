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


static void handler_recv(struct ch *ch)
{
	int n, i, ret;
	xudp_msg *m;
	char buf[10];

	xudp_def_msg(hdr, 100);

	while (true) {
		n = xudp_recv_channel(ch->ch, hdr, 0);
		if (n < 0)
			break;

		for (i = 0; i < hdr->used; ++i) {
            		m = hdr->msg + i;

			n = snprintf(buf, sizeof(buf), "%d", syscall(__NR_gettid));

			ret = xudp_send_channel(ch->ch, buf, n, (struct sockaddr *)&m->peer_addr, 0);

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

	libconf.conf.group_num     = 10;
	libconf.conf.force_xdp     = true;
	libconf.conf.flow_dispatch = XUDP_FLOW_DISPATCH_TYPE_RR;
	libconf.handler            = handler_recv;

	return stdmain(&libconf);
}
