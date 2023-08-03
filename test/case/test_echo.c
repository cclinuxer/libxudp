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


static void handler_msg(struct ch *ch, xudp_msg *m)
{
	int ret;

	ret = xudp_send_channel(ch->ch, m->p, m->size, (struct sockaddr *)&m->peer_addr, 0);

	if (ret < 0) {
		printf("xudp_send_one fail. %d\n", ret);
	}
}

int main(int argc, char **argv)
{
	struct libconf libconf = {};

	libconf.conf.group_num = 1;
	libconf.conf.force_xdp = true;
	libconf.handler_msg        = handler_msg;

	return stdmain(&libconf);
}
