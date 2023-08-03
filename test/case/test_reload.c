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

// Simulate nginx reload scenarios where multiple groups of workers exist at the
// same time

static void handler_msg(struct ch *ch, xudp_msg *m)
{
	int ret, n;
	char buf[100];
	char cmd[100] = {0};

	if (m->size > 4) {
		memcpy(cmd, m->p + 4, m->size - 4);
		cmd[m->size - 4] = 0;
		printf("cmd: %s\n", cmd);

		if (!strcmp(cmd, "AGAIN")) {
			exit(FORK_STATUS_AGAIN);
		}

		if (!strcmp(cmd, "EXIT")) {
			exit(FORK_STATUS_EXIT);
		}
	}

	n = snprintf(buf, sizeof(buf), "%d/%d/%d",
		     ch->th->id,
		     ch->libconf->conf.group_num,
		     getpid());

	ret = xudp_send_channel(ch->ch, buf, n, (struct sockaddr *)&m->peer_addr, 0);

	if (ret < 0) {
		printf("xudp_send_one fail. %d\n", ret);
	}
}

int main(int argc, char **argv)
{
	struct libconf libconf = {};
	int pid;

	libconf.conf.group_num     = 10;
	libconf.conf.force_xdp     = true;
	libconf.conf.isolate_group = true;
	libconf.conf.flow_dispatch = XUDP_FLOW_DISPATCH_TYPE_DICT;

	libconf.handler_msg        = handler_msg;
	libconf.conf.map_dict_n    = 200;
	libconf.fork               = 1;
	libconf.fork_loop          = 1;
	libconf.nowait             = 1;

	stdmain(&libconf);

	libconf.dict_key_offset = 100;

	process();

	stdwait();

	return 0;
}
