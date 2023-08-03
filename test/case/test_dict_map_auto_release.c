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

static int test_cluster_id;
static struct ch *tx_ch;

int xudp_dict_get_group_key(xudp *x, int key, int *group_id);

static int handler_msg(struct ch *ch, xudp_msg *m, char *buf)
{
	int ret, id, key, gid;

	if (4 == m->size) {
		return sprintf(buf, "%d/%d/%d/%d/%d",
			       mkkey(ch->th),
		     	       ch->th->cluster_id,
		     	       ch->th->id,
		     	       ch->libconf->conf.group_num,
		     	       syscall(__NR_gettid));
	}

	if (0 == strncmp("exit", m->p + 4, m->size)) {
		exit(0);
	};
	if (0 == strncmp("cover", m->p, m->size)) {
		return sprintf(buf, "%d/%d/%d/%d/%d",
			       mkkey(ch->th),
		     	       ch->th->cluster_id,
		     	       ch->th->id,
		     	       ch->libconf->conf.group_num,
		     	       syscall(__NR_gettid));
	};

	if (0 == strncmp("new for xsk release", m->p, m->size)) {
#if 0
		struct xudp_cluster_conf conf = {};
		int pid;

		conf.group_num = ch->libconf->conf.group_num;

		ret = xudp_cluster_new(ch->libconf->x, &conf);

		if (ret < 0)
			return sprintf(buf, "-1");

		pid = fork();
		if (pid == 0) {
			cluster_work(ret);
			sleep(3600);
		}

		sleep(1);


		test_cluster_id = ret;

		ret = xudp_cluster_new(ch->libconf->x, &conf);

		if (ret >= 0)
			cluster_work(ret);

		tx_ch = ch;
		xudp_cluster_detach(ch->libconf->x, test_cluster_id);

		return sprintf(buf, "%d,%d", test_cluster_id, ret);
#endif
	}

	if (0 == strncmp("check", m->p + 4, 17)) {
		key = ntohl(*(u32*)m->p);
//		xudp_dict_get_group_key(ch->libconf->x, key, &gid);
		return sprintf(buf, "%d/%d/%d/%d/%d/%d",
			       mkkey(ch->th),
		     	       ch->th->cluster_id,
		     	       ch->th->id,
		     	       ch->libconf->conf.group_num,
		     	       syscall(__NR_gettid),
			       gid);
	}
}

static void handler_recv(struct ch *ch)
{
	int n, i, ret, id, *p;
	xudp_msg *m;
	char buf[100];

	xudp_def_msg(hdr, 100);

	while (true) {
		n = xudp_recv_channel(ch->ch, hdr, 0);
		if (n < 0)
			break;

		for (i = 0; i < hdr->used; ++i) {
            		m = hdr->msg + i;
			n = handler_msg(ch, m, buf);

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
	libconf.conf.flow_dispatch = XUDP_FLOW_DISPATCH_TYPE_DICT;
	libconf.conf.map_dict_n    = 100000;
	libconf.handler            = handler_recv;
	//libconf.conf.log_level     = XUDP_LOG_DEBUG;

	return stdmain(&libconf);
}
