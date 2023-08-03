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

#include <sys/shm.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sys/capability.h>

#include "xudp_types.h"
#include "neigh.h"
#include "route.h"
#include "route6.h"
#include "xsk.h"
#include "ifapi.h"

static void xudp_init_byenv(struct xudp *x)
{
	char *p;
	int v;

	p = getenv("XUDP_CONF_FORCE_COPY");
	if (p) {
		v = atoi(p);
		if (v)
			x->flags |= XDP_COPY;
		else
			x->flags &= ~XDP_COPY;
	}

	p = getenv("XUDP_CONF_LOG_LEVEL");
	if (p) {
		x->log->level = atoi(p);
	}

	p = getenv("XUDP_CONF_LOG_US");
	if (p) {
		x->log->time_us = atoi(p);
	}
}

static int xudp_keep_capability()
{
	/* Retain capabilities over an identity change */
	if (prctl(PR_SET_KEEPCAPS, 1L))
		return 1; /* Fatal error */

	return 0;
}

void xudp_tx_set_frame_size(int size);
static int xudp_config(xudp *x)
{
	struct log *log;

	log = x->log;

#define check(x, v) if (!x) x = v;

	check(x->conf.sndnum,           1024 * 1);
	check(x->conf.rcvnum,           1024 * 1);
	check(x->conf.frame_size,       4096);
	check(x->conf.headroom,       256);
	check(x->conf.group_num,        1);
	check(x->conf.tx_batch_num,     100);
	check(x->conf.xskmap_capability, 10);

	if (x->conf.xskmap_capability > MAX_CLUSTER_SLOT_NUM)
		x->conf.xskmap_capability = MAX_CLUSTER_SLOT_NUM;

	x->conf.headroom = align(x->conf.headroom, 64);

#if XDP_UMEM_UNALIGNED_CHUNK_FLAG
	if (is_power_of_2(x->conf.frame_size))
		x->conf.unaligned = false;
	else
		x->conf.unaligned = true;
#else
	if (!is_power_of_2(x->conf.frame_size))
		return -1;
#endif

	if (x->conf.frame_size - x->conf.headroom < MTU)
		return -1;

	if (!is_power_of_2(x->conf.rcvnum))
		return -1;

	if (!is_power_of_2(x->conf.sndnum))
		return -1;

	log->cb   = x->conf.log_cb;
	log->data = x->conf.log_data;
	log->time = x->conf.log_with_time;
	if (x->conf.log_level)
		log->level = x->conf.log_level - 1;

	if (x->conf.no_force_zerocopy) {
		if (x->conf.force_copy)
			x->flags |= XDP_COPY;
	} else {
		x->flags |= XDP_ZEROCOPY;
	}

	xudp_init_byenv(x);
	if (x->conf.keep_cap)
		xudp_keep_capability();

	/* copy read mostly value */
	x->tx_batch_num = x->conf.tx_batch_num;
	x->frame_size   = x->conf.frame_size;
	x->noarp        = x->conf.noarp;

	xudp_tx_set_frame_size(x->conf.frame_size);
	return 0;
}

static void set_rlimit(struct log *log)
{
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};

	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		logerr(log, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
			strerror(errno));
	}
}

static bool check_xsk_support()
{
	int fd;

	fd = socket(PF_XDP, SOCK_RAW, 0);
	if (fd < 0 && errno == EAFNOSUPPORT)
		return false;

	close(fd);
	return true;
}

xudp *xudp_alloc(u32 dump_size)
{
	int shmid;
	void *p;

	/*
	 * |----- PAGE_SIZE -----------------------|--------- dump_size -----------|
	 * |--- offset --|- xudp -| |- dump ring --|
	 *
	 *
	 * */

	if (XUDP_SHM_OFFSET <= sizeof(XUDP_SHM_MAGIC) - 1)
		return NULL;

	if (XUDP_SHM_OFFSET + sizeof(xudp) + sizeof(struct log) + sizeof(struct dump_ring) > PAGE_SIZE)
		return NULL;

	shmid = shmget(IPC_PRIVATE, PAGE_SIZE + dump_size, 0);
	if (-1 == shmid) {
		printf("xudp init shmget fail. %s.\n", strerror(errno));
		return NULL;
	}

	p = shmat(shmid, NULL, 0);

	/* set the shm auto release */
	if (shmctl(shmid, IPC_RMID, NULL)) {
		printf("set shmid %d IPC_RMID fail. %s.\n",
		       shmid, strerror(errno));
	}

	if (p == (void *)-1) {
		printf("xudp init shmat fail. %s.\n",
		       strerror(errno));
		return NULL;
	}

	/* copy magic before set to txch->shmid */
	memcpy(p, XUDP_SHM_MAGIC, sizeof(XUDP_SHM_MAGIC));

	return p + XUDP_SHM_OFFSET;
}

void dump_prepare(void *p, struct dump *d, u64 size)
{
	struct dump_ring *r;

	r = (p - XUDP_SHM_OFFSET) + PAGE_SIZE - sizeof(*r);
	r->size = size;
	d->prepare = ((void *)r) - ((void *)d);
}

xudp *xudp_init(struct xudp_conf *c, u32 c_size)
{
	struct log *log;
	void *p;
	xudp *x;

	if (!check_xsk_support())
		return NULL;

	p = xudp_alloc(c->dump_prepare_size);
	if (!p)
		return NULL;
	x = p;

	if (c->dump_prepare_size)
		dump_prepare(p, &x->dump, c->dump_prepare_size);

	log = (struct log *)(x + 1);

	log->level      = LOG_LEVEL_WARN;
	log->prefix     = "xudp: ";
	log->prefix_len = strlen(log->prefix);

	neigh_init();

	x->log = log;

	if (c) {
		if (c_size != sizeof(x->conf)) {
			logerr(log, "config size not eq.\n");
			goto end;
		} else {
			memcpy(&x->conf, c, c_size);
		}
	}

	if (xudp_config(x))
		goto end;

	x->route = route_init(x->log);
	x->route6 = route6_init(x->log);

	set_rlimit(log);

	if (!x->route || !x->route6)
		goto end;

	INIT_LIST_HEAD(&x->dummy_xsk);
	return x;

end:
	free(x->log);
	munmap(x, sizeof(*x));
	if (x->route)
		route_free(x->route);

	if (x->route6)
		route6_free(x->route6);
	return NULL;
}

void xudp_nics_free(xudp *x);
void xudp_nics_unbond(xudp *x);
int xudp_clusters_destory(xudp *x);
void umem_free_many(xudp *x);

static void __xudp_free(xudp *x, bool unbind)
{
	struct xdpsock *xsk, *n;

	list_for_each_entry_safe(xsk, n, &x->dummy_xsk, list) {
		__xudp_xsk_free(xsk);
		free(xsk);
	}

	xudp_tx_xsk_free(x);

	umem_free_many(x);

	xudp_nics_free(x);
	if (!unbind)
		nl_info_free(x->nlinfo, true);

	route_free(x->route);
	route6_free(x->route6);

	if (x->bpf_need_free)
		bpf_close(&x->bpf);

	shmdt(((void *)x) - XUDP_SHM_OFFSET);
}

void xudp_unbind(xudp *x)
{
	__xudp_free(x, true);
}

void xudp_free(xudp *x)
{
	int i;

	xudp_nics_unbond(x);

	if (x->groups) {
		struct xudp_group *g;

		for (i = 0; i < x->conf.group_num; ++i) {
			g = x->groups[i];
			xudp_group_free(g);
		}
	}

	__xudp_free(x, false);
}

struct xudp_group *xudp_group_get(xudp *x, int gid)
{
	if (gid > x->conf.group_num)
		return NULL;

	if (x->conf.isolate_group)
		return NULL;

	return x->groups[gid];
}

int xudp_bpf_map_update(xudp *x, const char *name, int *key, void *value)
{
	int map;

	map = bpf_map_get(&x->bpf, name);
	if (map < 0)
		return -XUDP_ERR_BPF_MAP_GET;

	return bpf_map_update_elem(map, key, value, 0);
}

char *xudp_strerr(int err)
{

	switch (err) {

	case XUDP_ERR_BPF_LOAD:
	case XUDP_ERR_BPF_FD:
		return "xudp: bpf load error.";

	case XUDP_ERR_BPF_MAP:
		return "xudp: bpf map get/update fail.";

	case XUDP_ERR_SET_XSK:
	case XUDP_ERR_LINK_IF:
	case XUDP_ERR_NOBIND:
	case XUDP_ERR_CQ_NOSPACE:
	case XUDP_ERR_FQ_NOSPACE:
	case XUDP_ERR_TX_NOSPACE:
	case XUDP_ERR_RX_NOSPACE:
	case XUDP_ERR_CHANNEL_ID_OVERFLOW:
	case XUDP_ERR_NIC_INDEX_OVERFLOW:
	case XUDP_ERR_NIC_CHANNEL_OVERFLOW:
	case XUDP_ERR_NIC_CHANNEL:
	case XUDP_ERR_NIC_MAC:
	case XUDP_ERR_NIC_MORE_ADDR:
	case XUDP_ERR_NIC_NO_ADDR:
	case XUDP_ERR_NIC_NL_LINK:
	case XUDP_ERR_NIC_SLAVES_OVERFLOW:
	case XUDP_ERR_NIC_SLAVES_NOTFOUND:
	case XUDP_ERR_NIC_SLAVES_EMPTY:
	default:
		return "xudp: unknow.";
	}
}
