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

#include <errno.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <time.h>

#include <net/ethernet.h>
#include <net/if.h>
#include <linux/if_xdp.h>
#include <linux/if_link.h>

#include <linux/ip.h>
#include <linux/udp.h>

#include <sys/ipc.h>
#include <sys/shm.h>

#include "xudp_types.h"
#include "packet.h"
#include "ifapi.h"
#include "route.h"
#include "route6.h"
#include "kern.h"
#include "xsk.h"
#include "ip6.h"

struct bind_addr {
	struct sockaddr_storage *addr[MAX_IPPORT_NUM];
	/* this is for check it is used */
	u32 ref[MAX_IPPORT_NUM];
	u32 num;
};

static int pid_max()
{
	char buf[20];
	int fd, n, num;

	fd = open("/proc/sys/kernel/pid_max", O_RDONLY);
	if (fd < 0)
		return errno;

	n = read(fd, buf, sizeof(buf));
	if (n < 0) {
		close(fd);
		return errno;
	}

	num = atoi(buf);
	close(fd);

	return num;
}

/* save the matched addr that from user to nic.
 *
 * return the matched addr num
 */
static int xudp_nic_compare_addr(struct nl_info *info,
				 struct bind_addr *bind_addr,
				 struct xudp_nic *n, int *m4, int *m6)
{
	int p, p6, match, match6, i, family;
	struct nl_addr *addr;
	struct sockaddr_in *a4;
	struct sockaddr_in6 *a6 = NULL;

	match = 0;
	match6 = 0;
	p = 0;
	p6 = 0;

	/* should copy the addr, this include the port and ip */
	for (i = 0; i < bind_addr->num; ++i) {

		a4 = (struct sockaddr_in *)bind_addr->addr[i];
		family = a4->sin_family;

		if (family == AF_INET && !a4->sin_addr.s_addr) {
			goto wild;
		}

		if (family == AF_INET6) {
			a6 = (struct sockaddr_in6 *)bind_addr->addr[i];
			if (ip6_is_zero(&a6->sin6_addr))
				goto wild;
		}

		for (addr = info->addr; addr; addr = addr->next) {
			if (addr->family != family)
				continue;

			if (family == AF_INET) {
				if (addr->addr != a4->sin_addr.s_addr)
					continue;

				++match;

				/* n is null,
				 * when check for the nic is or not match */
				if (n)
					n->addr[p++] = *a4;

			} else {
				if (!ip6_eq(&a6->sin6_addr, &addr->addr6))
					continue;

				++match6;

				/* n is null,
				 * when check for the nic is or not match */
				if (n)
					n->addr6[p6++] = *a6;
			}

			if (n)
				++bind_addr->ref[i];
		}
		continue;

wild:
		for (addr = info->addr; addr; addr = addr->next) {
			if (addr->family != family)
				continue;

			if (n)
				++bind_addr->ref[i];

			if (family == AF_INET) {
				++match;
				if (!n)
					continue;

				n->addr[p].sin_addr.s_addr = addr->addr;
				n->addr[p++].sin_port = a4->sin_port;

			} else {
				++match6;
				if (!n)
					continue;

				ip6_cpy(&n->addr6[p6].sin6_addr, &addr->addr6);
				n->addr6[p6++].sin6_port = a6->sin6_port;
			}
		}
	}

	if (m4 && m6) {
		*m4 = match;
		*m6 = match6;
	}

	return match + match6;
}

static int xudp_nic_create(xudp *x,
			   struct nl_info *ni,
			   struct nl_info *head,
			   struct bind_addr *bind_addr,
			   int addr4_n, int addr6_n)
{
	int rx = 0, tx = 0, ret, chn;
	struct xudp_nic *n;
	struct nl_info *info;
	bool got_slave = false;

	zobj(n);

	n->link_fd = -1;

	n->next = x->nic;

	if (addr4_n) {
		n->addr4_n = addr4_n;
		n->addr = malloc(sizeof(*n->addr) * addr4_n);
	}

	if (addr6_n) {
		n->addr6_n = addr6_n;
		n->addr6 = malloc(sizeof(*n->addr6) * addr6_n);
	}

	x->nic = n;
	++ni->ref;
	n->ni = ni;
	n->x = x;
	++x->nic_n;

	if (ni->ismaster) {
		for (info = head; info; info = info->next) {
			if (info->master != ni)
				continue;

			if (!got_slave) {
				n->ni = info;
				++info->ref;
				got_slave = true;
			} else {
				ret = xudp_nic_create(x, info, head, bind_addr,
						      addr4_n, addr6_n);
				if (ret)
					return ret;
			}
		}
	}

	loginfo(x->log, "bind dev %s\n", n->ni->ifname);

	if (ni->master)
		info = ni->master;
	else
		info = ni;

	if (info->ifindex >= MAX_NIC_INDEX) {
		logerr(x->log, "ifindex too big: %d\n", info->ifindex);
		return -1;
	}

	xudp_nic_compare_addr(info, bind_addr, n, NULL, NULL);

	/* rx num */
	ret = ifgetchannels(info->ifname, &rx, &tx);
	if (ret) {
		logerr(x->log, "ifgetchannels error: %d\n", ret);
		return ret;
	}

	chn = rx;
	if (tx > rx)
		chn = tx;

	n->umem = malloc(sizeof(void *) * chn);
	memset(n->umem, 0, sizeof(void *) * chn);

	n->queue = rx;
	x->queue_n += rx;

	/* tx ring num */
	ret = ifgetringsize(info->ifname, &rx, &tx);
	if (ret) {
		logerr(x->log, "ifgetringsize error: %d\n", ret);
		return ret;
	}

	n->txring_n = tx;

	loginfo(x->log, "ring size: tx=%d, rx=%d\n", tx, rx);

	n->nic_index = info->ifindex;

	return 0;
}

static struct xudp_nic *xudp_nic_get_byid(xudp *x, int id)
{
	struct xudp_nic *n;

	for (n = x->nic; n; n = n->next) {
		if (n->nic_index == id)
			return n;
		if (n->ni->master && n->ni->master->ifindex == id)
			return n;
	}
	return NULL;
}

static int xudp_check_env(struct nl_info *info)
{
	char *nics = getenv("XUDP_NICS");
	char *p, *s;

	if (!nics)
		return 1;

	for (p = nics, s = p; ; ++p) {
		if (*p == 0 || *p == ':') {
			if (0 == strncmp(s, info->ifname, p - s)) {
				return 1;
			}

			if (*p == 0)
				return 0;
			s = p + 1;
		}
	}

	return 0;
}

static int xudp_bind_choose_dev(xudp *x, struct bind_addr *bind_addr)
{
	struct nl_info *ni, *info;
	int match4, match6;

	if (nl_link(&ni, 0, x->log)) {
		logerr(x->log, "got link by netlink fail.\n");
		return -XUDP_ERR_NIC_NL_LINK;
	}

	for (info = ni; info; info = info->next) {
		if (!(info->ifi_flags & IFF_UP))
			continue;

		if (info->ifi_flags & IFF_LOOPBACK)
			continue;

		if (info->ifi_flags & IFF_SLAVE)
			continue;

		if (!info->addr)
			continue;

		if (!xudp_check_env(info))
			continue;

		if (xudp_nic_compare_addr(info, bind_addr, NULL, &match4, &match6)) {
			if (xudp_nic_create(x, info, ni, bind_addr, match4, match6)) {
				return -XUDP_ERR_NIC_NL_LINK;
			}

		}
	}

	x->nlinfo = nl_info_free(ni, false);
	return 0;
}

static int xudp_xdp_info_update(xudp *x)
{
	int map, key, ret;

	map = bpf_map_get(&x->bpf, MAP_INFO);
	if (map < 0)
		return -XUDP_ERR_BPF_MAP;

        key = 0;
	ret = bpf_map_update_elem(map, &key, &x->kern_info, 0);
	if (ret) {
		logerr(x->log, "map xudp_info update fail.%s\n", strerror(errno));
		return -XUDP_ERR_BPF_MAP;
	}

	return ret;
}

static int xudp_xdp_set_info(xudp *x)
{
	struct xudp_nic *n;
	int i, j;

	x->kern_info.group_num = x->conf.group_num;

	i = j = 0;
	for (n = x->nic; n; n = n->next) {
		x->kern_info.nic_xskmap_set_offset[n->nic_index] = i;
		x->kern_info.nic_xskmap_offset[n->nic_index] = j;

		i += n->queue;
		j += n->queue * x->conf.group_num;
	}

	pthread_spin_init(&x->xskmap_set_lock, PTHREAD_PROCESS_SHARED);

	return xudp_xdp_info_update(x);
}

int __xudp_kern_xsk_alloc(xudp *x, int num, int *offset)
{
	int update_reuse = 0, ret;

	pthread_spin_lock(&x->xskmap_set_lock);

	*offset = x->kern_info.offset;

	if (x->kern_info.reuse == 0) {
		if (x->kern_info.offset + num <= x->map_xskmap_set_num) {
			goto end;
		} else {
			//check = x->kern_info.offset + num - x->map_xskmap_set_num;
			update_reuse = 1;
		}
	} else {
		//check = num;
		if (x->kern_info.offset + num > x->map_xskmap_set_num)
			update_reuse = 1;
	}

	/* TODO kernel not support for check xskmap value */

end:
	x->kern_info.offset = (x->kern_info.offset + num) % x->map_xskmap_set_num;
	if (update_reuse)
		x->kern_info.reuse += 1;
	ret = xudp_xdp_info_update(x);
	pthread_spin_unlock(&x->xskmap_set_lock);
	return ret;
}

int __xudp_kern_xsk_set(xudp *x, int offset, int sfd,
			int ifindex, int queue_id, int gid)
{
	int map, key, err;

	if (x->map_dict_active) {
		map = bpf_map_get(&x->bpf, MAP_XSKMAP_SET);
		if (map < 0) {
			logerr(x->log, "xsk set. get MPA_XSKMAP_SET fail.\n");
			return -XUDP_ERR_BPF_MAP;
		}

		offset += x->kern_info.nic_xskmap_set_offset[ifindex];
		offset += queue_id;
		offset = offset % x->map_xskmap_set_num;

		err = bpf_map_update_elem(map, &offset, &sfd, 0);
		if (err) {
			logerr(x->log, "xsk set. update XSKMAP_SET fail. %s\n",
		       	       strerror(errno));
			return -XUDP_ERR_BPF_MAP_UPDATE;
		}
	}

	map = bpf_map_get(&x->bpf, MAP_XSKMAP);
	if (map >= 0) {
		key = x->kern_info.nic_xskmap_offset[ifindex];
		key += x->conf.group_num * queue_id + gid;

		err = bpf_map_update_elem(map, &key, &sfd, 0);
		if (err) {
			logerr(x->log, "xsk set. update XSKMAP fail. %s\n",
		       	       strerror(errno));
			return -XUDP_ERR_BPF_MAP_UPDATE;
		}
	}

	return 0;
}

static int xudp_xdp_set_ipport(xudp *x, struct bind_addr *bind_addr)
{
	struct kern_ipport ipport = {}, *p;
	struct sockaddr_in6 *a6;
	struct sockaddr_in *a4;
	int map, i, key, ret;

	p = &ipport;

	for (i = 0; i < bind_addr->num; ++i) {
		a4 = (struct sockaddr_in *)bind_addr->addr[i];

		if (a4->sin_family == AF_INET) {
			p->addr[p->ipport_n] = a4->sin_addr.s_addr;
			p->port[p->ipport_n] = a4->sin_port;
			++p->ipport_n;
			continue;
		}

		a6 = (struct sockaddr_in6 *)bind_addr->addr[i];

		ip6_cpy(&p->addr6[p->ipport6_n], &a6->sin6_addr);
		p->port6[p->ipport6_n] = a6->sin6_port;
		++p->ipport6_n;
	}

	map = bpf_map_get(&x->bpf, MAP_IPPORT);
	if (map < 0)
		return -XUDP_ERR_BPF_MAP;

        key = 0;
	ret = bpf_map_update_elem(map, &key, p, 0);
	if (ret) {
		logerr(x->log, "map xudp_ipport update fail.%s\n", strerror(errno));
		return -XUDP_ERR_BPF_MAP;
	}

	return 0;
}

static int xudp_bpf_map_filter(struct bpf_map_def *def, void *_)
{
	xudp *x = _;

	if (0 == strcmp(def->name, MAP_DICT)) {
		int num;
		num = x->conf.map_dict_n;
		if (x->conf.map_dict_n_max_pid) {
			num = pid_max();
			x->conf.map_dict_n = num;
		}

		if (!num) {
			logerr(x->log, "map_dict max_entries is 0.\n");
			return -1;
		}

		def->type        = BPF_MAP_TYPE_ARRAY;
		def->key_size    = sizeof(int);
		def->value_size  = sizeof(struct kern_dict_item);
		def->max_entries = num;

		x->map_dict_active = true;
		return 0;
	}

	if (0 == strcmp(def->name, MAP_XSKMAP)) {
		int num;

		num = x->queue_n * x->conf.group_num;

		def->type         = BPF_MAP_TYPE_XSKMAP;
		def->key_size     = sizeof(int);
		def->value_size   = sizeof(int);
		def->max_entries = num;

		x->map_xskmaps_active = true;
		return 0;
	}

	if (0 == strcmp(def->name, MAP_XSKMAP_SET)) {
		int num;

		num = x->queue_n * x->conf.group_num * x->conf.xskmap_capability;

		def->type         = BPF_MAP_TYPE_XSKMAP;
		def->key_size     = sizeof(int);
		def->value_size   = sizeof(int);
		def->max_entries  = num;

		x->map_xskmap_set_num = num;

		x->map_xskmaps_active = true;
		return 0;
	}

	return 0;
}

static int xudp_xdp_bind_fd(int ifindex, int prog_fd, struct log *log)
{
#if CONF_BPF_LINK
	int fd;
	fd = bpf_xdp_link_create(prog_fd, ifindex);
	if (fd < 0) {
		logerr(log, "bpf xdp link create: %d. %s\n", fd,
		       strerror(errno));
		return fd;
	}
	return 0;
#else
	int ret;


	ret = nl_xdp_set(ifindex, prog_fd, 0, log);
	return ret;
#endif

}

static int xudp_xdp_bind(struct xudp_nic *n, int prog_fd, struct log *log)
{
#if CONF_BPF_LINK
#else
	if (n->ni->xdp_prog_id && !n->x->conf.force_xdp)
		return -1;
	n->link_fd = 1;
#endif
	return xudp_xdp_bind_fd(n->nic_index, prog_fd, log);
}

int xudp_xdp_clear()
{
	struct log *log, _log = {};
	struct nl_info *ni, *info;

	_log.level = LOG_LEVEL_ERR;
	log = &_log;

	if (nl_link(&ni, 0, log)) {
		logerr(log, "got link by netlink fail.\n");
		return -XUDP_ERR_NIC_NL_LINK;
	}

	for (info = ni; info; info = info->next) {
		if (info->ifi_flags & IFF_LOOPBACK)
			continue;

		xudp_xdp_bind_fd(info->ifindex, -1, log);
	}
	return 0;
}

static int xudp_bpf_namespace_bind(struct bpf *b)
{
	u32 sfd, idx = 0, key, v;
	struct bpf_map_info info;
	int err, fd;

	key = XUDP_MAP_ID;

	sfd = bpf_map_get(b, MAP_STATS);
	if (sfd < 0)
		return -XUDP_ERR_BPF_MAP_GET;

	while (true) {
		if (bpf_map_get_idx(b, idx++, &fd))
			break;

		if (fd == -1)
			continue;

		if (fd == sfd)
			continue;

		err = bpf_get_info_by_fd(fd, &info);
		if (err)
			return -errno;

		err = bpf_map_update_elem(sfd, &key, &info.id, 0);
		if (err)
			return -errno;
		++key;
	}

	v = key - XUDP_MAP_ID;
	key = XUDP_MAP_NUM;

	err = bpf_map_update_elem(sfd, &key, &v, 0);
	if (err)
		return err;

	key = XUDP_MAP_NS;
	v = net_namespace_id();
	err = bpf_map_update_elem(sfd, &key, &v, 0);
	if (err)
		return err;

	key = XUDP_MAP_TS;
	v = time(NULL);
	err = bpf_map_update_elem(sfd, &key, &v, 0);
	if (err)
		return err;
	return err;
}

static int xudp_init_xdp(xudp *x)
{
	int prog_fd, ret;
	struct xudp_nic *n;

	ret = 0;

	x->bpf.log             = x->log;
	x->bpf.map_filter      = xudp_bpf_map_filter;
	x->bpf.map_filter_data = x;

	prog_fd = kern_init(&x->bpf, x->conf.flow_dispatch,
			    x->conf.xdp_custom,
			    x->conf.xdp_custom_size,
			    x->conf.xdp_custom_path);
	if (prog_fd < 0)
		return -XUDP_ERR_BPF_FD;

	/* bind xdp to nic */
	for (n = x->nic; n; n = n->next) {
		ret = xudp_xdp_bind(n, prog_fd, x->log);
		if (ret < 0) {
			logerr(x->log,
			       "dev %s has set xdp. try: ip link set %s xdp off\n",
		       	       n->ni->ifname, n->ni->ifname);
			ret = -XUDP_ERR_LINK_IF;
			goto end;
		}
	}

	x->bpf_need_free = true;

	ret = xudp_bpf_namespace_bind(&x->bpf);

end:
	loginfo(x->log, "xdp init ret %d\n", ret);

	return ret;
}

static u32 xudp_get_prefsrc(struct xudp_nic *nic, struct route_rule *rule)
{
	struct nl_addr *addr;
	u32 a0 = 0, a1, a2, off;

	if (rule->pref_src)
		return rule->pref_src;

	for (addr = nic->ni->addr; addr; addr = addr->next) {
		if (addr->family != AF_INET)
			continue;

		off = 32 - addr->prefixlen;

		a1 = ntohl(addr->addr) >> off;
		a2 = ntohl(rule->next_hop) >> off;

		if (a1 == a2)
			return addr->addr;

		a0 = addr->addr;
	}

	return a0;
}

static struct in6_addr* xudp_get_prefsrc6(struct xudp_nic *nic, struct route_rule6 *rule)
{
	struct nl_addr *addr;
	struct in6_addr *a6, *a0 = NULL;

	if (!ip6_is_zero(&rule->pref_src))
		return &rule->pref_src;

	for (addr = nic->ni->addr; addr; addr = addr->next) {
		if (addr->family != AF_INET6)
			continue;

		a6 = &rule->next_hop;
		if (ip6_is_zero(a6))
			a6 = &rule->dst;

		if (ip6_cmp(a6, &addr->addr6, addr->prefixlen))
			return &addr->addr6;

		a0 = &addr->addr6;
	}

	return a0;
}

static int xudp_check_route6(xudp *x)
{
	struct sockaddr_in6 *a6;
	struct route_rule6 *rule;
	struct xudp_nic *n;
	struct in6_addr *prefsrc;
	int i, ii;

	for (i = 0; i < x->route6->rules_n; ++i) {
		rule = x->route6->rules + i;
		rule->data = NULL;

		n = xudp_nic_get_byid(x, rule->ifid);

		if (!n)
			continue;

		prefsrc = xudp_get_prefsrc6(n, rule);

		for (ii = 0; ii < n->addr6_n; ++ii) {
			a6 = n->addr6 + ii;

			if (ip6_eq(&a6->sin6_addr, prefsrc)) {
				rule->data = a6;
				break;
			}
		}
	}

	return 0;
}

/* save client bind ip:port to rule, special the port must save to rule, then we can
 * got that when route lookup.
 */
static int xudp_check_route(xudp *x)
{
	struct sockaddr_in *addr;
	struct route_rule *rule;
	struct xudp_nic *n;
	u32 ip, prefsrc;
	int i, ii;

	for (i = 0; i < x->route->rules_n; ++i) {
		rule = x->route->rules + i;
		rule->data = NULL;

		n = xudp_nic_get_byid(x, rule->ifid);

		if (!n)
			continue;

		prefsrc = xudp_get_prefsrc(n, rule);

		for (ii = 0; ii < n->addr4_n; ++ii) {
			addr = n->addr + ii;
			ip = addr->sin_addr.s_addr;

			/* ip can not be 0.0.0.0, that been handled */
			if (ip == prefsrc) {
				rule->data = addr;
				break;
			}
		}
	}

	return 0;
}

static int xudp_check_assign_address(xudp *x, struct bind_addr *bind_addr)
{
	int i;

	for (i = 0; i < bind_addr->num; ++i) {
		if (bind_addr->ref[i] == 0)
			goto err;
	}

	return 0;

err:
	logerr(x->log, "Cannot assign requested address\n");
	return -1;
}

static int _xudp_bind(xudp *x, struct bind_addr *bind_addr)
{
	const char *msg;
	int ret;

	ret = xudp_bind_choose_dev(x, bind_addr);
	if (ret)
		return ret;

	ret = xudp_check_assign_address(x, bind_addr);
	if (ret)
		return -1;

	if (x->conf.noxdp) {
		ret = xudp_tx_xsk_init(x);
		msg = "noxdp";
	} else {
		if (xudp_init_xdp(x))
			return -XUDP_ERR_BPF_LOAD;

		ret = xudp_xdp_set_ipport(x, bind_addr);
		if (ret)
			return ret;

		ret = xudp_xdp_set_info(x);
		if (ret)
			return ret;

		ret = xudp_tx_xsk_init(x);
		if (ret < 0)
			return ret;

		if (x->conf.isolate_group) {
			ret = xudp_umem_check(x);
			msg = "isolate group";
		} else {
			ret = xudp_group_create_all(x);
			msg = "groups init completed";
		}

		if (ret < 0)
			return ret;
	}

	ret = xudp_check_route(x);
	if (ret < 0)
		return ret;

	ret = xudp_check_route6(x);
	if (ret < 0)
		return ret;

	logwrn(x->log, "bind success. %s.\n", msg);
	return 0;
}

void xudp_nics_unbond(xudp *x)
{
	struct xudp_nic *n;

	for (n = x->nic; n; n = n->next) {
		if (n->link_fd > -1) {
#if CONF_BPF_LINK
			loginfo(x->log, "unbind dev(%s) by bpf-link fd: %d\n",
				n->ni->ifname, n->link_fd);
			close(n->link_fd);
#else
			loginfo(x->log, "unbind dev(%s) by netlink\n",
				n->ni->ifname);
			nl_xdp_off(n->nic_index, x->log);
#endif
		}
	}
}

void xudp_nics_free(xudp *x)
{
	struct xudp_nic *n, *t;

	for (n = x->nic; n; n = t) {
		t = n->next;
		if (n->addr)
			free(n->addr);
		if (n->addr6)
			free(n->addr6);
		if (n->umem)
			free(n->umem);
		free(n);
	}
}

int xudp_bind(xudp *x, struct sockaddr *_a, socklen_t addrlen, int num)
{
	struct bind_addr bind_addr = {};
	struct sockaddr *a;
	void *p;
	int i;

	if (num > MAX_IPPORT_NUM)
		return -E2BIG;

	for (i = 0; i < num; ++i) {
		p = _a;
		p = p + addrlen * i;
		a = p;

		if (a->sa_family != AF_INET && a->sa_family != AF_INET6) {
			logerr(x->log, "xudp_bind not support family: %d.\n", a->sa_family);
			continue;
		}

		bind_addr.addr[bind_addr.num++] = p;
	}

	if (!bind_addr.num)
		return -1;

	return _xudp_bind(x, &bind_addr);
}
