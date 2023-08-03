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

#include "ifapi.h"
#include "ip6.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define NLMSG_ATTR(nlh, data)  \
	((struct rtattr*)(((char*)nlh) + NLMSG_SPACE(sizeof(*data))))

#define RT_ATTR_NEXT(attr)  \
	((struct rtattr*)(((char*)attr) + NLMSG_ALIGN(attr->rta_len)))

#define NL_ATTR_NEXT(attr)  \
	((struct nlattr*)(((char*)attr) + NLMSG_ALIGN(attr->nla_len)))

#define ATTR_OK(attr, nl) (((char*)attr) - ((char*)nl) < (nl)->nlmsg_len)
#define ATTR_PAYLOAD(attr)  (void *)(attr + 1)

#define NEST_ATTR(attr) \
	((struct rtattr*)(((char*)attr) + NLMSG_ALIGN(sizeof(*attr))))

#define NEST_OK(attr, first) (((char*)attr) - ((char*)first) < (first)->rta_len)

#define NEST_ATTR_NEXT(attr) \
	((struct rtattr*)(((char*)attr) + NLMSG_ALIGN(attr->rta_len)))

#define nest_attr_foreach(n, attr) \
	for (n = NEST_ATTR(attr); NEST_OK(n, attr); n = NEST_ATTR_NEXT(n))

#define attr_foreach(attr, hdr, msg) \
	for (attr = NLMSG_ATTR(hdr, msg); ATTR_OK(attr, hdr); attr = RT_ATTR_NEXT(attr))

#define nl_put_attr_32(nlh, type, v) {\
	struct nlattr *attr; \
	attr = (struct nlattr *)(((char *)(nlh)) \
				+ NLMSG_ALIGN((nlh)->nlmsg_len)); \
	attr->nla_type = type; \
	attr->nla_len = NLA_HDRLEN + sizeof(int); \
	*(int *)ATTR_PAYLOAD(attr) = v; \
	(nlh)->nlmsg_len += NLA_ALIGN(attr->nla_len);\
}

#define attr_payload32(attr)  (*(uint *)(ATTR_PAYLOAD(attr)))
#define attr_payload32be(attr)  (*(__be32 *)(ATTR_PAYLOAD(attr)))
#define attr_payload_in6(attr)  (struct in6_addr *)(ATTR_PAYLOAD(attr))


#ifndef SOL_NETLINK
#define SOL_NETLINK       270
#endif

struct cb_data{
	struct nl_info *head;
	u8 family;
	int ifindex;
	__be32 addr;
	struct in6_addr *addr6;
	unsigned char *mac;
	int ret;
	int num;
	struct list_head *list;
};


typedef int (*libbpf_dump_nlmsg_t)(void *cookie, void *msg, struct nlattr **tb);
typedef int (*__dump_nlmsg_t)(struct nlmsghdr *nlmsg, libbpf_dump_nlmsg_t,
			      void *cookie);

int ifgetchannels(const char *name, int *rx, int *tx)
{
    	int fd, ret;
    	struct ifreq ifr = {};
    	struct ethtool_channels ch = {0};

    	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

    	ch.cmd = ETHTOOL_GCHANNELS;

	strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name) - 1);

    	ifr.ifr_data = (void*)&ch;

    	ret = ioctl(fd, SIOCETHTOOL, &ifr);
    	if (ret)
		goto end;

	*rx = ch.rx_count ? : ch.combined_count;
	*tx = ch.tx_count ? : ch.combined_count;

    	ret = 0;

end:
    	close(fd);
	return ret;
}

int ifgetringsize(const char *name, int *rx, int *tx)
{
    	int fd, ret;
    	struct ifreq ifr = {};
    	struct ethtool_ringparam ring = {0};

    	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

    	ring.cmd = ETHTOOL_GRINGPARAM;

	strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name) - 1);

    	ifr.ifr_data = (void*)&ring;

    	ret = ioctl(fd, SIOCETHTOOL, &ifr);
    	if (ret)
		goto end;

	*rx = ring.rx_pending;
	*tx = ring.tx_pending;

    	ret = 0;

end:
    	close(fd);
	return ret;
}

static int nl_find_bond_slave(struct nl_info *head, struct nl_info *master)
{
	int num, fd, ret = 0;
	char *s, *e;
	char buf[1024];
	struct nl_info *p;

	snprintf(buf, sizeof(buf), "/sys/class/net/%s/bonding/slaves",
		 master->ifname);

	fd = open(buf, O_RDONLY);
	if (fd < 0)
		return -errno;

	num = read(fd, buf, sizeof(buf));
	if (num <= 0) {
		ret = -errno;
		goto end;
	}
	if (num == sizeof(buf)) {
		ret = -2;
		goto end;
	}
	if (num == 0) {
		ret = -3;
		goto end;
	}

	if (buf[num - 1] == '\n')
		num = num - 1;


	buf[num] = 0;

	s = buf;
	while (true) {
		e = s;
		while (*e != ' ' && *e != 0)
			++e;

		*e = 0;

		for (p = head; p; p = p->next) {
			if (0 != strcmp(s, p->ifname))
				continue;
			p->master = master;
			p->isbond = true;
			goto found;
		}

		ret = -4;
		goto end;
found:
		if (e - buf >= num)
			break;

		s = e + 1;

		while (*s == ' ')
			++s;
	}

end:
	close(fd);
	return ret;
}

static int nl_check_bond(struct nl_info *ni)
{
	struct nl_info *head;
	int ret = 0;

	head =ni;
	for (; ni; ni = ni->next) {
		if (ni->ifi_flags & IFF_MASTER) {
			ni->ismaster = true;
			ret = nl_find_bond_slave(head, ni);
			if (ret)
				return ret;
		}
	}
	return 0;

}

static inline int nlmsg_len(const struct nlmsghdr *nlh)
{
	return nlh->nlmsg_len - NLMSG_HDRLEN;
}

static int nl_errmsg(struct nlmsghdr *nlh, struct log *log)
{
	struct nlattr *attr;
	struct nlmsgerr *err;
	int hlen;

	/* no TLVs, nothing to do here */
	if (!(nlh->nlmsg_flags & NLM_F_ACK_TLVS))
		return 0;

	err = (struct nlmsgerr *)NLMSG_DATA(nlh);
	hlen = sizeof(*err);

	/* if NLM_F_CAPPED is set then the inner err msg was capped */
	if (!(nlh->nlmsg_flags & NLM_F_CAPPED))
		hlen += nlmsg_len(&err->msg);

	attr = (struct nlattr *) ((void *) err + hlen);

	for (; ATTR_OK(attr, nlh); attr = NL_ATTR_NEXT(attr)) {
		if (NLMSGERR_ATTR_MSG != attr->nla_type)
			continue;

		logerr(log, "kernel err: %s\n", ATTR_PAYLOAD(attr));
	}

	return 0;
}

static int netlink_recv(int sock, __u32 nl_pid, int seq,
			    __dump_nlmsg_t _fn, libbpf_dump_nlmsg_t fn,
			    void *cookie, struct log *log)
{
	bool multipart = true;
	struct nlmsgerr *err;
	struct nlmsghdr *nh;
	char buf[4096];
	int len, ret;

	while (multipart) {
		multipart = false;
		len = recv(sock, buf, sizeof(buf), 0);
		if (len < 0) {
			ret = -errno;
			goto done;
		}

		if (len == 0)
			break;

		for (nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, len);
		     nh = NLMSG_NEXT(nh, len)) {
			if (nh->nlmsg_pid != nl_pid) {
				ret = -1;
				goto done;
			}
			if (nh->nlmsg_seq != seq) {
				ret = -1;
				goto done;
			}
			if (nh->nlmsg_flags & NLM_F_MULTI)
				multipart = true;
			switch (nh->nlmsg_type) {
			case NLMSG_ERROR:
				err = (struct nlmsgerr *)NLMSG_DATA(nh);
				if (!err->error)
					continue;
				ret = err->error;
				nl_errmsg(nh, log);
				goto done;
			case NLMSG_DONE:
				return 0;
			default:
				break;
			}
			if (_fn) {
				ret = _fn(nh, fn, cookie);
				if (ret)
					return ret;
			}
		}
	}
	ret = 0;
done:
	return ret;
}

typedef int (recv_handler)(struct nlmsghdr*, struct cb_data *, struct log *log);

static int nl_recv_proc(int sock, recv_handler handler, struct cb_data *data,
			struct log *log)
{
	char buf[4096];
	int n, offset;
	struct nlmsghdr *h;

	offset = 0;

	while (1) {
		n = recv(sock, buf + offset, sizeof(buf) - offset, 0);

		if (n < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;

			return -1;
		}

		n += offset;

		h  = (struct nlmsghdr *)buf;

		while (1) {
			if (n < sizeof(*h))
				break;

			if (h->nlmsg_len > sizeof(buf))
				return -1;

			if (h->nlmsg_len > n) {
				break;
			}

			if (h->nlmsg_type == NLMSG_DONE)
				goto end;

        		if (h->nlmsg_flags & NLM_F_DUMP_INTR) {
            			logerr(log, "Dump was interrupted\n");
            			return -1;
        		}

        		if (h->nlmsg_type == NLMSG_ERROR) {
            			logerr(log, "netlink reported error");
				return -1;
        		}

			if (handler(h, data, log))
				goto end;

        		h = NLMSG_NEXT(h, n);
		}

		if ((char *)h != buf)
			memcpy(buf, h, n);

		offset = n;
	}

end:
	return 0;
}

static int netlink_open(__u32 *nl_pid, struct log *log)
{
	struct sockaddr_nl sa;
	socklen_t addrlen;
	int one = 1, ret, size = 1024 * 1024;
	int sock;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;

	sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sock < 0)
		return -errno;

	if (setsockopt(sock, SOL_NETLINK, NETLINK_EXT_ACK,
		       &one, sizeof(one)) < 0) {
		logwrn(log, "Netlink error reporting not supported\n");
	}

	if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size))) {
		logwrn(log, "set SO_RCVBUF err\n");
	}

	if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size))) {
		logwrn(log, "set SO_RCVBUF err\n");
	}

	if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		ret = -errno;
		goto cleanup;
	}

	addrlen = sizeof(sa);
	if (getsockname(sock, (struct sockaddr *)&sa, &addrlen) < 0) {
		ret = -errno;
		goto cleanup;
	}

	if (addrlen != sizeof(sa)) {
		ret = -1;;
		goto cleanup;
	}

	*nl_pid = sa.nl_pid;
	return sock;

cleanup:
	close(sock);
	return ret;
}

static int nl_req_route(int sock)
{
  	struct {
        	struct nlmsghdr nlh;
		struct rtmsg rg;
    	} nl_request = {};

	nl_request.nlh.nlmsg_type  = RTM_GETROUTE;
	nl_request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nl_request.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));
	nl_request.nlh.nlmsg_seq   = time(NULL);

	nl_request.rg.rtm_family  = AF_UNSPEC;
	nl_request.rg.rtm_table  = RT_TABLE_MAIN;

//	nl_request.rg.rtm_flags |= RTM_F_LOOKUP_TABLE;

	if (send(sock, &nl_request, sizeof(nl_request), 0) < 0) {
		return errno;
	}

	return 0;
}

static int nl_req_link(int sock, int type)
{
  	struct {
        	struct nlmsghdr nlh;
		struct ifinfomsg ifm;
    	} nl_request = {};

	nl_request.nlh.nlmsg_type  = type;
	nl_request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nl_request.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	nl_request.nlh.nlmsg_seq   = time(NULL);

	nl_request.ifm.ifi_family  = AF_PACKET;

	if (send(sock, &nl_request, sizeof(nl_request), 0) < 0) {
		return errno;
	}

	return 0;
}

static int nl_req_neigh(int sock, int type)
{
  	struct {
        	struct nlmsghdr nlh;
		struct ndmsg ng;
    	} nl_request = {};

	nl_request.nlh.nlmsg_type  = type;
	nl_request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nl_request.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct ndmsg));
	nl_request.nlh.nlmsg_seq   = time(NULL);

	nl_request.ng.ndm_family  = AF_UNSPEC;

	if (send(sock, &nl_request, sizeof(nl_request), 0) < 0) {
		return errno;
	}

	return 0;
}

static int nl_req_addr(int sock, int type)
{
  	struct {
        	struct nlmsghdr nlh;
		struct ifaddrmsg ifa;
    	} nl_request = {};

	nl_request.nlh.nlmsg_type  = type;
	nl_request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nl_request.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	nl_request.nlh.nlmsg_seq   = time(NULL);

	nl_request.ifa.ifa_family  = AF_PACKET;

	if (send(sock, &nl_request, sizeof(nl_request), 0) < 0) {
		return errno;
	}

	return 0;
}

static int parse_link_bind_addr(struct nlmsghdr* nl, struct cb_data *data,
				struct log *log)
{
	struct ifaddrmsg *r;
	struct rtattr *attr;
	struct nl_info *info;
	struct nl_addr *na;

    	r = NLMSG_DATA(nl);

	if (r->ifa_family != AF_INET && r->ifa_family != AF_INET6)
		return 0;

	if (data->ifindex && r->ifa_index != data->ifindex)
		return 0;

	for (info = data->head; info; info = info->next) {
		if (info->ifindex == r->ifa_index)
			goto found;
	}

	logdebug(log, "not found %d\n", r->ifa_index);

	data->ret = -1;
	return 1;

found:
	na = malloc(sizeof(*na));
	na->next = info->addr;
	info->addr = na;

	na->prefixlen = r->ifa_prefixlen;
	na->family = r->ifa_family;

	attr_foreach(attr, nl, r)
	{
		switch(attr->rta_type) {
		case IFA_ADDRESS:
			if (na->family == AF_INET)
				na->addr = attr_payload32be(attr);
			else
				ip6_cpy(&na->addr6, ATTR_PAYLOAD(attr));
			break;
		}
	}

	return 0;
}

static int parse_link(struct nlmsghdr* nl, struct cb_data *data, struct log *log)
{
	struct ifinfomsg *ifi;
	struct rtattr *attr;
	struct nl_info *info;
	char *name;
	int len;

    	ifi = NLMSG_DATA(nl);

	if (data->ifindex && ifi->ifi_index != data->ifindex)
		return 0;

	info = malloc(sizeof(*info));
	memset(info, 0, sizeof(*info));

	info->ifindex    = ifi->ifi_index;
	info->ifi_type   = ifi->ifi_type;
	info->ifi_flags  = ifi->ifi_flags;

	info->next = data->head;
	data->head = info;

	attr_foreach(attr, nl, ifi)
	{
		switch(attr->rta_type) {
		case IFLA_ADDRESS:
			memcpy(info->mac, ATTR_PAYLOAD(attr), 6);
			break;


		case IFLA_MTU:
			info->mtu = attr_payload32(attr);
			break;

		case IFLA_IFNAME:
			name = ATTR_PAYLOAD(attr);
			len = attr->rta_len - 4;
			if (len > sizeof(info->ifname) - 1) {
				len = sizeof(info->ifname) - 1;
			}
			memcpy(info->ifname, name, len);
			info->ifname[len] = 0;
			break;

		case IFLA_XDP:
			{
				struct rtattr *nest_attr;
				nest_attr_foreach(nest_attr, attr) {
				switch(nest_attr->rta_type) {
					case IFLA_XDP_PROG_ID:
						info->xdp_prog_id = attr_payload32(attr);
						break;
					}
				}
			}
		}
	}

	return 0;
}

int nl_link(struct nl_info **ni, int ifindex, struct log *log)
{
	int sock, ret;
	__u32 nl_pid = 0;
	struct cb_data data = {};

	sock = netlink_open(&nl_pid, log);
	if (sock < 0)
		return sock;

	data.ifindex = ifindex;

	/* addr */
	if (nl_req_link(sock, RTM_GETLINK)) {
		ret = errno;
		goto err;
	}

	ret = nl_recv_proc(sock, parse_link, &data, log);
	if (!ret)
		*ni = data.head;
	else
		goto err;

	/* link */
	if (nl_req_addr(sock, RTM_GETADDR)) {
		ret = errno;
		goto err;
	}


	ret = nl_recv_proc(sock, parse_link_bind_addr, &data, log);
	if (ret || data.ret) {
		nl_info_free(data.head, log);
		ret = -1;
		goto err;
	}

	ret = nl_check_bond(*ni);

err:
	close(sock);
	if (ret)
		nl_info_free(*ni, true);
	return ret;
}

int nl_link_byname(struct nl_info **_ni, const char *name, struct log *log)
{
	struct nl_info *ni, **p;
	int ret;

	ret = nl_link(&ni, 0, log);
	if (ret)
		return ret;

	for (p = &ni; *p; p = &(*p)->next) {
		if (0 == strcmp(name, (*p)->ifname))
		{
			*_ni = *p;
			*p = (*p)->next;
			ret = 0;
			goto found;
		}
	}
	ret = -1;

found:
	nl_info_free(ni, log);
	return ret;
}

void nl_route_free(struct list_head *head)
{
	struct nl_route *r, *n;
	list_for_each_entry_safe(n, r, head, list) {
		free(n);
	}
}

static int parse_route(struct nlmsghdr* nl,
		       struct cb_data *data, struct log *log)
{
	struct rtmsg *rg;
	struct rtattr *attr;
	struct nl_route *r, *n;

    	rg = NLMSG_DATA(nl);

	if (rg->rtm_family != data->family)
		return 0;

	if (rg->rtm_type != RTN_UNICAST)
		return 0;

	if (rg->rtm_family == AF_INET6 && rg->rtm_table != RT_TABLE_MAIN)
		return 0;

	r = malloc(sizeof(*r));
	memset(r, 0, sizeof(*r));

	r->dst_len = rg->rtm_dst_len;

	++data->num;

	list_for_each_entry(n, data->list, list) {
		if (r->dst_len >= n->dst_len) {
			list_insert_before(&n->list, &r->list);
			goto ok;
		}
	}
	list_append(data->list, &r->list);
ok:
	if (rg->rtm_family == AF_INET) {
		attr_foreach(attr, nl, rg)
		{
			switch(attr->rta_type) {
			case RTA_DST:
				r->dst = attr_payload32(attr);
				break;

			case RTA_PREFSRC:
				r->pref_src = attr_payload32(attr);
				break;

			case RTA_OIF:
				r->ifid = attr_payload32(attr);
				break;

			case RTA_GATEWAY:
				r->next_hop = attr_payload32(attr);
				break;
			}
		}

		r->mask = ~((1 << (32 - r->dst_len)) - 1);
		r->dst_h = ntohl(r->dst);
	}

	if (rg->rtm_family == AF_INET6) {
		attr_foreach(attr, nl, rg)
		{
			switch(attr->rta_type) {
			case RTA_DST:
				memcpy((u8 *)&r->dst, ATTR_PAYLOAD(attr), 16);
				break;

			case RTA_PREFSRC:
				memcpy((u8 *)&r->pref_src, ATTR_PAYLOAD(attr), 16);
				break;

			case RTA_OIF:
				r->ifid = attr_payload32(attr);
				break;

			case RTA_GATEWAY:
				memcpy((u8 *)&r->next_hop, ATTR_PAYLOAD(attr), 16);
				break;
			}
		}
	}

	return 0;
}

int __nl_route(struct list_head *head, u8 family, struct log *log)
{
	struct cb_data data = {};
	struct nl_route *nr;
	unsigned char index;
	bool def = false;
	__u32 nl_pid = 0;
	int sock, ret;

	data.list = head;

	sock = netlink_open(&nl_pid, log);
	if (sock < 0)
		return sock;

	/* addr */
	if (nl_req_route(sock)) {
		ret = errno;
		goto err;
	}

	data.family = family;

	ret = nl_recv_proc(sock, parse_route, &data, log);
	if (ret)
		goto err;

	close(sock);

	index = 1;
	list_for_each_entry(nr, head, list) {
		if (nr->dst_len == 0 && !def) {
			def = true;
			nr->index = 0;
		} else {
			nr->index = index++;
		}
	}

	return data.num;

err:
	close(sock);
	if (ret)
		nl_route_free(head);
	return ret;
}

static int parse_neigh(struct nlmsghdr *nl, struct cb_data *data, struct log *log)
{
	struct ndmsg *n;
	struct rtattr *attr;
	__be32 *a4 = NULL;
	struct in6_addr *a6 = NULL;
	char *haddr = NULL;

    	n = NLMSG_DATA(nl);

	if (n->ndm_family != data->family)
		return 0;

	attr_foreach(attr, nl, n)
	{
		switch(attr->rta_type) {
		case NDA_DST:
			if (data->family == AF_INET)
				a4 = ATTR_PAYLOAD(attr);
			else
				a6 = ATTR_PAYLOAD(attr);
			break;

		case NDA_LLADDR:
			haddr = ATTR_PAYLOAD(attr);
			break;
		}

		if (data->family == AF_INET) {
			if (a4 && haddr) {
				if (data->addr == *a4) {
					memcpy(data->mac, haddr, 6);
					data->ret = 1;// found
					return 1;
				}
			}
		} else {
			if (a6 && haddr) {
				if (ip6_eq(data->addr6, a6)) {
					memcpy(data->mac, haddr, 6);
					data->ret = 1;// found
					return 1;
				}
			}
		}
	}

	return 0;
}

int __nl_neigh(struct cb_data *data, struct log *log)
{
	int sock, ret;
	__u32 nl_pid = 0;

	sock = netlink_open(&nl_pid, log);
	if (sock < 0)
		return sock;

	if (nl_req_neigh(sock, RTM_GETNEIGH)) {
		ret = errno;
		goto err;
	}

	ret = nl_recv_proc(sock, parse_neigh, data, log);

	if (!ret && data->ret) {
		ret = 0; // found
	}
	else{
		ret = -1; // not found
	}

err:
	close(sock);
	return ret;

}

int nl_neigh(__be32 addr, unsigned char *mac, struct log *log)
{
	struct cb_data data = {};

	data.addr = addr;
	data.mac = mac;
	data.family = AF_INET;

	return __nl_neigh(&data, log);
}

int nl_neigh6(struct in6_addr *addr, unsigned char *mac, struct log *log)
{
	struct cb_data data = {};

	data.addr6 = addr;
	data.mac = mac;
	data.family = AF_INET6;

	return __nl_neigh(&data, log);
}

static void __nl_info_free(struct nl_info *info)
{
	struct nl_addr *na, *next;

	for (na = info->addr; na; na = next) {
		next = na->next;
		free(na);
	}

	free(info);
}

struct nl_info *nl_info_free(struct nl_info *ia, bool force)
{
	struct nl_info *next, *head, *p;

	if (!ia)
		return NULL;

	if (force) {
		for (; ia; ia = next) {
			next = ia->next;
			__nl_info_free(ia);
		}
		return NULL;
	}
	else{
		for (head = ia; !head->ref; head = next) {
			next = head->next;
			__nl_info_free(head);
			if (!next)
				return NULL;
		}
		for (p = head; p && p->next; p = p->next) {
			next = p->next;
			if (next->ref)
				continue;

			p->next = next->next;
			__nl_info_free(next);
		}
		return head;
	}
}

static int __bpf_set_link_xdp_fd_replace(int ifindex, int fd, int old_fd,
					 __u32 flags, struct log *log)
{
	int sock, seq = 0, ret;
	struct nlattr *nla, *nla_xdp;
	struct {
		struct nlmsghdr  nh;
		struct ifinfomsg ifinfo;
		char             attrbuf[64];
	} req = {};
	__u32 nl_pid = 0;

	sock = netlink_open(&nl_pid, log);
	if (sock < 0)
		return sock;

	req.nh.nlmsg_type  = RTM_SETLINK;
	req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nh.nlmsg_seq   = ++seq;

	req.ifinfo.ifi_family = AF_UNSPEC;
	req.ifinfo.ifi_index  = ifindex;

	/* started nested attribute for XDP */
	nla = (struct nlattr *)(((char *)&req)
				+ NLMSG_ALIGN(req.nh.nlmsg_len));
	nla->nla_type = NLA_F_NESTED | IFLA_XDP;
	nla->nla_len = NLA_HDRLEN;

	/* add XDP fd */
	nla_xdp = (struct nlattr *)((char *)nla + nla->nla_len);
	nla_xdp->nla_type = IFLA_XDP_FD;
	nla_xdp->nla_len = NLA_HDRLEN + sizeof(int);
	memcpy((char *)nla_xdp + NLA_HDRLEN, &fd, sizeof(fd));
	nla->nla_len += nla_xdp->nla_len;

	/* if user passed in any flags, add those too */
	if (flags) {
		nla_xdp = (struct nlattr *)((char *)nla + nla->nla_len);
		nla_xdp->nla_type = IFLA_XDP_FLAGS;
		nla_xdp->nla_len = NLA_HDRLEN + sizeof(flags);
		memcpy((char *)nla_xdp + NLA_HDRLEN, &flags, sizeof(flags));
		nla->nla_len += nla_xdp->nla_len;
	}

#if XDP_FLAGS_REPLACE
	if (flags & XDP_FLAGS_REPLACE) {
		nla_xdp = (struct nlattr *)((char *)nla + nla->nla_len);
		nla_xdp->nla_type = IFLA_XDP_EXPECTED_FD;
		nla_xdp->nla_len = NLA_HDRLEN + sizeof(old_fd);
		memcpy((char *)nla_xdp + NLA_HDRLEN, &old_fd, sizeof(old_fd));
		nla->nla_len += nla_xdp->nla_len;
	}
#endif

	req.nh.nlmsg_len += NLA_ALIGN(nla->nla_len);

	if (send(sock, &req, req.nh.nlmsg_len, 0) < 0) {
		ret = -errno;
		goto cleanup;
	}
	ret = netlink_recv(sock, nl_pid, seq, NULL, NULL, NULL, log);

cleanup:
	close(sock);
	return ret;
}

int nl_xdp_set(int ifindex, int fd, __u32 flags, struct log *log)
{
	int ret;

	ret = __bpf_set_link_xdp_fd_replace(ifindex, fd, 0, flags, log);
	if (fd < 0 || ret)
		return ret;

	return 0;
}

void nl_xdp_off(int ifindex, struct log *log)
{
	__bpf_set_link_xdp_fd_replace(ifindex, -1, 0, 0, log);
}
