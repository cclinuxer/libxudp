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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "bpf.h"
#include "kern.h"
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <arpa/inet.h>

enum {
	opt_null,
	opt_update,
	opt_read,
	opt_list,
};

static u32 current_ns_map[100];
static bool show_map_of_other_ns;

static int show_stats_ts(int fd)
{
	struct tm *tm_info;
	int key, err;
	time_t value;
	char buf[512];

	key = XUDP_MAP_TS;

	err = bpf_map_lookup_elem(fd, &key, &value);
	if (err)
		return -1;

	tm_info = localtime(&value);
	strftime(buf, sizeof(buf), "xudp xdp bind: %Y-%m-%d %H:%M:%S", tm_info);

	printf("# %s\n\n", buf);
	return 0;
}

static int init_ns()
{
	u32 nsid, value;
	struct bpf_map_info info;
	int id = 0, key, i, fd, err, num;

	key = XUDP_MAP_NS;

	nsid = net_namespace_id();

	while (true) {
		id = bpf_next_id(id);
		if (id < 0)
			break;

		if (bpf_get_info(id, &info))
			return -1;

		if (0 == strcmp(MAP_STATS, info.name)) {
			fd = bpf_get_fd(id);
			if (fd < 0)
				return -1;

			err = bpf_map_lookup_elem(fd, &key, &value);
			if (err)
				continue;

			if (value != nsid)
				continue;

			goto found;
		}
	}
	return -1;
found:
	show_stats_ts(fd);

	key = XUDP_MAP_NUM;
	err = bpf_map_lookup_elem(fd, &key, &num);
	if (err)
		return -1;

	key = XUDP_MAP_ID;

	for (i = 0; i < num; ++i, ++key) {
		err = bpf_map_lookup_elem(fd, &key, &value);
		if (err)
			return -1;

		current_ns_map[i] = value;
	}

	current_ns_map[i] = info.id;

	return 0;
}

static bool is_current_ns_map(u32 id)
{
	u32 i;

	for (i = 0; current_ns_map[i]; ++i) {
		if (current_ns_map[i] == id)
			return true;
	}

	return false;
}

static inline int bpf_lookup_map_ns(char *name)
{
	struct bpf_map_info info;
	int id = 0;

	while (true) {
		id = bpf_next_id(id);
		if (id < 0)
			break;

		if (!is_current_ns_map(id))
			continue;

		if (bpf_get_info(id, &info))
			return -1;

		if (strcmp(name, info.name))
			continue;

		return id;

	}

	return -1;
}

static inline int map_list(int argc, char *argv[])
{
	struct bpf_map_info info;
	int id = 0;

	if (argc >= 3 && 0 == strcmp(argv[2], "-a"))
		show_map_of_other_ns = true;

	while (true) {
		id = bpf_next_id(id);
		if (id < 0) {
			if (errno != ENOENT)
				printf("find map err. %s\n", strerror(errno));

			break;
		}

		if (!show_map_of_other_ns && !is_current_ns_map(id))
			continue;

		if (bpf_get_info(id, &info))
			return -1;

		printf("map %-15s type: %2u id: %5u vsize: %5u max_entries: %8u flags: %3u ifindex: %3u dev: %3llu ino: %3llu\n",
		       info.name, info.type, info.id, info.value_size, info.max_entries,
		       info.map_flags, info.ifindex, info.netns_dev, info.netns_ino);
	}
	return 0;
}

static int dump_ipport()
{
	struct kern_ipport ipport;
	struct in_addr addr;
	int id, fd, i, err;
	int key = 0;

	id = bpf_lookup_map_ns(MAP_IPPORT);
	if (id == -1) {
		printf("%s. map not found. %s\n", MAP_IPPORT, strerror(errno));
		return 0;
	}

	fd = bpf_get_fd(id);
	if (fd < 0)
		return 0;

	err = bpf_map_lookup_elem(fd, &key, &ipport);
	if (err) {
		printf("err lookup\n");
		return 0;
	}

	for (i = 0; i < ipport.ipport_n; ++i) {
		addr.s_addr = ipport.addr[i];
		printf("%s:%u\n", inet_ntoa(addr), ntohs(ipport.port[i]));
	}

	char buf[100];
	for (i = 0; i < ipport.ipport6_n; ++i) {
		inet_ntop(AF_INET6, &ipport.addr6[i], buf, sizeof(buf));
		printf("%s:%u\n", buf, ntohs(ipport.port6[i]));
	}

	return 0;
}

static void exit_help(void)
{
	printf("xudp-map list [-a]\n");
	printf("xudp-map ipport -- dump ipport\n");
	printf("xudp-map <update/read> <map name> <key> [value]\n");
	exit(0);
}

int main(int argc, char *argv[])
{
	int id, fd, key, value, opt, err;
	char *map_name;

	opt = opt_null;
	key = 0;

	if (init_ns()) {
		printf("fail init ns. try sudo.\n");
		return -1;
	}

	if (argc <= 1 || 0 == strcmp(argv[1], "list"))
		return map_list(argc, argv);

	if (0 == strcmp(argv[1], "help"))
		exit_help();

	if (0 == strcmp(argv[1], "-h"))
		exit_help();

	if (0 == strcmp(argv[1], "ipport"))
		return dump_ipport();

	if (0 == strcmp(argv[1], "update")) {
		if (argc !=  5)
			exit_help();

		opt = opt_update;
		value = atoi(argv[4]);
	}

	if (0 == strcmp(argv[1], "read")) {
		if (argc !=  4)
			exit_help();

		opt = opt_read;
	}

	if (opt == opt_null)
		exit_help();

	map_name = argv[2];
	key = atoi(argv[3]);

	id = bpf_lookup_map_ns(map_name);
	if (id == -1) {
		printf("%s. map not found. %s\n", map_name, strerror(errno));
		return -1;
	}

	fd = bpf_get_fd(id);
	if (fd < 0)
		return -1;

	if (opt == opt_update)
		return bpf_map_update_elem(fd, &key, &value, 0);

	err = bpf_map_lookup_elem(fd, &key, &value);
	if (!err)
		printf("%d\n", value);

	return err;
}
