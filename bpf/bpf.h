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

#ifndef  __BPF_H__
#define __BPF_H__

#include <string.h>
#include <linux/bpf.h>
#include <libelf.h>
#include <gelf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define _GNU_SOURCE	   /* See feature_test_macros(7) */
#include <unistd.h>
#include <sys/syscall.h>	  /* For SYS_xxx definitions */
#include "log.h"

#include "bpf_helpers.h"

/*
 * When building perf, unistd.h is overridden. __NR_bpf is
 * required to be defined explicitly.
 */
#ifndef __NR_bpf
# if defined(__i386__)
#  define __NR_bpf 357
# elif defined(__x86_64__)
#  define __NR_bpf 321
# elif defined(__aarch64__)
#  define __NR_bpf 280
# elif defined(__sparc__)
#  define __NR_bpf 349
# elif defined(__s390__)
#  define __NR_bpf 351
# elif defined(__arc__)
#  define __NR_bpf 280
# else
#  error __NR_bpf not defined. libbpf does not support your arch.
# endif
#endif


#define ptr_to_u64(x)  ((uint64_t)x)

#ifndef SOL_XDP
#define SOL_XDP 283
#endif

#ifndef AF_XDP
#define AF_XDP 44
#endif

#ifndef PF_XDP
#define PF_XDP AF_XDP
#endif

struct str{
	char *p;
	int size;
};

struct map;

struct rel_sec{
	GElf_Shdr sh;
	Elf_Data *data;
};

struct bpf{
	int maps_idx;


	int (*map_filter)(struct bpf_map_def *, void *);
	void *map_filter_data;

	struct map *maps;
	int maps_n;

	Elf *elf;
	GElf_Ehdr ehdr;

	struct str ins;

	char *target_proc;

	struct str license;
	struct str version;

	enum bpf_prog_type type;

	Elf_Data *symbols;
	int symbols_shndx;
	int prog_fd;

	size_t strtabidx;

	Elf_Scn *rel_scn;

	struct log *log;
};

static inline int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr,
			  unsigned int size)
{
	return syscall(__NR_bpf, cmd, attr, size);
}
int bpf_load(struct bpf *b, char *proc,
	     enum bpf_prog_type type, char *elf, int size);
int bpf_map_get(struct bpf *b, const char *name);
void bpf_close(struct bpf *b);

static inline int bpf_map_update_elem(int fd, const void *key, const void *value,
			       __u64 flags)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_fd = fd;
	attr.key = ptr_to_u64(key);
	attr.value = ptr_to_u64(value);
	attr.flags = flags;

	return sys_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

static inline int bpf_map_lookup_elem(int fd, const void *key, void *value)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_fd = fd;
	attr.key = ptr_to_u64(key);
	attr.value = ptr_to_u64(value);

	return sys_bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

static inline int bpf_map_delete_elem(int fd, const void *key)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_fd = fd;
	attr.key = ptr_to_u64(key);

	return sys_bpf(BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
}

#ifdef BPF_XDP
static inline int bpf_xdp_link_create(int prog_fd, int ifindex)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));

	attr.link_create.prog_fd = prog_fd;
	attr.link_create.target_ifindex = ifindex;
	attr.link_create.attach_type = BPF_XDP;

	return sys_bpf(BPF_LINK_CREATE, &attr, sizeof(attr));
}
#endif

static inline int bpf_next_id(int id)
{
	union bpf_attr attr;
	int err;

	memset(&attr, 0, sizeof(attr));

	attr.start_id = id;

	err = sys_bpf(BPF_MAP_GET_NEXT_ID, &attr, sizeof(attr));
	if (err)
		return err;

	return attr.next_id;
}

static inline int bpf_get_fd(int id)
{
	union bpf_attr attr;
	int err;

	memset(&attr, 0, sizeof(attr));

	attr.map_id = id;

	err = sys_bpf(BPF_MAP_GET_FD_BY_ID, &attr, sizeof(attr));
	if (err)
		return err;

	return attr.map_fd;
}

static inline int bpf_get_info_by_fd(int fd, struct bpf_map_info *info)
{
	union bpf_attr attr;
	int err;

	memset(&attr, 0, sizeof(attr));
	attr.info.bpf_fd = fd;
	attr.info.info = ptr_to_u64(info);
	attr.info.info_len = sizeof(*info);

	err = sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr));

	return err;
}

static inline int bpf_get_info(int id, struct bpf_map_info *info)
{
	union bpf_attr attr;
	int fd, err;

	fd = bpf_get_fd(id);
	if (fd < 0)
		return fd;

	memset(&attr, 0, sizeof(attr));
	attr.info.bpf_fd = fd;
	attr.info.info = ptr_to_u64(info);
	attr.info.info_len = sizeof(*info);

	err = sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr));

	close(fd);

	return err;
}

static inline int bpf_lookup_map(char *name)
{
	struct bpf_map_info info;
	int id = 0;

	while (true) {
		id = bpf_next_id(id);
		if (id < 0)
			break;

		if (bpf_get_info(id, &info))
			return -1;

		if (strcmp(name, info.name))
			continue;

		return id;

	}

	return -1;
}

static inline unsigned int net_namespace_id(void)
{
	struct stat buf;

	stat("/proc/self/ns/net", &buf);

	return buf.st_ino;
}

int bpf_map_get_idx(struct bpf *b, unsigned int i, int *fd);
#endif


