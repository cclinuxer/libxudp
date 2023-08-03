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

#include "xudp_types.h"

#define bin_kern(name) \
	extern uint8_t _binary_kern_ ##name## _o_start[]; \
	extern uint8_t _binary_kern_ ##name## _o_end[]; \
	extern uint8_t _binary_kern_ ##name## _o_size;

bin_kern(rr);
bin_kern(hash);
bin_kern(dict);

#define bin_start(name) ((_binary_kern_ ##name## _o_start))
#define bin_size(name) (_binary_kern_ ##name## _o_end - bin_start(name))

int kern_init(struct bpf *b, enum xudp_flow_dispatch_type type,
	      void *bin, int size, const char *path)
{
	switch(type) {
	case XUDP_FLOW_DISPATCH_TYPE_HASH:
		bin = bin_start(hash);
		size = bin_size(hash);
		break;

	case XUDP_FLOW_DISPATCH_TYPE_RR:
		bin = bin_start(rr);
		size = bin_size(rr);
		break;

	case XUDP_FLOW_DISPATCH_TYPE_DICT:
		bin = bin_start(dict);
		size = bin_size(dict);
		break;

	case XUDP_FLOW_DISPATCH_TYPE_CUSTOM:
		if (path && !bin) {
			int fd;
			struct stat buf;

			fd = open(path, O_RDONLY);
			if (fd < 0)
				return -1;

			if (fstat(fd, &buf) < 0) {
				close(fd);
				return -1;
			}

			size = buf.st_size;
			bin = malloc(size);
			if (!bin) {
				close(fd);
				return -1;
			}

			if (size != read(fd, bin, size)) {
				free(bin);
				close(fd);
				return -1;
			}
			close(fd);
		}
		break;
	}

	return bpf_load(b, "xdp_sock", BPF_PROG_TYPE_XDP, bin, size);
}

#if TEST
#include <time.h>
#include <stdio.h>
int bpf_set_link_xdp_fd(int ifindex, int fd, __u32 flags);
int main(void)
{
	struct bpf B = {}, *b;

	b = &B;
	int ret;

	ret = kern_init(b);
	if (ret) {
		logerr("bpf load ret: %d\n", ret);
	}
	ret = bpf_set_link_xdp_fd(13, ret, 0);
	logdebug("link set xdp ret: %d\n", ret);
	sleep(3600);

}
#endif
