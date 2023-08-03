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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>

#include "dump.h"
#include "common.h"


static struct config {
	void *xudp_map;
	struct dump *dump;

	int loop;

	char *outfile;
	int outfd;
	int shm_size;
	u64 capture;
} dump_conf;

typedef u32 guint32;
typedef u16 guint16;
typedef int gint32;

typedef struct pcap_hdr_s {
        guint32 magic_number;   /* magic number */
        guint16 version_major;  /* major version number */
        guint16 version_minor;  /* minor version number */
        gint32  thiszone;       /* GMT to local correction */
        guint32 sigfigs;        /* accuracy of timestamps */
        guint32 snaplen;        /* max length of captured packets, in octets */
        guint32 network;        /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
        guint32 ts_sec;         /* timestamp seconds */
        guint32 ts_usec;        /* timestamp microseconds */
        guint32 incl_len;       /* number of octets of packet saved in file */
        guint32 orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

enum {
	en_line_end,
	en_key_before,
	en_key,
	en_shmid_before,
	en_shmid,
};

static void scan_shm(void (*callback)(int shmid))
{
	int state, shmid = 0, n, i;
	char buf[1024];
	int fd;
	char c;

	state = en_line_end;

	fd = open("/proc/sysvipc/shm", O_RDONLY);

	while (true) {
		n = read(fd, buf, sizeof(buf));
		if (n <= 0)
			break;

		for (i = 0; i < n; ++i) {
			c = buf[i];

			switch(state) {
			case en_line_end:
				if (c == '\n')
					state = en_key_before;
				break;

			case en_key_before:
				if (c == ' ' || c == '\t')
					continue;

				state = en_key;
				break;

			case en_key:
				if (c >= '0' && c <= '9')
					continue;

				state = en_shmid_before;
				break;

			case en_shmid_before:
				if (c == ' ' || c == '\t')
					continue;

				state = en_shmid;
				shmid = c - '0';
				break;

			case en_shmid:
				if (c >= '0' && c <= '9') {
					shmid = shmid * 10 + c - '0';
					continue;
				}

				callback(shmid);
				state = en_line_end;
				break;
			}
		}
	}
	close(fd);
}

static void shmid_handler(int shmid)
{
	void *p;

	p = shmat(shmid, NULL, 0);
	if (p == (void *)-1)
		return;

	if (0 == strncmp(p, XUDP_SHM_MAGIC, sizeof(XUDP_SHM_MAGIC) - 1)) {
		if (dump_conf.xudp_map) {
			shmdt(p);
			shmdt(dump_conf.xudp_map);
			fprintf(stderr, "multi xudp instance\n");
			exit(-1);
		}
		dump_conf.xudp_map = p;
	} else {
		shmdt(p);
		return;
	}

}

static void print_help_exit(void)
{
	fprintf(stderr,
	       "xudp-dump  [option]\n"
	       "--size      cache size. default 2M\n"
	       "-o          outfile. -: stdout\n"
	      );
	exit(0);
}

static void parse_argv(int argc, char **argv)
{
	int i;
	char *k, *v;

	dump_conf.shm_size = 2 * 1024 * 1024;
	dump_conf.loop = 1;

	for (i = 1; i < argc; ++i) {
		k = argv[i];

		if (0 == strcmp(k, "-h")) {
			print_help_exit();
		}

		v = argv[++i];

		if (0 == strcmp(k, "--size")) {
			dump_conf.shm_size = atoi(v);
			continue;
		}

		if (0 == strcmp(k, "-o")) {
			dump_conf.outfile = v;
			continue;
		}

		fprintf(stderr, "invalid option: %s\n", k);
		exit(-1);
	}
}

static void int_exit(int sig)
{
	(void)sig;
	dump_conf.loop = 0;
}

static int save_packet(struct dump_ring *r, struct dump_header *pkt, u32 pos)
{
	pcaprec_hdr_t hdr;
	u32 left;
	int n;

	hdr.ts_sec = pkt->tv_sec;
	hdr.ts_usec = pkt->tv_usec;
	hdr.incl_len = pkt->len;
	hdr.orig_len = pkt->len;

	n = write(dump_conf.outfd, &hdr, sizeof(hdr));

	left = r->size - pos;

	if (left >= pkt->len) {
		n += write(dump_conf.outfd, r->pkt + pos, pkt->len);
		return n;
	}

	n += write(dump_conf.outfd, r->pkt + pos, left);
	n += write(dump_conf.outfd, r->pkt, pkt->len - left);
	return n;
}

static void fetch_packet(struct dump_ring *r)
{
	struct dump_header pkt;
	u32 pos, left;

	pos = r->cons % r->size;
	left = r->size - pos;

	if (left >= sizeof(pkt)) {
		memcpy(&pkt, r->pkt + pos, sizeof(pkt));
		pos = pos + sizeof(pkt);
	} else {
		memcpy(&pkt, r->pkt + pos, left);
		memcpy(((void *)&pkt) + left, r->pkt, sizeof(pkt) - left);
		pos = sizeof(pkt) - left;
	}

	save_packet(r, &pkt, pos);

	u_smp_wmb();

	++dump_conf.capture;

	r->cons += pkt.len + sizeof(struct dump_header);
}

static int consume(struct dump_ring *r)
{
	pcap_hdr_t hdr;
	int n;

	hdr.magic_number  = 0xa1b2c3d4;
	hdr.version_major = 2;
	hdr.version_minor = 4;
	hdr.thiszone      = 0;
	hdr.sigfigs       = 0;
	hdr.snaplen       = 65535;
	hdr.network       = 1;

	n = write(dump_conf.outfd, &hdr, sizeof(hdr));

	while (dump_conf.loop) {
		if (r->cons < r->prod) {
			fetch_packet(r);
			continue;
		}

		usleep(10);
	}

	return n;
}

static struct dump_ring *alloc_ring(int size)
{
	struct dump_ring *r;
	int shmid;
	void *p;

	shmid = shmget(IPC_PRIVATE, size + sizeof(struct dump_ring), 0);
	if (-1 == shmid) {
		fprintf(stderr, "alloc ring shmget. %s.\n", strerror(errno));
		return NULL;
	}

	p = shmat(shmid, NULL, 0);

	/* set the shm auto release */
	if (shmctl(shmid, IPC_RMID, NULL)) {
		fprintf(stderr, "set shmid %d IPC_RMID fail. %s.\n",
		       shmid, strerror(errno));
	}

	if (p == (void *)-1) {
		fprintf(stderr, "shmat fail. %s.\n", strerror(errno));
		return NULL;
	}

	r = (struct dump_ring *)p;

	r->shmid = shmid;
	r->size = size;

	return r;
}

static struct dump_ring *get_ring()
{
	struct dump_ring *r;

	dump_conf.dump = dump_conf.xudp_map + XUDP_SHM_OFFSET;
	if (dump_conf.dump->prepare) {
		r = ((void *)dump_conf.dump) + dump_conf.dump->prepare;
		return r;
	}

	r = alloc_ring(dump_conf.shm_size);
	return r;
}

static int xudp_dump_active(struct dump_ring *r)
{
	pthread_spin_init(&r->lock, PTHREAD_PROCESS_SHARED);

	dump_conf.dump->shmid = r->shmid;

	r->prod = 0;
	r->cons = 0;
	r->drop = 0;

	u_smp_wmb();

	dump_conf.dump->active = XUDP_DUMP_ACTIVE;

	return 0;
}

int main(int argc, char *argv[])
{
	struct dump_ring *r;

	parse_argv(argc, argv);

	if (!dump_conf.outfile)
		print_help_exit();

	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);

	scan_shm(shmid_handler);

	if (!dump_conf.xudp_map) {
		fprintf(stderr, "not found xudp instance\n");
		return -1;
	}

	if (*dump_conf.outfile == '-')
		dump_conf.outfd = 1;
	else
		dump_conf.outfd = open(dump_conf.outfile, O_WRONLY | O_CREAT, S_IRUSR | S_IRGRP);

	r = get_ring();
	if (!r)
		return -1;

	xudp_dump_active(r);

	consume(r);

	dump_conf.dump->active = XUDP_DUMP_NOACTIVE;

	fprintf(stderr, "xudp dump drop: %lld\n", r->drop);
	fprintf(stderr, "xudp dump capture: %lld\n", dump_conf.capture);

	shmdt(dump_conf.xudp_map);
	shmdt(r);

	return 0;
}
