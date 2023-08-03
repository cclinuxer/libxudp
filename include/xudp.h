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

#ifndef  __XUDP_H__
#define __XUDP_H__

#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <linux/types.h>

typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;
typedef __u8 u8;

struct xudp_addr {
	struct sockaddr_storage to;
	struct sockaddr_storage from;
	struct ethhdr eth;
};

enum xudp_rxtx_flag {
	/* rx */
	XUDP_FLAG_COPY     = 1 << 0,

	/* tx */
	XUDP_FLAG_SRC_ETH   = 1 << 1,
	XUDP_FLAG_SRC_IP    = 1 << 2,
	XUDP_FLAG_SRC_PORT  = 1 << 3,

	XUDP_FLAG_DST_ETH   = 1 << 4,

	XUDP_FLAG_FRAME_MIX = 1 << 5,
};


#define XUDP_CAP (CAP_TO_MASK(CAP_NET_RAW) | CAP_TO_MASK(CAP_SYS_ADMIN) | \
                 CAP_TO_MASK(CAP_IPC_OWNER))

#define xudp_def_msg(hdr, n)                               \
	xudp_msg __msg[n];                                 \
	xudp_msghdr __hdr, *hdr;                           \
	hdr = &__hdr;                                      \
    	hdr->msg = __msg;                                  \
    	hdr->total = n;                                    \
	hdr->used  = 0;

#define xudp_alloc_msg(n) ({                               \
	xudp_msghdr *hdr;                                  \
	hdr = malloc(sizeof(*hdr) + sizeof(xudp_msg) * n); \
	hdr->msg = (xudp_msg*)(hdr + 1);                   \
	hdr->total = n;                                    \
	hdr->used = 0;                                     \
	hdr;})

enum{
	/* bpf err code */
	XUDP_ERR_BPF_LOAD = 1000,
	XUDP_ERR_BPF_FD,
	XUDP_ERR_BPF_MAP,
	XUDP_ERR_BPF_MAP_GET,
	XUDP_ERR_BPF_MAP_LOOKUP,
	XUDP_ERR_BPF_MAP_DELETE,
	XUDP_ERR_BPF_MAP_UPDATE,
	XUDP_ERR_BPF_UMEM_INIT,
	XUDP_ERR_BPF_CQ_CACHE_INIT,
	XUDP_ERR_BPF_TX_BIND,
	XUDP_ERR_BPF_TX_BIND_NOZC,
	XUDP_ERR_BPF_TX_BIND_BUSY,

	XUDP_ERR_UMEM_INIT = 1100,
	XUDP_ERR_UMEM_INIT_ALLOC,
	XUDP_ERR_UMEM_INIT_ALIGN,
	XUDP_ERR_UMEM_INIT_ALLOCS,
	XUDP_ERR_UMEM_INIT_REG,
	XUDP_ERR_UMEM_INIT_F,
	XUDP_ERR_UMEM_INIT_C,
	XUDP_ERR_UMEM_INIT_FR,
	XUDP_ERR_UMEM_INIT_CR,
	XUDP_ERR_UMEM_INIT_ENQ,

	/* channel err code */
	XUDP_ERR_SET_XSK = 2000,
	XUDP_ERR_LINK_IF,
	XUDP_ERR_NOBIND,
	XUDP_ERR_CQ_NOSPACE,
	XUDP_ERR_FQ_NOSPACE,
	XUDP_ERR_TX_NOSPACE,
	XUDP_ERR_RX_NOSPACE,
	XUDP_ERR_PACKET_TOO_BIG,
	XUDP_ERR_CHANNEL_ID_OVERFLOW,
	XUDP_ERR_CHANNEL_COMMIT,
	XUDP_ERR_COMMIT_AGAIN,

	/* nic err code */
	XUDP_ERR_NIC_INDEX_OVERFLOW = 3000,
	XUDP_ERR_NIC_CHANNEL_OVERFLOW,
	XUDP_ERR_NIC_CHANNEL,
	XUDP_ERR_NIC_MAC,
	XUDP_ERR_NIC_MORE_ADDR,
	XUDP_ERR_NIC_NO_ADDR,
	XUDP_ERR_NIC_NL_LINK,
	XUDP_ERR_NIC_SLAVES_OVERFLOW,
	XUDP_ERR_NIC_SLAVES_NOTFOUND,
	XUDP_ERR_NIC_SLAVES_EMPTY,

	/* route&arp err code */
	XUDP_ERR_ROUTE_NONE = 4000,
	XUDP_ERR_ROUTE_INVALID,
	XUDP_ERR_ROUTE_NIC_NOMACTH,
	XUDP_ERR_ROUTE_NOTFOUND,
	XUDP_ERR_ROUTE_ARP_MAX,

	XUDP_ERR_ARP_NOTFOUND = 4500,


	/* cluster err code*/
	XUDP_ERR_CLUSTER_CREATE = 6000,
	XUDP_ERR_CLUSTER_JUSTONE,
	XUDP_ERR_CLUSTER_OVERFLOW,
	XUDP_ERR_CLUSTER_GROUPNUM,
	XUDP_ERR_CLUSTER_ACTIVE,

	/* dispatch err code*/
	XUDP_ERR_DISPATCH_OVERFLOW = 7000,

	XUDP_ERR_FRAME_MIX_NOGROUP = 8000,

};

enum xudp_flow_dispatch_type {
	XUDP_FLOW_DISPATCH_TYPE_HASH = 0,
	XUDP_FLOW_DISPATCH_TYPE_DICT,
	XUDP_FLOW_DISPATCH_TYPE_RR,
	XUDP_FLOW_DISPATCH_TYPE_CUSTOM,
};

struct xudp_msg {
	u64 recycle1;
	u64 recycle2;

	struct sockaddr_storage  local_addr;
	struct sockaddr_storage  peer_addr;

	u32 size;
	u32 headroom;
	u64 usec; // ptk recv from nic
	char *p;
	char *frame;
	int flags;
};

struct xudp_msghdr {
	struct xudp_msg *msg;
	struct xudp_group *group;
	u32 total;
	u32 used;
	int err;
};

enum {
	XUDP_LOG_ERR = 1,
	XUDP_LOG_WARN,
	XUDP_LOG_INFO,
	XUDP_LOG_DEBUG,
};

typedef int (*xudp_log_cb)(char *log, int size, void *data);


struct xudp_conf {
	/* headroom, save headroom before packet */
	u32 headroom;

	/* frame size, every udp packet will use one frame, the
	 * frame must > the packet size */
	u32 frame_size;

	/* frame num for recv of one net nic channel */
	u32 rcvnum;

	/* frame num for send of one net nic channel */
	u32 sndnum;

	/* the number of xsk contained in the group is the
	 * number of network card channels
	 */
	u32 group_num;

	/* log */
	u32          log_level;
	void        *log_data;
	xudp_log_cb  log_cb;

	/* format the log with time */
	bool log_with_time;

	/* bind to the same addr by kernel udp */
	bool bindudp;

	/* stop arp, that can work for aliyun */
	bool noarp;

	/* force xsk use copy mode*/
	bool force_copy;

	/* no force xsk use zerocopy mode.
	 * we like zerocopy, so zerocopy is default value. if you do not like
	 * it, set this true. */
	bool no_force_zerocopy;

	/* xdp is for recv, so noxudp is for just send process. */
	bool noxdp;

	/* force load xdp, when there is xdp bound to the network card, it
	 * will try to unbind the old xdp first
	 */
	bool force_xdp;

	/* use the pid as the map key of dict, then the size
	 * of the map is the pid_max */
	bool map_dict_n_max_pid;

	/* dict map size */
	u32 map_dict_n;

	/* cluster slot num, max 256. default value 10. */
	u32 xskmap_capability;

	/* auto commit when how many pkt in the tx queue */
	u32 tx_batch_num;

	/* xdp flow dispatch type */
	enum xudp_flow_dispatch_type flow_dispatch;

	/* user custom xdp bpf.
	 * flow_dispatch must be XUDP_FLOW_DISPATCH_TYPE_CUSTOM */
	void *xdp_custom;

	/* the size of user custom xdp bpf
	 * flow_dispatch must be XUDP_FLOW_DISPATCH_TYPE_CUSTOM */
	int xdp_custom_size;

	/* the path of custom xdp file
	 * flow_dispatch must be XUDP_FLOW_DISPATCH_TYPE_CUSTOM */
	const char *xdp_custom_path;

	bool isolate_group;

	/* set PR_SET_KEEPCAPS for isolate group with other uid */
	bool keep_cap;

	bool unaligned;

	/* alloc dump memory when xudp init. Otherwise shmat shm memory. */
	u32 dump_prepare_size;
};

typedef struct xudp        xudp;
typedef struct xudp_conf   xudp_conf;
typedef struct xudp_group  xudp_group;
typedef struct xdpsock     xudp_channel;
typedef struct xudp_msghdr xudp_msghdr;
typedef struct xudp_msg    xudp_msg;

/************************** xudp api  ****************************************/
xudp *xudp_init(struct xudp_conf *conf, u32 conf_size);

/*
 * unbind xsk, xsk mmap. used by worker not use xudp more.
 * not close/free global xudp.
 * */
void xudp_unbind(xudp *x);

/* 1. xdp will been unbind
 * 2. xudp will been relase
 * 3. xsk will been closed
 * */
void xudp_free(xudp *x);
/* clear xdp for all net device */
int xudp_xdp_clear();

/* bind to local addr
 *
 * x: xudp
 * a: addr pointer
 * num: specify the number of addr
 *
 * Here, based on the specified address, the local network card is selected for
 * binding
 * */
int xudp_bind(xudp *x, struct sockaddr *a, socklen_t addrlen, int num);

/************************** bpf api      **************************************/
/* this should called after xudp_bind. */
int xudp_bpf_map_update(xudp *x, const char *name, int *key, void *value);

/************************** group/channel api  ********************************/
struct xudp_group *xudp_group_new(xudp *x, int gid);
struct xudp_group *xudp_group_get(xudp *x, int gid);
void xudp_group_free(struct xudp_group *g);

xudp_channel *xudp_group_channel_first(xudp_group *g);
xudp_channel *xudp_group_channel_next(xudp_channel *ch);

#define xudp_group_channel_foreach(ch, group)		\
	for (ch = xudp_group_channel_first(group); ch;	\
	     ch = xudp_group_channel_next(ch))

int xudp_channel_get_fd(xudp_channel *ch);
int xudp_channel_get_groupid(xudp_channel *ch);
int xudp_channel_is_tx(xudp_channel *ch);

xudp_channel *xudp_txch_get(xudp *x, int gid);
void xudp_txch_put(xudp_channel *ch);
/************************** recv api  *****************************************/
int xudp_recv_channel(xudp_channel *ch, xudp_msghdr *msghdr, int flags);

int xudp_recycle(xudp_msghdr *msghdr);

/************************** send api  *****************************************/
/*
 * The parameter "to" can actually be struct xudp_addr, so that the user can
 * pass in the local address or mac address at the same time. This depends on
 * the flag for judgment:
 *
 * The following flags will make xudp use the from or eth information in struct
 * xudp_addr.
 *
 * 	XUDP_FLAG_SRC_ETH
 * 	XUDP_FLAG_SRC_IP
 * 	XUDP_FLAG_SRC_PORT
 * 	XUDP_FLAG_DST_ETH
 */
int xudp_send_channel(xudp_channel *ch, char *buf, u32 size,
		      struct sockaddr *to, int flags);

int xudp_commit_channel(xudp_channel *ch);

/* Apply for memory in advance, write udp payload data, and then call
 * xudp_frame_send to send udp data. So as to achieve zero copy.
 *
 * If tx is shared by multiple groups, it is inadvertent to get too many frames
 * at once. In theory, holding a small number of frames for a long time does not
 * affect xudp.
 *
 * Note: The frame must be released before the group is released. If the worker
 * hangs abnormally in the master/worker model, or exits without calling
 * xudp_frame_free, it may cause the requested frame to be leaked.
 *
 * This just works with the ONE nic mode.
 *
 * hdr: alloc by user.
 *    in:
 *      hdr->total: record the msg num
 *      hdr->msg: pointer msg array
 *
 *    out:
 *      hdr->used record the number of the msg been filled.
 *      hdr->err is the err code
 *
 *	msg->p point to the buffer
 *	msg->size is the buffer size
 *
 * retun value:
 *   <=0 err.
 *   >   frame num alloc
 */
int xudp_frame_alloc(struct xudp_group *g, xudp_msghdr *hdr, int flags);

/*
 * hdr: alloc by user.
 *    in:
 *      hdr->total: record the msg num to send
 *      hdr->msg: pointer msg array
 *
 *	msg->p point to the buffer
 *	msg->size is the payload size
 *
 *      flag:
 *          XUDP_FRAME_FLAGS_MIX that mean may some msg->p is not alloced
 *          from xudp_frame_alloc(). Then the hdr->group _MUST_ been seted.
 *
 *    out:
 *      hdr->err is the err code
 *
 * retun value:
 *   <=0 err.
 *   >   frame num sent
 */
int xudp_frame_send(xudp_group *g, xudp_msghdr *hdr, struct sockaddr *to, int flags);

/* hdr: alloc by user.
 *    in:
 *      hdr->total: record the msg num to free
 *
 *	msg->p point to the buffer
 */
void xudp_frame_free(xudp_group *g, xudp_msghdr *hdr);

/************************** cluster api  **************************************/

int xudp_dict_set_group_key(struct xudp_group *g, int key);

#endif


