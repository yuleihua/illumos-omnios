/*
 * Copyright (c) 2013  Chris Torek <torek @ torek net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 *
 * Copyright 2015 Pluribus Networks Inc.
 * Copyright 2019 Joyent, Inc.
 * Copyright 2020 Oxide Computer Company
 */

#ifndef	_VIONA_IMPL_H
#define	_VIONA_IMPL_H

#include <sys/ddi.h>
#include <sys/list.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/strsun.h>
#include <sys/sysmacros.h>
#include <sys/uio.h>

#include <sys/mac_client.h>
#include <sys/mac_provider.h>
#include <sys/mac_client_priv.h>
#include <sys/neti.h>
#include <inet/ip.h>
#include <inet/tcp.h>

#include <sys/vmm_drv.h>
#include <sys/viona_io.h>

struct viona_link;
typedef struct viona_link viona_link_t;
struct viona_desb;
typedef struct viona_desb viona_desb_t;
struct viona_net;
typedef struct viona_neti viona_neti_t;

enum viona_ring_state {
	VRS_RESET	= 0x0,	/* just allocated or reset */
	VRS_SETUP	= 0x1,	/* addrs setup and starting worker thread */
	VRS_INIT	= 0x2,	/* worker thread started & waiting to run */
	VRS_RUN		= 0x3,	/* running work routine */
	VRS_STOP	= 0x4,	/* worker is exiting */
};
enum viona_ring_state_flags {
	VRSF_REQ_START	= 0x1,	/* start running from INIT state */
	VRSF_REQ_STOP	= 0x2,	/* stop running, clean up, goto RESET state */
	VRSF_RENEW	= 0x4,	/* ring renewing lease */
};

typedef struct viona_vring {
	viona_link_t	*vr_link;

	kmutex_t	vr_lock;
	kcondvar_t	vr_cv;
	uint16_t	vr_state;
	uint16_t	vr_state_flags;
	uint_t		vr_xfer_outstanding;
	kthread_t	*vr_worker_thread;
	vmm_lease_t	*vr_lease;

	/* ring-sized resources for TX activity */
	viona_desb_t	*vr_txdesb;
	struct iovec	*vr_txiov;

	uint_t		vr_intr_enabled;
	uint64_t	vr_msi_addr;
	uint64_t	vr_msi_msg;

	/* Internal ring-related state */
	kmutex_t	vr_a_mutex;	/* sync consumers of 'avail' */
	kmutex_t	vr_u_mutex;	/* sync consumers of 'used' */
	uint64_t	vr_pa;
	uint16_t	vr_size;
	uint16_t	vr_mask;	/* cached from vr_size */
	uint16_t	vr_cur_aidx;	/* trails behind 'avail_idx' */

	/* Host-context pointers to the queue */
	volatile struct virtio_desc	*vr_descr;

	volatile uint16_t		*vr_avail_flags;
	volatile uint16_t		*vr_avail_idx;
	volatile uint16_t		*vr_avail_ring;
	volatile uint16_t		*vr_avail_used_event;

	volatile uint16_t		*vr_used_flags;
	volatile uint16_t		*vr_used_idx;
	volatile struct virtio_used	*vr_used_ring;
	volatile uint16_t		*vr_used_avail_event;

	/* Per-ring error condition statistics */
	struct viona_ring_stats {
		uint64_t	rs_ndesc_too_high;
		uint64_t	rs_bad_idx;
		uint64_t	rs_indir_bad_len;
		uint64_t	rs_indir_bad_nest;
		uint64_t	rs_indir_bad_next;
		uint64_t	rs_no_space;
		uint64_t	rs_too_many_desc;
		uint64_t	rs_desc_bad_len;

		uint64_t	rs_bad_ring_addr;

		uint64_t	rs_fail_hcksum;
		uint64_t	rs_fail_hcksum6;
		uint64_t	rs_fail_hcksum_proto;

		uint64_t	rs_bad_rx_frame;
		uint64_t	rs_rx_merge_overrun;
		uint64_t	rs_rx_merge_underrun;
		uint64_t	rs_rx_pad_short;
		uint64_t	rs_rx_mcast_check;
		uint64_t	rs_too_short;
		uint64_t	rs_tx_absent;

		uint64_t	rs_rx_hookdrop;
		uint64_t	rs_tx_hookdrop;
	} vr_stats;
} viona_vring_t;

struct viona_link {
	vmm_hold_t		*l_vm_hold;
	boolean_t		l_destroyed;

	viona_vring_t		l_vrings[VIONA_VQ_MAX];

	uint32_t		l_features;
	uint32_t		l_features_hw;
	uint32_t		l_cap_csum;

	uint16_t		l_notify_ioport;
	void			*l_notify_cookie;

	datalink_id_t		l_linkid;
	mac_handle_t		l_mh;
	mac_client_handle_t	l_mch;
	mac_promisc_handle_t	l_mph;

	pollhead_t		l_pollhead;

	viona_neti_t		*l_neti;
};

typedef struct viona_nethook {
	net_handle_t		vnh_neti;
	hook_family_t		vnh_family;
	hook_event_t		vnh_event_in;
	hook_event_t		vnh_event_out;
	hook_event_token_t	vnh_token_in;
	hook_event_token_t	vnh_token_out;
	boolean_t		vnh_hooked;
} viona_nethook_t;

struct viona_neti {
	list_node_t		vni_node;

	netid_t			vni_netid;
	zoneid_t		vni_zid;

	viona_nethook_t		vni_nethook;

	kmutex_t		vni_lock;	/* Protects remaining members */
	kcondvar_t		vni_ref_change; /* Protected by vni_lock */
	uint_t			vni_ref;	/* Protected by vni_lock */
	list_t			vni_dev_list;	/* Protected by vni_lock */
};

typedef struct used_elem {
	uint16_t	id;
	uint32_t	len;
} used_elem_t;

typedef struct viona_soft_state {
	kmutex_t		ss_lock;
	viona_link_t		*ss_link;
	list_node_t		ss_node;
} viona_soft_state_t;

#pragma pack(1)
struct virtio_desc {
	uint64_t	vd_addr;
	uint32_t	vd_len;
	uint16_t	vd_flags;
	uint16_t	vd_next;
};

struct virtio_used {
	uint32_t	vu_idx;
	uint32_t	vu_tlen;
};

struct virtio_net_mrgrxhdr {
	uint8_t		vrh_flags;
	uint8_t		vrh_gso_type;
	uint16_t	vrh_hdr_len;
	uint16_t	vrh_gso_size;
	uint16_t	vrh_csum_start;
	uint16_t	vrh_csum_offset;
	uint16_t	vrh_bufs;
};

struct virtio_net_hdr {
	uint8_t		vrh_flags;
	uint8_t		vrh_gso_type;
	uint16_t	vrh_hdr_len;
	uint16_t	vrh_gso_size;
	uint16_t	vrh_csum_start;
	uint16_t	vrh_csum_offset;
};
#pragma pack()

#define	VRING_NEED_BAIL(ring, proc)					\
		(((ring)->vr_state_flags & VRSF_REQ_STOP) != 0 ||	\
		((proc)->p_flag & SEXITING) != 0)


#define	VNETHOOK_INTERESTED_IN(neti) \
	(neti)->vni_nethook.vnh_event_in.he_interested
#define	VNETHOOK_INTERESTED_OUT(neti) \
	(neti)->vni_nethook.vnh_event_out.he_interested


#define	VIONA_PROBE(name)	DTRACE_PROBE(viona__##name)
#define	VIONA_PROBE1(name, arg1, arg2)	\
	DTRACE_PROBE1(viona__##name, arg1, arg2)
#define	VIONA_PROBE2(name, arg1, arg2, arg3, arg4)	\
	DTRACE_PROBE2(viona__##name, arg1, arg2, arg3, arg4)
#define	VIONA_PROBE3(name, arg1, arg2, arg3, arg4, arg5, arg6)	\
	DTRACE_PROBE3(viona__##name, arg1, arg2, arg3, arg4, arg5, arg6)
#define	VIONA_PROBE5(name, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, \
	arg9, arg10) \
	DTRACE_PROBE5(viona__##name, arg1, arg2, arg3, arg4, arg5, arg6, arg7, \
	arg8, arg9, arg10)
#define	VIONA_PROBE_BAD_RING_ADDR(r, a)		\
	VIONA_PROBE2(bad_ring_addr, viona_vring_t *, r, void *, (void *)(a))

#define	VIONA_RING_STAT_INCR(r, name)	\
	(((r)->vr_stats.rs_ ## name)++)


#define	VIONA_MAX_HDRS_LEN	(sizeof (struct ether_vlan_header) + \
	IP_MAX_HDR_LENGTH + TCP_MAX_HDR_LENGTH)

#define	VRING_AVAIL_F_NO_INTERRUPT	1
#define	VRING_USED_F_NO_NOTIFY		1

#define	VRING_DESC_F_NEXT	(1 << 0)
#define	VRING_DESC_F_WRITE	(1 << 1)
#define	VRING_DESC_F_INDIRECT	(1 << 2)

#define	VIRTIO_NET_HDR_F_NEEDS_CSUM	(1 << 0)
#define	VIRTIO_NET_HDR_F_DATA_VALID	(1 << 1)

#define	VIRTIO_NET_HDR_GSO_NONE		0
#define	VIRTIO_NET_HDR_GSO_TCPV4	1

#define	VIRTIO_NET_F_CSUM		(1 << 0)
#define	VIRTIO_NET_F_GUEST_CSUM		(1 << 1)
#define	VIRTIO_NET_F_MAC		(1 << 5) /* host supplies MAC */
#define	VIRTIO_NET_F_GUEST_TSO4		(1 << 7) /* guest can accept TSO */
#define	VIRTIO_NET_F_HOST_TSO4		(1 << 11) /* host can accept TSO */
#define	VIRTIO_NET_F_MRG_RXBUF		(1 << 15) /* host can merge RX bufs */
#define	VIRTIO_NET_F_STATUS		(1 << 16) /* cfg status field present */
#define	VIRTIO_F_RING_NOTIFY_ON_EMPTY	(1 << 24)
#define	VIRTIO_F_RING_INDIRECT_DESC	(1 << 28)
#define	VIRTIO_F_RING_EVENT_IDX		(1 << 29)


void viona_ring_alloc(viona_link_t *, viona_vring_t *);
void viona_ring_free(viona_vring_t *);
int viona_ring_reset(viona_vring_t *, boolean_t);
int viona_ring_init(viona_link_t *, uint16_t, uint16_t, uint64_t);
boolean_t viona_ring_lease_renew(viona_vring_t *);
int vq_popchain(viona_vring_t *, struct iovec *, uint_t, uint16_t *);
void vq_pushchain(viona_vring_t *, uint32_t, uint16_t);
void vq_pushchain_many(viona_vring_t *, uint_t, used_elem_t *);
void viona_intr_ring(viona_vring_t *ring);

void viona_rx_init(void);
void viona_rx_fini(void);
int viona_rx_set(viona_link_t *);
void viona_rx_clear(viona_link_t *);
void viona_worker_rx(viona_vring_t *, viona_link_t *);

extern kmutex_t viona_force_copy_lock;
void viona_worker_tx(viona_vring_t *, viona_link_t *);
void viona_tx_ring_alloc(viona_vring_t *, const uint16_t);
void viona_tx_ring_free(viona_vring_t *, const uint16_t);

void viona_neti_attach(void);
void viona_neti_detach(void);
viona_neti_t *viona_neti_lookup_by_zid(zoneid_t);
void viona_neti_rele(viona_neti_t *);
int viona_hook(viona_link_t *, viona_vring_t *, mblk_t **, boolean_t);

#endif	/* _VIONA_IMPL_H */
