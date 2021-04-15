/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2011 NetApp, Inc.
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
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
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
 * Copyright 2013 Pluribus Networks Inc.
 * Copyright 2018 Joyent, Inc.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#ifndef WITHOUT_CAPSICUM
#include <sys/capsicum.h>
#endif
#include <sys/linker_set.h>
#include <sys/select.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#ifdef __FreeBSD__
#ifndef NETMAP_WITH_LIBS
#define NETMAP_WITH_LIBS
#endif
#include <net/netmap_user.h>
#endif

#ifndef WITHOUT_CAPSICUM
#include <capsicum_helpers.h>
#endif
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <assert.h>
#include <md5.h>
#include <pthread.h>
#include <pthread_np.h>
#include <sysexits.h>
#ifndef __FreeBSD__
#include <poll.h>
#include <libdlpi.h>
#endif

#include "bhyverun.h"
#include "debug.h"
#include "pci_emul.h"
#ifdef __FreeBSD__
#include "mevent.h"
#endif
#include "virtio.h"
#include "net_utils.h"

#define VTNET_RINGSZ	1024

#define VTNET_MAXSEGS	256

/*
 * Host capabilities.  Note that we only offer a few of these.
 */
#define	VIRTIO_NET_F_CSUM	(1 <<  0) /* host handles partial cksum */
#define	VIRTIO_NET_F_GUEST_CSUM	(1 <<  1) /* guest handles partial cksum */
#define	VIRTIO_NET_F_MAC	(1 <<  5) /* host supplies MAC */
#define	VIRTIO_NET_F_GSO_DEPREC	(1 <<  6) /* deprecated: host handles GSO */
#define	VIRTIO_NET_F_GUEST_TSO4	(1 <<  7) /* guest can rcv TSOv4 */
#define	VIRTIO_NET_F_GUEST_TSO6	(1 <<  8) /* guest can rcv TSOv6 */
#define	VIRTIO_NET_F_GUEST_ECN	(1 <<  9) /* guest can rcv TSO with ECN */
#define	VIRTIO_NET_F_GUEST_UFO	(1 << 10) /* guest can rcv UFO */
#define	VIRTIO_NET_F_HOST_TSO4	(1 << 11) /* host can rcv TSOv4 */
#define	VIRTIO_NET_F_HOST_TSO6	(1 << 12) /* host can rcv TSOv6 */
#define	VIRTIO_NET_F_HOST_ECN	(1 << 13) /* host can rcv TSO with ECN */
#define	VIRTIO_NET_F_HOST_UFO	(1 << 14) /* host can rcv UFO */
#define	VIRTIO_NET_F_MRG_RXBUF	(1 << 15) /* host can merge RX buffers */
#define	VIRTIO_NET_F_STATUS	(1 << 16) /* config status field available */
#define	VIRTIO_NET_F_CTRL_VQ	(1 << 17) /* control channel available */
#define	VIRTIO_NET_F_CTRL_RX	(1 << 18) /* control channel RX mode support */
#define	VIRTIO_NET_F_CTRL_VLAN	(1 << 19) /* control channel VLAN filtering */
#define	VIRTIO_NET_F_GUEST_ANNOUNCE \
				(1 << 21) /* guest can send gratuitous pkts */

#define VTNET_S_HOSTCAPS      \
  ( VIRTIO_NET_F_MAC | VIRTIO_NET_F_MRG_RXBUF | VIRTIO_NET_F_STATUS | \
    VIRTIO_F_NOTIFY_ON_EMPTY | VIRTIO_RING_F_INDIRECT_DESC)

/*
 * PCI config-space "registers"
 */
struct virtio_net_config {
	uint8_t  mac[6];
	uint16_t status;
	uint16_t max_virtqueue_pairs;
	uint16_t mtu;
} __packed;

/*
 * Queue definitions.
 */
#define VTNET_RXQ	0
#define VTNET_TXQ	1
#define VTNET_CTLQ	2	/* NB: not yet supported */

#define VTNET_MAXQ	3

/*
 * Fixed network header size
 */
struct virtio_net_rxhdr {
	uint8_t		vrh_flags;
	uint8_t		vrh_gso_type;
	uint16_t	vrh_hdr_len;
	uint16_t	vrh_gso_size;
	uint16_t	vrh_csum_start;
	uint16_t	vrh_csum_offset;
	uint16_t	vrh_bufs;
} __packed;

/*
 * Debug printf
 */
static int pci_vtnet_debug;
#define DPRINTF(params) if (pci_vtnet_debug) PRINTLN params
#define WPRINTF(params) PRINTLN params

/*
 * Per-device softc
 */
struct pci_vtnet_softc {
	struct virtio_softc vsc_vs;
	struct vqueue_info vsc_queues[VTNET_MAXQ - 1];
	pthread_mutex_t vsc_mtx;
	struct mevent	*vsc_mevp;

#ifdef	__FreeBSD
	int		vsc_tapfd;
#else
	dlpi_handle_t	vsc_dhp;
	int		vsc_dlpifd;
#endif
	struct nm_desc	*vsc_nmd;

	int		vsc_rx_ready;
	bool		features_negotiated;	/* protected by rx_mtx */
	int		resetting;	/* protected by tx_mtx */

	uint64_t	vsc_features;	/* negotiated features */

	struct virtio_net_config vsc_config;
	struct virtio_consts vsc_consts;

	pthread_mutex_t	rx_mtx;
	int		rx_vhdrlen;
	int		rx_merge;	/* merged rx bufs in use */

	pthread_t 	tx_tid;
	pthread_mutex_t	tx_mtx;
	pthread_cond_t	tx_cond;
	int		tx_in_progress;

	void (*pci_vtnet_rx)(struct pci_vtnet_softc *sc);
	void (*pci_vtnet_tx)(struct pci_vtnet_softc *sc, struct iovec *iov,
			     int iovcnt, int len);
};

static void pci_vtnet_reset(void *);
/* static void pci_vtnet_notify(void *, struct vqueue_info *); */
static int pci_vtnet_cfgread(void *, int, int, uint32_t *);
static int pci_vtnet_cfgwrite(void *, int, int, uint32_t);
static void pci_vtnet_neg_features(void *, uint64_t);

static struct virtio_consts vtnet_vi_consts = {
	"vtnet",		/* our name */
	VTNET_MAXQ - 1,		/* we currently support 2 virtqueues */
	sizeof(struct virtio_net_config), /* config reg size */
	pci_vtnet_reset,	/* reset */
	NULL,			/* device-wide qnotify -- not used */
	pci_vtnet_cfgread,	/* read PCI config */
	pci_vtnet_cfgwrite,	/* write PCI config */
	pci_vtnet_neg_features,	/* apply negotiated features */
	VTNET_S_HOSTCAPS,	/* our capabilities */
};

static void
pci_vtnet_reset(void *vsc)
{
	struct pci_vtnet_softc *sc = vsc;

	DPRINTF(("vtnet: device reset requested !"));

	/* Acquire the RX lock to block RX processing. */
	pthread_mutex_lock(&sc->rx_mtx);

	sc->features_negotiated = false;

	/* Set sc->resetting and give a chance to the TX thread to stop. */
	pthread_mutex_lock(&sc->tx_mtx);
	sc->resetting = 1;
	while (sc->tx_in_progress) {
		pthread_mutex_unlock(&sc->tx_mtx);
		usleep(10000);
		pthread_mutex_lock(&sc->tx_mtx);
	}

	sc->vsc_rx_ready = 0;
	sc->rx_merge = 1;
	sc->rx_vhdrlen = sizeof(struct virtio_net_rxhdr);

	/*
	 * Now reset rings, MSI-X vectors, and negotiated capabilities.
	 * Do that with the TX lock held, since we need to reset
	 * sc->resetting.
	 */
	vi_reset_dev(&sc->vsc_vs);

	sc->resetting = 0;
	pthread_mutex_unlock(&sc->tx_mtx);
	pthread_mutex_unlock(&sc->rx_mtx);
}

/*
 * Called to send a buffer chain out to the tap device
 */
#ifdef __FreeBSD__
static void
pci_vtnet_tap_tx(struct pci_vtnet_softc *sc, struct iovec *iov, int iovcnt,
		 int len)
{
	static char pad[60]; /* all zero bytes */

	if (sc->vsc_tapfd == -1)
		return;

	/*
	 * If the length is < 60, pad out to that and add the
	 * extra zero'd segment to the iov. It is guaranteed that
	 * there is always an extra iov available by the caller.
	 */
	if (len < 60) {
		iov[iovcnt].iov_base = pad;
		iov[iovcnt].iov_len = 60 - len;
		iovcnt++;
	}
	(void) writev(sc->vsc_tapfd, iov, iovcnt);
}
#else
static void
pci_vtnet_tap_tx(struct pci_vtnet_softc *sc, struct iovec *iov, int iovcnt,
		 int len)
{
	int i;

	for (i = 0; i < iovcnt; i++) {
		(void) dlpi_send(sc->vsc_dhp, NULL, 0,
		    iov[i].iov_base, iov[i].iov_len, NULL);
	}
}
#endif /* __FreeBSD__ */

#ifdef __FreeBSD__
/*
 *  Called when there is read activity on the tap file descriptor.
 * Each buffer posted by the guest is assumed to be able to contain
 * an entire ethernet frame + rx header.
 *  MP note: the dummybuf is only used for discarding frames, so there
 * is no need for it to be per-vtnet or locked.
 */
static uint8_t dummybuf[2048];
#endif /* __FreeBSD__ */

static __inline struct iovec *
rx_iov_trim(struct iovec *iov, int *niov, int tlen)
{
	struct iovec *riov;

	/* XXX short-cut: assume first segment is >= tlen */
	assert(iov[0].iov_len >= tlen);

	iov[0].iov_len -= tlen;
	if (iov[0].iov_len == 0) {
		assert(*niov > 1);
		*niov -= 1;
		riov = &iov[1];
	} else {
		iov[0].iov_base = (void *)((uintptr_t)iov[0].iov_base + tlen);
		riov = &iov[0];
	}

	return (riov);
}

static void
pci_vtnet_tap_rx(struct pci_vtnet_softc *sc)
{
	struct iovec iov[VTNET_MAXSEGS], *riov;
	struct vqueue_info *vq;
	void *vrx;
	int n;
#ifdef	__FreeBSD__
	int len;
#else
	size_t len;
	int ret;
#endif
	uint16_t idx;

	/*
	 * Should never be called without a valid tap fd
	 */
#ifdef	__FreeBSD__
	assert(sc->vsc_tapfd != -1);
#else
	assert(sc->vsc_dlpifd != -1);
#endif

	/* Features must be negotiated */
	if (!sc->features_negotiated) {
		return;
	}

	/*
	 * But, will be called when the rx ring hasn't yet
	 * been set up.
	 */
	if (!sc->vsc_rx_ready) {
#ifdef	__FreeBSD__
		/*
		 * Drop the packet and try later.
		 */
		(void) read(sc->vsc_tapfd, dummybuf, sizeof(dummybuf));
#endif
		return;
	}

	/*
	 * Check for available rx buffers
	 */
	vq = &sc->vsc_queues[VTNET_RXQ];
	if (!vq_has_descs(vq)) {
		/*
		 * Drop the packet and try later.  Interrupt on
		 * empty, if that's negotiated.
		 */
#ifdef	__FreeBSD__
		(void) read(sc->vsc_tapfd, dummybuf, sizeof(dummybuf));
#endif
		vq_endchains(vq, 1);
		return;
	}

	do {
		/*
		 * Get descriptor chain
		 */
		n = vq_getchain(vq, &idx, iov, VTNET_MAXSEGS, NULL);
		assert(n >= 1 && n <= VTNET_MAXSEGS);

		/*
		 * Get a pointer to the rx header, and use the
		 * data immediately following it for the packet buffer.
		 */
		vrx = iov[0].iov_base;
		riov = rx_iov_trim(iov, &n, sc->rx_vhdrlen);
#ifdef	__FreeBSD__
		len = readv(sc->vsc_tapfd, riov, n);
#else
		len = riov[0].iov_len;
		ret = dlpi_recv(sc->vsc_dhp, NULL, NULL,
		    (uint8_t *)riov[0].iov_base, &len, 0, NULL);
		if (ret != DLPI_SUCCESS) {
			errno = EWOULDBLOCK;
			len = 0;
		}
#endif
		if (len <= 0 && errno == EWOULDBLOCK) {
			/*
			 * No more packets, but still some avail ring
			 * entries.  Interrupt if needed/appropriate.
			 */
			vq_retchains(vq, 1);
			vq_endchains(vq, 0);
			return;
		}

		/*
		 * The only valid field in the rx packet header is the
		 * number of buffers if merged rx bufs were negotiated.
		 */
		memset(vrx, 0, sc->rx_vhdrlen);

		if (sc->rx_merge) {
			struct virtio_net_rxhdr *vrxh;

			vrxh = vrx;
			vrxh->vrh_bufs = 1;
		}

		/*
		 * Release this chain and handle more chains.
		 */
		vq_relchain(vq, idx, len + sc->rx_vhdrlen);
	} while (vq_has_descs(vq));

	/* Interrupt if needed, including for NOTIFY_ON_EMPTY. */
	vq_endchains(vq, 1);
}

#ifdef __FreeBSD__
static __inline int
pci_vtnet_netmap_writev(struct nm_desc *nmd, struct iovec *iov, int iovcnt)
{
	int r, i;
	int len = 0;

	for (r = nmd->cur_tx_ring; ; ) {
		struct netmap_ring *ring = NETMAP_TXRING(nmd->nifp, r);
		uint32_t cur, idx;
		char *buf;

		if (nm_ring_empty(ring)) {
			r++;
			if (r > nmd->last_tx_ring)
				r = nmd->first_tx_ring;
			if (r == nmd->cur_tx_ring)
				break;
			continue;
		}
		cur = ring->cur;
		idx = ring->slot[cur].buf_idx;
		buf = NETMAP_BUF(ring, idx);

		for (i = 0; i < iovcnt; i++) {
			if (len + iov[i].iov_len > 2048)
				break;
			memcpy(&buf[len], iov[i].iov_base, iov[i].iov_len);
			len += iov[i].iov_len;
		}
		ring->slot[cur].len = len;
		ring->head = ring->cur = nm_ring_next(ring, cur);
		nmd->cur_tx_ring = r;
		ioctl(nmd->fd, NIOCTXSYNC, NULL);
		break;
	}

	return (len);
}

static __inline int
pci_vtnet_netmap_readv(struct nm_desc *nmd, struct iovec *iov, int iovcnt)
{
	int len = 0;
	int i = 0;
	int r;

	for (r = nmd->cur_rx_ring; ; ) {
		struct netmap_ring *ring = NETMAP_RXRING(nmd->nifp, r);
		uint32_t cur, idx;
		char *buf;
		size_t left;

		if (nm_ring_empty(ring)) {
			r++;
			if (r > nmd->last_rx_ring)
				r = nmd->first_rx_ring;
			if (r == nmd->cur_rx_ring)
				break;
			continue;
		}
		cur = ring->cur;
		idx = ring->slot[cur].buf_idx;
		buf = NETMAP_BUF(ring, idx);
		left = ring->slot[cur].len;

		for (i = 0; i < iovcnt && left > 0; i++) {
			if (iov[i].iov_len > left)
				iov[i].iov_len = left;
			memcpy(iov[i].iov_base, &buf[len], iov[i].iov_len);
			len += iov[i].iov_len;
			left -= iov[i].iov_len;
		}
		ring->head = ring->cur = nm_ring_next(ring, cur);
		nmd->cur_rx_ring = r;
		ioctl(nmd->fd, NIOCRXSYNC, NULL);
		break;
	}
	for (; i < iovcnt; i++)
		iov[i].iov_len = 0;

	return (len);
}

/*
 * Called to send a buffer chain out to the vale port
 */
static void
pci_vtnet_netmap_tx(struct pci_vtnet_softc *sc, struct iovec *iov, int iovcnt,
		    int len)
{
	static char pad[60]; /* all zero bytes */

	if (sc->vsc_nmd == NULL)
		return;

	/*
	 * If the length is < 60, pad out to that and add the
	 * extra zero'd segment to the iov. It is guaranteed that
	 * there is always an extra iov available by the caller.
	 */
	if (len < 60) {
		iov[iovcnt].iov_base = pad;
		iov[iovcnt].iov_len = 60 - len;
		iovcnt++;
	}
	(void) pci_vtnet_netmap_writev(sc->vsc_nmd, iov, iovcnt);
}

static void
pci_vtnet_netmap_rx(struct pci_vtnet_softc *sc)
{
	struct iovec iov[VTNET_MAXSEGS], *riov;
	struct vqueue_info *vq;
	void *vrx;
	int len, n;
	uint16_t idx;

	/*
	 * Should never be called without a valid netmap descriptor
	 */
	assert(sc->vsc_nmd != NULL);

	/* Features must be negotiated */
	if (!sc->features_negotiated) {
		return;
	}

	/*
	 * But, will be called when the rx ring hasn't yet
	 * been set up.
	 */
	if (!sc->vsc_rx_ready) {
		/*
		 * Drop the packet and try later.
		 */
		(void) nm_nextpkt(sc->vsc_nmd, (void *)dummybuf);
		return;
	}

	/*
	 * Check for available rx buffers
	 */
	vq = &sc->vsc_queues[VTNET_RXQ];
	if (!vq_has_descs(vq)) {
		/*
		 * Drop the packet and try later.  Interrupt on
		 * empty, if that's negotiated.
		 */
		(void) nm_nextpkt(sc->vsc_nmd, (void *)dummybuf);
		vq_endchains(vq, 1);
		return;
	}

	do {
		/*
		 * Get descriptor chain.
		 */
		n = vq_getchain(vq, &idx, iov, VTNET_MAXSEGS, NULL);
		assert(n >= 1 && n <= VTNET_MAXSEGS);

		/*
		 * Get a pointer to the rx header, and use the
		 * data immediately following it for the packet buffer.
		 */
		vrx = iov[0].iov_base;
		riov = rx_iov_trim(iov, &n, sc->rx_vhdrlen);

		len = pci_vtnet_netmap_readv(sc->vsc_nmd, riov, n);

		if (len == 0) {
			/*
			 * No more packets, but still some avail ring
			 * entries.  Interrupt if needed/appropriate.
			 */
			vq_retchain(vq);
			vq_endchains(vq, 0);
			return;
		}

		/*
		 * The only valid field in the rx packet header is the
		 * number of buffers if merged rx bufs were negotiated.
		 */
		memset(vrx, 0, sc->rx_vhdrlen);

		if (sc->rx_merge) {
			struct virtio_net_rxhdr *vrxh;

			vrxh = vrx;
			vrxh->vrh_bufs = 1;
		}

		/*
		 * Release this chain and handle more chains.
		 */
		vq_relchain(vq, idx, len + sc->rx_vhdrlen);
	} while (vq_has_descs(vq));

	/* Interrupt if needed, including for NOTIFY_ON_EMPTY. */
	vq_endchains(vq, 1);
}
#endif /* __FreeBSD__ */

#ifdef __FreeBSD__
static void
pci_vtnet_rx_callback(int fd, enum ev_type type, void *param)
{
	struct pci_vtnet_softc *sc = param;

	pthread_mutex_lock(&sc->rx_mtx);
	sc->pci_vtnet_rx(sc);
	pthread_mutex_unlock(&sc->rx_mtx);

}
#else
static void *
pci_vtnet_poll_thread(void *param)
{
	struct pci_vtnet_softc *sc = param;
	pollfd_t pollset;

	pollset.fd = sc->vsc_dlpifd;
	pollset.events = POLLIN | POLLPRI | POLLRDNORM | POLLRDBAND;

	for (;;) {
		if (poll(&pollset, 1, -1) < 0) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "pci_vtnet_poll_thread poll() error %d\n", errno);
			continue;
		}
		pthread_mutex_lock(&sc->vsc_mtx);
		pci_vtnet_tap_rx(sc);
		pthread_mutex_unlock(&sc->vsc_mtx);
	}

	return (NULL);
}
#endif /* __FreeBSD__ */

static void
pci_vtnet_ping_rxq(void *vsc, struct vqueue_info *vq)
{
	struct pci_vtnet_softc *sc = vsc;

	/*
	 * A qnotify means that the rx process can now begin.
	 * Enable RX only if features are negotiated.
	 */
	pthread_mutex_lock(&sc->rx_mtx);
	if (sc->vsc_rx_ready == 0 && sc->features_negotiated) {
		sc->vsc_rx_ready = 1;
		vq_kick_disable(vq);
	}
	pthread_mutex_unlock(&sc->rx_mtx);
}

static void
pci_vtnet_proctx(struct pci_vtnet_softc *sc, struct vqueue_info *vq)
{
	struct iovec iov[VTNET_MAXSEGS + 1];
	int i, n;
	int plen, tlen;
	uint16_t idx;

	/*
	 * Obtain chain of descriptors.  The first one is
	 * really the header descriptor, so we need to sum
	 * up two lengths: packet length and transfer length.
	 */
	n = vq_getchain(vq, &idx, iov, VTNET_MAXSEGS, NULL);
	assert(n >= 1 && n <= VTNET_MAXSEGS);
	plen = 0;
	tlen = iov[0].iov_len;
	for (i = 1; i < n; i++) {
		plen += iov[i].iov_len;
		tlen += iov[i].iov_len;
	}

	DPRINTF(("virtio: packet send, %d bytes, %d segs\n\r", plen, n));
	sc->pci_vtnet_tx(sc, &iov[1], n - 1, plen);

	/* chain is processed, release it and set tlen */
	vq_relchain(vq, idx, tlen);
}

static void
pci_vtnet_ping_txq(void *vsc, struct vqueue_info *vq)
{
	struct pci_vtnet_softc *sc = vsc;

	/*
	 * Any ring entries to process?
	 */
	if (!vq_has_descs(vq))
		return;

	/* Signal the tx thread for processing */
	pthread_mutex_lock(&sc->tx_mtx);
	vq_kick_disable(vq);
	if (sc->tx_in_progress == 0)
		pthread_cond_signal(&sc->tx_cond);
	pthread_mutex_unlock(&sc->tx_mtx);
}

/*
 * Thread which will handle processing of TX desc
 */
static void *
pci_vtnet_tx_thread(void *param)
{
	struct pci_vtnet_softc *sc = param;
	struct vqueue_info *vq;
	int error;

	vq = &sc->vsc_queues[VTNET_TXQ];

	/*
	 * Let us wait till the tx queue pointers get initialised &
	 * first tx signaled
	 */
	pthread_mutex_lock(&sc->tx_mtx);
	error = pthread_cond_wait(&sc->tx_cond, &sc->tx_mtx);
	assert(error == 0);

	for (;;) {
		/* note - tx mutex is locked here */
		while (sc->resetting || !vq_has_descs(vq)) {
			vq_kick_enable(vq);
			if (!sc->resetting && vq_has_descs(vq))
				break;

			sc->tx_in_progress = 0;
			error = pthread_cond_wait(&sc->tx_cond, &sc->tx_mtx);
			assert(error == 0);
		}
		vq_kick_disable(vq);
		sc->tx_in_progress = 1;
		pthread_mutex_unlock(&sc->tx_mtx);

		do {
			/*
			 * Run through entries, placing them into
			 * iovecs and sending when an end-of-packet
			 * is found
			 */
			pci_vtnet_proctx(sc, vq);
		} while (vq_has_descs(vq));

		/*
		 * Generate an interrupt if needed.
		 */
		vq_endchains(vq, 1);

		pthread_mutex_lock(&sc->tx_mtx);
	}
	return (NULL);
}

#ifdef __FreeBSD__
static void
pci_vtnet_ping_ctlq(void *vsc, struct vqueue_info *vq)
{

	DPRINTF(("vtnet: control qnotify!"));
}
#endif /* __FreeBSD__ */

static void
pci_vtnet_tap_setup(struct pci_vtnet_softc *sc, char *devname)
{
	char tbuf[80];
#ifndef WITHOUT_CAPSICUM
	cap_rights_t rights;
#endif
#ifndef	__FreeBSD__
	uchar_t physaddr[DLPI_PHYSADDR_MAX];
	size_t physaddrlen = DLPI_PHYSADDR_MAX;
	int error;
#endif

	strcpy(tbuf, "/dev/");
	strlcat(tbuf, devname, sizeof(tbuf));

	sc->pci_vtnet_rx = pci_vtnet_tap_rx;
	sc->pci_vtnet_tx = pci_vtnet_tap_tx;
#ifdef	__FreeBSD__
	sc->vsc_tapfd = open(tbuf, O_RDWR);
	if (sc->vsc_tapfd == -1) {
		WPRINTF(("open of tap device %s failed\n", tbuf));
		return;
	}

	/*
	 * Set non-blocking and register for read
	 * notifications with the event loop
	 */
	int opt = 1;
	if (ioctl(sc->vsc_tapfd, FIONBIO, &opt) < 0) {
		WPRINTF(("tap device O_NONBLOCK failed\n"));
		close(sc->vsc_tapfd);
		sc->vsc_tapfd = -1;
	}

#ifndef WITHOUT_CAPSICUM
	cap_rights_init(&rights, CAP_EVENT, CAP_READ, CAP_WRITE);
	if (caph_rights_limit(sc->vsc_tapfd, &rights) == -1)
		errx(EX_OSERR, "Unable to apply rights for sandbox");
#endif

	sc->vsc_mevp = mevent_add(sc->vsc_tapfd,
				  EVF_READ,
				  pci_vtnet_rx_callback,
				  sc);
	if (sc->vsc_mevp == NULL) {
		WPRINTF(("Could not register event\n"));
		close(sc->vsc_tapfd);
		sc->vsc_tapfd = -1;
	}
#else
	if (dlpi_open(devname, &sc->vsc_dhp, DLPI_RAW) != DLPI_SUCCESS) {
		WPRINTF(("open of vnic device %s failed\n", devname));
	}

	if (dlpi_get_physaddr(sc->vsc_dhp, DL_CURR_PHYS_ADDR, physaddr,
	    &physaddrlen) != DLPI_SUCCESS) {
		WPRINTF(("read MAC address of vnic device %s failed\n",
		    devname));
	}
	if (physaddrlen != ETHERADDRL) {
		WPRINTF(("bad MAC address len %d on vnic device %s\n",
		    physaddrlen, devname));
	}
	memcpy(sc->vsc_config.mac, physaddr, ETHERADDRL);

	if (dlpi_bind(sc->vsc_dhp, DLPI_ANY_SAP, NULL) != DLPI_SUCCESS) {
		WPRINTF(("bind of vnic device %s failed\n", devname));
	}

	if (dlpi_promiscon(sc->vsc_dhp, DL_PROMISC_PHYS) != DLPI_SUCCESS) {
		WPRINTF(("enable promiscous mode(physical) of vnic device %s "
		    "failed\n", devname));
	}
	if (dlpi_promiscon(sc->vsc_dhp, DL_PROMISC_SAP) != DLPI_SUCCESS) {
		WPRINTF(("enable promiscous mode(SAP) of vnic device %s "
		    "failed\n", devname));
	}

	sc->vsc_dlpifd = dlpi_fd(sc->vsc_dhp);

	if (fcntl(sc->vsc_dlpifd, F_SETFL, O_NONBLOCK) < 0) {
		WPRINTF(("enable O_NONBLOCK of vnic device %s failed\n",
		    devname));
		dlpi_close(sc->vsc_dhp);
		sc->vsc_dlpifd = -1;
	}

	error = pthread_create(NULL, NULL, pci_vtnet_poll_thread, sc);
	assert(error == 0);
#endif
}

#ifdef __FreeBSD__
static void
pci_vtnet_netmap_setup(struct pci_vtnet_softc *sc, char *ifname)
{
	sc->pci_vtnet_rx = pci_vtnet_netmap_rx;
	sc->pci_vtnet_tx = pci_vtnet_netmap_tx;

	sc->vsc_nmd = nm_open(ifname, NULL, 0, 0);
	if (sc->vsc_nmd == NULL) {
		WPRINTF(("open of netmap device %s failed\n", ifname));
		return;
	}

	sc->vsc_mevp = mevent_add(sc->vsc_nmd->fd,
				  EVF_READ,
				  pci_vtnet_rx_callback,
				  sc);
	if (sc->vsc_mevp == NULL) {
		WPRINTF(("Could not register event\n"));
		nm_close(sc->vsc_nmd);
		sc->vsc_nmd = NULL;
	}
}
#endif /* __FreeBSD__ */

static int
pci_vtnet_init(struct vmctx *ctx, struct pci_devinst *pi, char *opts)
{
	struct pci_vtnet_softc *sc;
	char tname[MAXCOMLEN + 1];
#ifdef __FreeBSD__
	int mac_provided;
	int mtu_provided;
	unsigned long mtu = ETHERMTU;
#else
	int use_msix = 1;
#endif

	/*
	 * Allocate data structures for further virtio initializations.
	 * sc also contains a copy of vtnet_vi_consts, since capabilities
	 * change depending on the backend.
	 */
	sc = calloc(1, sizeof(struct pci_vtnet_softc));

	sc->vsc_consts = vtnet_vi_consts;
	pthread_mutex_init(&sc->vsc_mtx, NULL);

	sc->vsc_queues[VTNET_RXQ].vq_qsize = VTNET_RINGSZ;
	sc->vsc_queues[VTNET_RXQ].vq_notify = pci_vtnet_ping_rxq;
	sc->vsc_queues[VTNET_TXQ].vq_qsize = VTNET_RINGSZ;
	sc->vsc_queues[VTNET_TXQ].vq_notify = pci_vtnet_ping_txq;
#ifdef notyet
	sc->vsc_queues[VTNET_CTLQ].vq_qsize = VTNET_RINGSZ;
        sc->vsc_queues[VTNET_CTLQ].vq_notify = pci_vtnet_ping_ctlq;
#endif
 
	/*
	 * Attempt to open the backend device and read the MAC address
	 * if specified.
	 */
#ifdef __FreeBSD__
	mac_provided = 0;
	mtu_provided = 0;
#endif
	if (opts != NULL) {
		char *optscopy;
		char *vtopts;
		int err = 0;

		/* Get the device name. */
		optscopy = vtopts = strdup(opts);
		(void) strsep(&vtopts, ",");

#ifdef __FreeBSD__
		/*
		 * Parse the list of options in the form
		 *     key1=value1,...,keyN=valueN.
		 */
		while (vtopts != NULL) {
			char *value = vtopts;
			char *key;

			key = strsep(&value, "=");
			if (value == NULL)
				break;
			vtopts = value;
			(void) strsep(&vtopts, ",");

			if (strcmp(key, "mac") == 0) {
				err = net_parsemac(value, sc->vsc_config.mac);
				if (err)
					break;
				mac_provided = 1;
			} else if (strcmp(key, "mtu") == 0) {
				err = net_parsemtu(value, &mtu);
				if (err)
					break;

				if (mtu < VTNET_MIN_MTU || mtu > VTNET_MAX_MTU) {
					err = EINVAL;
					errno = EINVAL;
					break;
				}
				mtu_provided = 1;
			}
		}
#endif

#ifndef __FreeBSD__
		/* Use the already strsep(",")-ed optscopy */
		if (strncmp(optscopy, "tap", 3) == 0 ||
		    strncmp(optscopy, "vmnet", 5) == 0)
			pci_vtnet_tap_setup(sc, optscopy);
#endif

		free(optscopy);

		if (err) {
			free(sc);
			return (err);
		}

#ifdef __FreeBSD__
		err = netbe_init(&sc->vsc_be, opts, pci_vtnet_rx_callback,
		          sc);
		if (err) {
			free(sc);
			return (err);
		}

		sc->vsc_consts.vc_hv_caps |= VIRTIO_NET_F_MRG_RXBUF |
		    netbe_get_cap(sc->vsc_be);
#endif

	}

#ifdef __FreeBSD__
	if (!mac_provided) {
		net_genmac(pi, sc->vsc_config.mac);
	}

	sc->vsc_config.mtu = mtu;
	if (mtu_provided) {
		sc->vsc_consts.vc_hv_caps |= VIRTIO_NET_F_MTU;
	}
#endif

	/* 
	 * Since we do not actually support multiqueue,
	 * set the maximum virtqueue pairs to 1. 
	 */
	sc->vsc_config.max_virtqueue_pairs = 1;

	/* initialize config space */
	pci_set_cfgdata16(pi, PCIR_DEVICE, VIRTIO_DEV_NET);
	pci_set_cfgdata16(pi, PCIR_VENDOR, VIRTIO_VENDOR);
	pci_set_cfgdata8(pi, PCIR_CLASS, PCIC_NETWORK);
	pci_set_cfgdata16(pi, PCIR_SUBDEV_0, VIRTIO_TYPE_NET);
	pci_set_cfgdata16(pi, PCIR_SUBVEND_0, VIRTIO_VENDOR);

	/* Link is up if we managed to open tap device or vale port. */
#ifdef	__FreeBSD__
	sc->vsc_config.status = (opts == NULL || sc->vsc_tapfd >= 0 ||
#else
	sc->vsc_config.status = (opts == NULL || sc->vsc_dlpifd >= 0 ||
	    sc->vsc_nmd != NULL);
#endif

	/* use BAR 1 to map MSI-X table and PBA, if we're using MSI-X */
	if (vi_intr_init(&sc->vsc_vs, 1, use_msix))
		return (1);

	/* use BAR 0 to map config regs in IO space */
	vi_set_io_bar(&sc->vsc_vs, 0);

	sc->resetting = 0;

	sc->rx_merge = 1;
	sc->rx_vhdrlen = sizeof(struct virtio_net_rxhdr);
	pthread_mutex_init(&sc->rx_mtx, NULL); 

	/* 
	 * Initialize tx semaphore & spawn TX processing thread.
	 * As of now, only one thread for TX desc processing is
	 * spawned. 
	 */
	sc->tx_in_progress = 0;
	pthread_mutex_init(&sc->tx_mtx, NULL);
	pthread_cond_init(&sc->tx_cond, NULL);
	pthread_create(&sc->tx_tid, NULL, pci_vtnet_tx_thread, (void *)sc);
	snprintf(tname, sizeof(tname), "vtnet-%d:%d tx", pi->pi_slot,
	    pi->pi_func);
	pthread_set_name_np(sc->tx_tid, tname);

	return (0);
}

static int
pci_vtnet_cfgwrite(void *vsc, int offset, int size, uint32_t value)
{
	struct pci_vtnet_softc *sc = vsc;
	void *ptr;

	if (offset < 6) {
		assert(offset + size <= 6);
		/*
		 * The driver is allowed to change the MAC address
		 */
		ptr = &sc->vsc_config.mac[offset];
		memcpy(ptr, &value, size);
	} else {
		/* silently ignore other writes */
		DPRINTF(("vtnet: write to readonly reg %d", offset));
	}

	return (0);
}

static int
pci_vtnet_cfgread(void *vsc, int offset, int size, uint32_t *retval)
{
	struct pci_vtnet_softc *sc = vsc;
	void *ptr;

	ptr = (uint8_t *)&sc->vsc_config + offset;
	memcpy(retval, ptr, size);
	return (0);
}

static void
pci_vtnet_neg_features(void *vsc, uint64_t negotiated_features)
{
	struct pci_vtnet_softc *sc = vsc;

	sc->vsc_features = negotiated_features;

	if (!(sc->vsc_features & VIRTIO_NET_F_MRG_RXBUF)) {
		sc->rx_merge = 0;
		/* non-merge rx header is 2 bytes shorter */
		sc->rx_vhdrlen -= 2;
	}

	pthread_mutex_lock(&sc->rx_mtx);
	sc->features_negotiated = true;
	pthread_mutex_unlock(&sc->rx_mtx);
}

struct pci_devemu pci_de_vnet = {
	.pe_emu = 	"virtio-net",
	.pe_init =	pci_vtnet_init,
	.pe_barwrite =	vi_pci_write,
	.pe_barread =	vi_pci_read
};
PCI_EMUL_SET(pci_de_vnet);
