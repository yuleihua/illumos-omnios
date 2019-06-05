/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2015, 2018, 2019, Meisaka Yukara
 * Copyright 2018, 2019 Prominic.NET Inc. All Rights reserved.
 * Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
 */

/*
 * DLPI interface module
 */

#include "yuka.h"
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <inttypes.h>
#include <strings.h>

#include <sys/conf.h>
#include <sys/ethernet.h>

#include "dlpi.h"
#include "cdp.h"

/* option flags */
extern int verbose;
extern boolean_t vlanflag;
extern boolean_t promisc;

void
DlpiOpenSession(yuka_session_t *ses)
{
	dlpi_handle_t hdl;
	dlpi_info_t dli;
	int e;

	if ((e = dlpi_open(ses->device, &hdl, DLPI_RAW)) != DLPI_SUCCESS)
		Error("cannot open device %s, %s", ses->device,
		    dlpi_strerror(e));

	if (verbose > 0)
		printf("Opened device %s\n", ses->device);

	if (vlanflag) {
		if (verbose > 0)
			printf("Binding to VLAN-tagged traffic.\n");
		if ((e = dlpi_bind(hdl, ETHERTYPE_VLAN, NULL)) != DLPI_SUCCESS)
			Error("SAP bind, %s", dlpi_strerror(e));
	} else {
		if ((e = dlpi_bind(hdl, DLPI_ANY_SAP, NULL))
		    != DLPI_SUCCESS)
			Error("SAP bind, %s", dlpi_strerror(e));
	}
	/*
	 * Currently changing the promiscous state for a VLAN SAP handle
	 * does not work; revisit later.
	 */
	if (!vlanflag) {
		if (promisc) {
			if ((e = dlpi_promiscon(hdl,
			    vlanflag ? DL_PROMISC_SAP : DL_PROMISC_MULTI))
			    != DLPI_SUCCESS)
				Error("SAP promiscon, %s", dlpi_strerror(e));
		} else {
			if ((e = dlpi_enabmulti(hdl, &MAC_CDP,
			    ETHERADDRL)) != DLPI_SUCCESS)
				Error("SAP enabmulti, %s", dlpi_strerror(e));
		}
	}

	if ((e = dlpi_info(hdl, &dli, 0)) != DLPI_SUCCESS)
		Error("cannot retrieve DLPI info, %s", dlpi_strerror(e));

	ses->hdl = hdl;
	ses->fd = dlpi_fd(hdl);
	ses->mtu = dli.di_max_sdu;
	ses->buf = malloc(ses->mtu);
	if (ses->buf == NULL)
		Error("Could not allocate %d bytes for buffer.", ses->mtu);
	bcopy(dli.di_physaddr, ses->physaddr, sizeof (ses->physaddr));

	if (verbose > 0) {
		nbytes_hex(" ... phys=", dli.di_physaddr,
		    dli.di_physaddrlen, "\n");
		printf(" ... sap=%#x\n", dli.di_sap);
		printf(" ... mtu=%u\n", dli.di_max_sdu);
	}
}

void
DlpiCloseSession(yuka_session_t *ses)
{
	(void) dlpi_unbind(ses->hdl);
	(void) dlpi_close(ses->hdl);
	ses->hdl = NULL;
	ses->fd = -1;
	free(ses->buf);
	ses->buf = NULL;
}

void
DlpiSnd(yuka_session_t *ses, data_link_addr_t dst, uchar_t *buf, int len)
{
	(void) dlpi_send(ses->hdl, &dst, sizeof (dst), buf, len, NULL);
	ses->frames_out++;
	ses->bytes_out += len;
}

boolean_t
DlpiRcv(yuka_session_t *ses, yuka_packet_t *eth,
    dlsap_addr_t src, dlsap_addr_t dst)
{
	eth->framelen = eth->bufsize;
	if (dlpi_recv(ses->hdl, NULL, NULL,
	    eth->buf, &eth->framelen, 0, NULL) != DLPI_SUCCESS)
		return (B_FALSE);

	ses->frames_in++;
	ses->bytes_in += eth->framelen;

	bcopy(eth->buf + 6, src, 6);
	bcopy(eth->buf, dst, 6);

	return (B_TRUE);
}

char *
get_ether_type(int ty)
{
	switch (ty) {
	case 0:			return "ALL";
	case ETHERTYPE_PUP:	return "ETHERTYPE_PUP";
	case ETHERTYPE_IP:	return "ETHERTYPE_IP";
	case ETHERTYPE_ARP:	return "ETHERTYPE_ARP";
	case ETHERTYPE_REVARP:	return "ETHERTYPE_REVARP";
	case ETHERTYPE_IPV6:	return "ETHERTYPE_IPV6";
	case ETHERTYPE_VLAN:	return "ETHERTYPE_VLAN";
	case 0x88cc:		return "ETHERTYPE_LLDP";
	default:	return "???";
	}
}
