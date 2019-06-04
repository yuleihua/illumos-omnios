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

#include <stdio.h>
#include <strings.h>
#include <sys/types.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/utsname.h>
#include <pthread.h>

#include "yuka.h"
#include "cdp.h"

static pthread_mutex_t cdp_mutex = PTHREAD_MUTEX_INITIALIZER;

static neighbour_t *neighbour_table = NULL;

const data_link_addr_t MAC_CDP = { {0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc} };
const uint8_t LLC_CDP[8] = { 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20, 0x00 };

extern int verbose;

static void
cdp_add_x(yuka_packet_t *lfr, unsigned short ty, const uint8_t *x,
    unsigned short xlen)
{
	int inp = lfr->insertpos;
	if (xlen + 4 + inp > lfr->bufsize)
		return;
	add_short(lfr, ty);
	add_short(lfr, 4 + xlen);
	add_string(lfr, (uint8_t *)x, xlen);
}

unsigned short
verify_checksum(const uint16_t *ptr, int length, int oddtype)
{
	uint32_t sum = 0;
	const uint16_t *w = ptr;
	uint16_t v;
	int nleft = length - 4;

	sum = ntohs(*w);
	w += 2;
	while (nleft > 1) {
		sum += ntohs(*w++);
		nleft -= 2;
	}
	if (nleft == 1) {
		v = (*(const uint8_t *)w) & 0xff;
		sum += v;
		/*
		 * don't know the exact checksum algorithm
		 * but it seems like this may be needed in some instances
		 */
		if (oddtype)
			sum += 0xfeff;
	}
	while (sum & 0xffff0000) {
		sum = (sum >> 16) + (sum & 0xFFFF);
	}
	return (~sum);
}

void
cdp_add_hostid(yuka_packet_t *lfr, const char *devid)
{
	cdp_add_x(lfr, 1, (uint8_t *)devid, strlen(devid));
}

// ip 1.2.3.4 == 0x01020304
void
cdp_add_ipaddress(yuka_packet_t *lfr, in_addr_t ip)
{
	// Type NLPID(1), Len 1, Proto: IP( 0xCC )
	uint8_t stg[3] = { 1, 1, 0xcc };
	if (lfr->insertpos + 17 > lfr->bufsize)
		return;
	add_short(lfr, 2);
	add_short(lfr, 17);
	add_long(lfr, 1); // Address Count
	add_string(lfr, stg, 3); // Address Info
	add_short(lfr, 4); // Address Len - 4 Bytes
	add_ip(lfr, ip); // IP
}

void
cdp_add_portid(yuka_packet_t *lfr, const char *portid)
{
	cdp_add_x(lfr, 3, (uint8_t *)portid, strlen(portid));
}

void
cdp_add_capabilities(yuka_packet_t *lfr, uint32_t flags)
{
	if (lfr->insertpos + 8 > lfr->bufsize)
		return;
	add_short(lfr, 4);
	add_short(lfr, 8);
	add_long(lfr, flags);
}

static void
cdp_add_softver(yuka_packet_t *lfr, const char *verstr)
{
	cdp_add_x(lfr, 5, (uint8_t *)verstr, strlen(verstr));
}

static void
cdp_add_platform(yuka_packet_t *lfr, const char *plfstr)
{
	cdp_add_x(lfr, 6, (uint8_t *)plfstr, strlen(plfstr));
}

int
get_cdp_string(const uint8_t *cdata, int slen, char *dest, int dlen)
{
	int p = slen;

	if (slen >= dlen)
		p = dlen - 1;

	bcopy(cdata, dest, p);
	dest[p] = '\0';

	return (p);
}

static int
yuka_compare_host_entry(const neighbour_t *he_a, const neighbour_t *he_b)
{
	return (he_a->localportid == he_b->localportid &&
	    strcmp(he_a->portid, he_b->portid) == 0 &&
	    strcmp(he_a->devid, he_b->devid) == 0);
}

void
yuka_cdp_walk(void (*walkcb)(neighbour_t *, void *), void *extra,
    boolean_t dead)
{
	neighbour_t *n;

	(void) pthread_mutex_lock(&cdp_mutex);
	for (n = neighbour_table; n != NULL; n = n->next)
		if (dead || n->holdtime > 0)
			walkcb(n, extra);
	(void) pthread_mutex_unlock(&cdp_mutex);
}

void
yuka_cdp_reap(int threshold)
{
	neighbour_t **n, *e;

	(void) pthread_mutex_lock(&cdp_mutex);
	n = &neighbour_table;
	while (*n != NULL) {
		e = *n;

		if (e->holdtime == 0 && e->deadtime >= threshold) {
			if (verbose > 0)
				printf("cdp: reap %s@%s (%u)\n",
				    e->devid, e->portid, e->deadtime);
			*n = e->next;
			free(e);
		} else {
			n = &(*n)->next;
		}
	}
	(void) pthread_mutex_unlock(&cdp_mutex);
}

void
yuka_cdp_refresh(const neighbour_t *new)
{
	neighbour_t *n, *next;

	(void) pthread_mutex_lock(&cdp_mutex);

	for (n = neighbour_table; n != NULL; n = n->next) {
		if (yuka_compare_host_entry(n, new))
			break;
	}

	if (n != NULL) {
		if (verbose > 0)
			printf("cdp: refresh entry %s@%s;%d\n",
			    n->devid, n->portid, n->holdtime);
	} else {
		if (verbose > 0)
			printf("cdp: new entry\n");
		n = malloc(sizeof (neighbour_t));
		if (n == NULL) {
			perror("malloc");
			goto out;
		}
		n->next = neighbour_table;
		neighbour_table = n;
	}

	next = n->next;
	bcopy(new, n, sizeof (neighbour_t));
	n->next = next;
	n->deadtime = 0;

	if (verbose > 0)
		printf("cdp: processed entry %s@%s\n", n->devid, n->portid);

out:
	(void) pthread_mutex_unlock(&cdp_mutex);
}

int
yuka_cdp_parse(const uint8_t *remdata, uint32_t rlen, neighbour_t *rhe)
{
	int i;
	const uint8_t *end, *cdata;
	int dumpcdp = (verbose > 3 ? 1 : 0);

	if (rlen < 20)
		return (1);

	end = remdata + rlen;
	cdata = remdata;

	for (i = 0; i < 8; i++) {
		if (*(cdata++) != LLC_CDP[i])
			return (1);
	}

	uint16_t cdp_checksum, v_checksum, alt_checksum, seclen, sectype;

	v_checksum = verify_checksum((uint16_t *)cdata, rlen - 8, 0);
	alt_checksum = verify_checksum((uint16_t *)cdata, rlen - 8, 1);
	rhe->version = *(cdata++); // version
	rhe->holdtime = *(cdata++); // holdtime (seconds)
	cdp_checksum = get_short_m(&cdata);

	if (dumpcdp)
		printf("CDP PARSE:\n%02x: %d seconds\n%04x ",
		    rhe->version, rhe->holdtime, cdp_checksum);

	if (v_checksum == cdp_checksum) {
		if (dumpcdp)
			printf("[OK]\n");
	} else if (alt_checksum == cdp_checksum) {
		if (dumpcdp)
			printf("[ALT OK]\n");
	} else {
		if (dumpcdp)
			printf("[Computed: %04x]\n", v_checksum);
		return (1);
	}

	while (cdata < end) {
		sectype = get_short_m(&cdata);
		seclen = get_short_m(&cdata) - 4;

		switch (sectype) {
		case CDP_DATA_DEVID:
			(void) get_cdp_string(cdata, seclen, rhe->devid,
			    sizeof (rhe->devid));
			if (dumpcdp)
				printf("[Device ID]: %s\n", rhe->devid);
			break;
		case CDP_DATA_ADDRESSES:
			if (dumpcdp) {
				printf("[Addresses]\n");
				xdump(cdata, seclen);
			}
			break;
		case CDP_DATA_PORTID:
			(void) get_cdp_string(cdata, seclen, rhe->portid,
			    sizeof (rhe->portid));
			if (dumpcdp)
				printf("[Port ID]: %s\n", rhe->portid);
			break;
		case CDP_DATA_CAPABILITY:
			rhe->caps = get_long(cdata);
			if (dumpcdp)
				printf("[Capability]: %08x\n", rhe->caps);
			break;
		case CDP_DATA_SWVER:
			(void) get_cdp_string(cdata, seclen, rhe->swversion,
			    sizeof (rhe->swversion));
			if (dumpcdp)
				printf("[Sw Version]: %s\n", rhe->swversion);
			break;
		case CDP_DATA_PLATFORM:
			(void) get_cdp_string(cdata, seclen, rhe->platform,
			    sizeof (rhe->platform));
			if (dumpcdp)
				printf("[Platform]: %s\n", rhe->platform);
			break;
		case CDP_DATA_VTP:
			(void) get_cdp_string(cdata, seclen, rhe->vtpdomain,
			    sizeof (rhe->vtpdomain));
			if (dumpcdp)
				printf("[VTP Domain]: %s\n", rhe->vtpdomain);
			break;
		case CDP_DATA_VLAN:
			rhe->vlan = get_short(cdata);
			if (dumpcdp)
				printf("[Native VLAN]: %d\n", rhe->vlan);
			break;
		case CDP_DATA_DUPLEX:
			rhe->duplex = *cdata;
			if (dumpcdp)
				printf("[Duplex]: %d\n", rhe->duplex);
			break;
		case CDP_DATA_TRUSTBM:
			if (dumpcdp) {
				printf("[Trust Bitmap]:(%04x)\n", seclen);
				xdump(cdata, seclen);
			}
			break;
		case CDP_DATA_COS:
			if (dumpcdp) {
				printf("[Untrusted Port CoS]:(%04x)\n", seclen);
				xdump(cdata, seclen);
			}
			break;
		case CDP_DATA_MGMTADDR:
			if (dumpcdp) {
				printf("[Management Addresses]:(%04x)\n",
				    seclen);
				xdump(cdata, seclen);
			}
			break;
		default:
			if (dumpcdp) {
				printf("[Unknown %04x]:(%04x)\n",
				    sectype, seclen);
				xdump(cdata, seclen);
			}
			break;
		}
		cdata += seclen;
	}

	if (dumpcdp)
		printf("//CDP PARSE\n\n");

	return (0);
}

void
yuka_cdp_init(yuka_session_t *ses, yuka_packet_t *lclcdp)
{
	lclcdp->framelen = 0;
	lclcdp->insertpos = 0;
	lclcdp->framepos = 0;
	lclcdp->llcstart = 14;
	lclcdp->llclen = 8;
	add_string(lclcdp, MAC_CDP.a, 6); // CDP Multicast
	add_string(lclcdp, ses->physaddr, 6); // Local address
	// Skip frame length
	lclcdp->insertpos = 14;
	add_string(lclcdp, LLC_CDP, 8); // LLC Header
	add_byte(lclcdp, 2);
	add_byte(lclcdp, CDP_HOLD_TIMER); // Holdtime
	add_short(lclcdp, 0); // Space for checksum
}

void
yuka_cdp_final(yuka_packet_t *lclcdp)
{
	int begin = lclcdp->llcstart + lclcdp->llclen;
	int cdplen = lclcdp->framelen - begin;
	if (verbose > 3)
		printf("finalize CDP: ofs=+%d, len=%d\n", begin, cdplen);
	uint16_t chksm = checksum((unsigned short *)(lclcdp->buf + begin),
	    cdplen);
	*((uint16_t *)(lclcdp->buf + begin + 2)) = chksm;

	/* IEEE 802.3 Frame size */
	lclcdp->insertpos = 12;
	add_short(lclcdp, lclcdp->framelen - 14);
}

void
cdp_add_sysname(yuka_packet_t *lclcdp)
{
	struct utsname name;

	if (uname(&name) == -1) {
		perror("cannot get system name");
		return;
	}
	cdp_add_softver(lclcdp, name.version);
	cdp_add_platform(lclcdp, "OmniOS");
}
