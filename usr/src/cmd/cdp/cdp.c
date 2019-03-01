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
 */
#include <ctype.h>
#include <stdlib.h>
#include <stdint.h>
#include <netinet/in.h>

#include "yuka.h"
#include "cdp.h"

struct lineprocst {
	int tlmode;
	int slmode;
	int idc;
	int hav;
	uint8_t r_mac[6];
	uint8_t t_mac[6];
	in_addr_t r_ipaddr;
	in_addr_t t_ipaddr;
	char r_devname[32];
	char t_devname[32];
	char t_data[64];
	char r_model[256];
};

extern int verbose;
static int cdp_add_x(yuka_packet_t *, unsigned short, const uint8_t*, unsigned short);

unsigned short verify_checksum(const unsigned short *ptr, int length, int oddtype)
{
	uint32_t sum = 0;
	const uint16_t *w = ptr;
	uint16_t v;
	int nleft = length - 4;

	sum = ntohs(*w);
	w += 2;
	while(nleft > 1) {
		sum += ntohs(*w++);
		nleft -= 2;
	}
	if(nleft == 1) {
		v = (*(const uint8_t*)w) & 0xff;
		sum += v;
		/* don't know the exact checksum algorithm
		 * but it seems like this may be needed in some instances */
		if(oddtype) sum += 0xfeff;
	}
	while(sum & 0xffff0000) {
		sum = (sum >> 16) + (sum & 0xFFFF);
	}
	return (~sum);
}

int cdp_add_hostid(yuka_packet_t * lfr, const char * devid)
{
	return cdp_add_x(lfr, 1, (uint8_t*)devid, strlen( devid ));
}

// ip 1.2.3.4 == 0x01020304
int cdp_add_ipaddress(yuka_packet_t * lfr, in_addr_t ip)
{
	uint8_t stg[3] = { 1, 1, 0xcc }; // Type NLPID(1), Len 1, Proto: IP( 0xCC )
	if(17 + lfr->insertpos > lfr->bufsize) {
		return -5;
	}
	add_short(lfr, 2);
	add_short(lfr, 17);
	add_long(lfr, 1); // Address Count
	add_string(lfr, stg, 3); // Address Info
	add_short(lfr, 4); // Address Len - 4 Bytes
	add_ip(lfr, ip); // IP
	return 0;
}

int cdp_add_portid(yuka_packet_t * lfr, const char * portid)
{
	return cdp_add_x(lfr, 3, (uint8_t*)portid, strlen( portid ));
}

int cdp_add_capabilities(yuka_packet_t * lfr, uint32_t flags)
{
	if(8 + lfr->insertpos > lfr->bufsize) {
	return -5;
	}
	add_short(lfr, 4);
	add_short(lfr, 8);
	add_long(lfr, flags);
	return 0;
}

static int cdp_add_softver(yuka_packet_t * lfr, const char * verstr)
{
	return cdp_add_x(lfr, 5, (uint8_t*)verstr, strlen(verstr));
}

static int cdp_add_platform(yuka_packet_t * lfr, const char * plfstr)
{
	return cdp_add_x(lfr, 6, (uint8_t*)plfstr, strlen(plfstr));
}

static int cdp_add_x(yuka_packet_t * lfr, unsigned short ty, const uint8_t* x, unsigned short xlen)
{
	int inp = lfr->insertpos;
	if(xlen + 4 + inp > lfr->bufsize) {
		return -5;
	}
	add_short(lfr, ty);
	add_short(lfr, 4+xlen);
	add_string(lfr, (uint8_t*)x, xlen);
	return 0;
}

int get_cdp_string(const uint8_t* cdata, int slen, char* dest, int dlen) {
	int p = slen;
	if(slen >= dlen) { p = dlen - 1; }
	int i;
	for(i = 0; i < p; i++) {
		dest[i] = (cdata)[i];
	}
	dest[i] = 0;
	return p;
}

static struct cdp_table_set yuka_cdp_hosts_table = {0, };

static int yuka_compare_host_entry(const struct cdp_host_entry *he_a, const struct cdp_host_entry *he_b)
{
	return (
		he_a->localportid == he_b->localportid
		&& strcmp(he_a->portid, he_b->portid) == 0
		&& strcmp(he_a->devid, he_b->devid) == 0
	       );
}

void yuka_cdp_walk(void (*walkcb)(struct cdp_host_entry *, void *), void * extra)
{
	struct cdp_table_set *ctp;
	struct cdp_host_entry *che;
	int i;
	ctp = &yuka_cdp_hosts_table;
	while(ctp) {
		for(i = 0; i < 40; i++) {
			che = &ctp->entries[i];
			if(che->holdtime) {
				walkcb(che, extra);
			}
		}
		ctp = ctp->next;
	}
}

int yuka_cdp_refresh(const struct cdp_host_entry *rhe)
{
	struct cdp_table_set *ctp;
	struct cdp_host_entry *che, *ehe;
	int i;
	ctp = &yuka_cdp_hosts_table;
	ehe = 0;
	while(ctp) {
		for(i = 0; i < 40; i++) {
			che = &ctp->entries[i];
			if(che->holdtime) {
				if(yuka_compare_host_entry(che, rhe)) {
					//printf("EQ\n");
					ehe = che;
				}
			} else {
				if(!ehe) {
					//printf("Slot %d\n", i);
					ehe = che;
				}
			}
		}
		ctp = ctp->next;
	}
	if(!ehe) { // no empty slots
		if(verbose > 3) printf("cdp: out of slots\n");
	} else {
		if(!ehe->holdtime) {
			if(verbose > 0) printf("cdp: new entry\n");
		}
		memcpy(ehe, rhe, sizeof(struct cdp_host_entry));
	}
	return 0;
}

const t_data_link_addr MAC_CDP = { {0x01,0x00,0x0c,0xcc,0xcc,0xcc} };
const uint8_t LLC_CDP[8] = { 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20, 0x00 };
int yuka_cdp_parse(const uint8_t *remdata, uint32_t rlen, struct cdp_host_entry *rhe) {
	if(rlen < 20) return 1;
	int i;
	const uint8_t *end, *cdata;
	int dumpcdp = (verbose > 3 ? 1 : 0);
	end = remdata + rlen;
	cdata = remdata;
	for(i = 0; i < 8; i++) {
		if(*(cdata++) != LLC_CDP[i]) return 1;
	}
	rhe->flags = 0;
	uint16_t cdp_checksum, v_checksum, alt_checksum, seclen, sectype;
	v_checksum = verify_checksum((uint16_t*)cdata, rlen - 8, 0);
	alt_checksum = verify_checksum((uint16_t*)cdata, rlen - 8, 1);
	rhe->version = *(cdata++); // version
	rhe->holdtime = *(cdata++); // holdtime (seconds)
	cdp_checksum = get_short_m(&cdata);
	if(dumpcdp) printf("CDP PARSE:\n%02x: %d seconds\n%04x ", rhe->version, rhe->holdtime, cdp_checksum);
	if(v_checksum == cdp_checksum) {
		if(dumpcdp) printf("[OK]\n");
	} else if(alt_checksum == cdp_checksum) {
		if(dumpcdp) printf("[ALT OK]\n");
	} else {
		if(dumpcdp) printf("[Computed: %04x]\n", v_checksum);
		return 1;
	}
	while(cdata < end) {
		sectype = get_short_m(&cdata);
		seclen = get_short_m(&cdata) - 4;
		switch(sectype) {
		case 1: // device id
			get_cdp_string(cdata, seclen, rhe->devid, sizeof(rhe->devid));
			if(dumpcdp) printf("[Device ID]: %s\n", rhe->devid);
			rhe->flags |= 1;
			break;
		case 2: // addresses
			if(dumpcdp) {
				printf("[Addresses]\n");
				xdump(cdata, seclen);
			}
			break;
		case 3: // port ID
			get_cdp_string(cdata, seclen, rhe->portid, sizeof(rhe->portid));
			if(dumpcdp) printf("[Port ID]: %s\n", rhe->portid);
			rhe->flags |= 2;
			break;
		case 4: // capabilities
			rhe->caps = get_long(cdata);
			if(dumpcdp) printf("[Capability]: %08x\n", rhe->caps);
			rhe->flags |= 4;
			break;
		case 5: // Software version
			get_cdp_string(cdata, seclen, rhe->swversion, sizeof(rhe->swversion));
			if(dumpcdp) printf("[Sw Version]: %s\n", rhe->swversion);
			rhe->flags |= 8;
			break;
		case 6: // platform
			get_cdp_string(cdata, seclen, rhe->platform, sizeof(rhe->platform));
			if(dumpcdp) printf("[Platform]: %s\n", rhe->platform);
			rhe->flags |= 0x10;
			break;
		case 9: // management domain (VTP)
			get_cdp_string(cdata, seclen, rhe->vtpdomain, sizeof(rhe->vtpdomain));
			if(dumpcdp) printf("[VTP Domain]: %s\n", rhe->vtpdomain);
			rhe->flags |= 0x20;
			break;
		case 10: // native VLAN
			rhe->vlan = get_short(cdata);
			if(dumpcdp) printf("[Native VLAN]: %d\n", rhe->vlan);
			rhe->flags |= 0x40;
			break;
		case 11: // link duplex
			if(dumpcdp) printf("[Duplex]: %x\n", *(cdata));
			break;
		case 0x0012: // trust bitmap
			if(dumpcdp) {
				printf("[Trust Bitmap]:(%04x)\n", seclen);
				xdump(cdata, seclen);
			}
			break;
		case 0x0013: // untrusted port CoS
			if(dumpcdp) {
				printf("[Untrusted Port CoS]:(%04x)\n", seclen);
				xdump(cdata, seclen);
			}
			break;
		case 0x0016: // management addresses
			if(dumpcdp) {
				printf("[Management Addresses]:(%04x)\n", seclen);
				xdump(cdata, seclen);
			}
			break;
		default:
			if(dumpcdp) {
				printf("[Unknown %04x]:(%04x)\n", sectype, seclen);
				xdump(cdata, seclen);
			}
			break;
		}
		cdata += seclen;
	}
	if(dumpcdp) printf("//CDP PARSE\n");
	return 0;
}

int yuka_cdp_init(yuka_packet_t * lclcdp) {
	lclcdp->framelen = 0;
	lclcdp->insertpos = 0;
	lclcdp->framepos = 0;
	//lclcdp->llcstart = 14;
	lclcdp->llcstart = 0;
	lclcdp->llclen = 8;
	//add_string(lclcdp, MAC_CDP.a, 6); // CDP Multicast
	//lclcdp->insertpos = 14;
	add_string(lclcdp, LLC_CDP, 8); // LLC Header
	add_byte(lclcdp, 2);
	add_byte(lclcdp, 180); // Holdtime
	add_short(lclcdp, 0); // Space for checksum
	return 0;
}
int yuka_cdp_final(yuka_packet_t * lclcdp) {
	int begin = lclcdp->llcstart + lclcdp->llclen;
	int cdplen = lclcdp->framelen - begin;
	if(verbose > 3) printf("finallize CDP: ofs=+%d, len=%d\n", begin, cdplen);
	uint16_t chksm = checksum((unsigned short *)(lclcdp->buf + begin), cdplen);
	*((uint16_t*)(lclcdp->buf + begin + 2)) = chksm;
	return 0;
}

#include <sys/utsname.h>

void cdp_add_sysname(yuka_packet_t * lclcdp) {
	struct utsname name;
	if(uname (&name) == -1) {
		perror("cannot get system name");
		return;
	}
	cdp_add_softver(lclcdp, name.version);
	cdp_add_platform(lclcdp, "Solaris");
}
