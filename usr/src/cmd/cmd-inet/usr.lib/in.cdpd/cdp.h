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

#ifndef YUKA_CDP_H_INC
#define	YUKA_CDP_H_INC

#include <stdint.h>

#define	CDP_XMIT_INTERVAL	60
#define	CDP_REAP_INTERVAL	60
#define	CDP_HOLD_TIMER		180
#define	CDP_DEAD_TIMER		300

#define	CDP_DATA_DEVID		0x1
#define	CDP_DATA_ADDRESSES	0x2
#define	CDP_DATA_PORTID		0x3
#define	CDP_DATA_CAPABILITY	0x4
#define	CDP_DATA_SWVER		0x5
#define	CDP_DATA_PLATFORM	0x6
#define	CDP_DATA_VTP		0x9
#define	CDP_DATA_VLAN		0xa
#define	CDP_DATA_DUPLEX		0xb
#define	CDP_DATA_TRUSTBM	0x12
#define	CDP_DATA_COS		0x13
#define	CDP_DATA_MGMTADDR	0x16

#define	CDPCAP_ROUTER		0x1
#define	CDPCAP_TRBRIDGE		0x2
#define	CDPCAP_SRBRIDGE		0x4
#define	CDPCAP_SWITCH		0x8
#define	CDPCAP_HOST		0x10
#define	CDPCAP_IGMP		0x20
#define	CDPCAP_REPEATER		0x40
#define	CDPCAP_PHONE		0x80

typedef struct cdp_host_entry {
	void			*localportid;
	uint8_t			holdtime;
	uint16_t		deadtime;
	uint8_t			version;
	uint8_t			duplex;
	uint16_t		vlan;
	uint32_t		caps;
	char			devid[40];
	char			portid[40];
	char			platform[80];
	char			vtpdomain[40];
	char			swversion[256];
	struct cdp_host_entry	*next;
} neighbour_t;

void yuka_cdp_init(yuka_session_t *, yuka_packet_t *);
void yuka_cdp_final(yuka_packet_t *);
void yuka_cdp_walk(void (*)(neighbour_t *, void *), void *, boolean_t);
void yuka_cdp_reap(int);
void yuka_cdp_refresh(const neighbour_t *);
int yuka_cdp_parse(const uint8_t *, uint32_t, neighbour_t *);
void cdp_add_sysname(yuka_packet_t * lclcdp);
void cdp_add_hostid(yuka_packet_t *, const char *);
void cdp_add_ipaddress(yuka_packet_t *, in_addr_t);
void cdp_add_portid(yuka_packet_t *, const char *);
void cdp_add_capabilities(yuka_packet_t *, uint32_t);
extern const data_link_addr_t MAC_CDP;

#endif /* YUKA_CDP_H_INC */
