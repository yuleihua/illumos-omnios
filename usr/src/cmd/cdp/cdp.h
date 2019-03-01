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
#ifndef YUKA_CDP_H_INC
#define YUKA_CDP_H_INC

#include <stdint.h>

#define CDPCAP_ROUTER 1
#define CDPCAP_TRBRIDGE 2
#define CDPCAP_SRBRIDGE 4
#define CDPCAP_SWITCH 8
#define CDPCAP_HOST 0x10
#define CDPCAP_IGMP 0x20
#define CDPCAP_REPEATER 0x40
#define CDPCAP_PHONE 0x80

struct cdp_host_entry {
	void *localportid;
	uint8_t holdtime;
	uint8_t version;
	uint8_t duplex;
	uint16_t vlan;
	uint32_t caps;
	uint32_t flags;
	char devid[40];
	char portid[40];
	char platform[80];
	char vtpdomain[40];
	char swversion[256];
};

struct cdp_table_set {
	struct cdp_table_set *next;
	struct cdp_host_entry entries[40];
};

int yuka_cdp_init(yuka_packet_t * lclcdp);
int yuka_cdp_final(yuka_packet_t * lclcdp);
void yuka_cdp_walk(void (*walkcb)(struct cdp_host_entry *, void *), void * extra);
int yuka_cdp_refresh(const struct cdp_host_entry *rhe);
int yuka_cdp_parse(const uint8_t *remdata, uint32_t rlen, struct cdp_host_entry *rhe);
void cdp_add_sysname(yuka_packet_t * lclcdp);
int cdp_add_hostid(yuka_packet_t * lfr, const char * devid);
int cdp_add_ipaddress(yuka_packet_t * lfr, in_addr_t ip);
int cdp_add_portid(yuka_packet_t * lfr, const char * portid);
int cdp_add_capabilities(yuka_packet_t * lfr, uint32_t flags);
extern const t_data_link_addr MAC_CDP;

#endif

