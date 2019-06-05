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

#ifndef YUKA_H_INC
#define	YUKA_H_INC

#include <ctype.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stropts.h>
#include <stdio.h>
#include <time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <net/if_dl.h>
#include <libdlpi.h>

#define	FRAME_SIZE	1500

/* data link addresses */
typedef union {
	unsigned char a[DLPI_PHYSADDR_MAX];
	uint64_t qa[DLPI_PHYSADDR_MAX / 8];
} data_link_addr_t;

/* dlsap addresses */
typedef uint8_t dlsap_addr_t[DLPI_PHYSADDR_MAX];

typedef struct {
	uint8_t *buf;
	size_t bufsize;
	int insertpos;
	size_t framelen;
	int framepos;
	int llcstart;
	int llclen;
} yuka_packet_t;

typedef struct {
	int id_yuka_session;
	char *device;

	int fd;
	dlpi_handle_t hdl;
	uint8_t physaddr[DLPI_PHYSADDR_MAX];
	uint_t mtu;
	uint8_t *buf;

	yuka_packet_t *cdpinfo;

	int frames_in;
	int frames_out;
	int bytes_in;
	int bytes_out;
} yuka_session_t;

typedef struct yuka_string_list {
	char *str;
	struct yuka_string_list *next;
} stringlist_t;

void Error(char *, ...) __NORETURN;
void Warn(char *, ...);
void xdump(const unsigned char *, int);
void nbytes_hex(const char *, const uchar_t *, int, const char *);

int mac_equal(const void *, const void *);
void add_long(yuka_packet_t *, uint32_t);
void add_ip(yuka_packet_t *, in_addr_t);
void add_short(yuka_packet_t *, uint16_t);
void add_byte(yuka_packet_t *, uint8_t);
void add_string(yuka_packet_t *, const uint8_t *, int);
uint32_t get_long(const uint8_t *);
uint16_t get_short(const uint8_t *);
uint16_t get_short_m(const uint8_t **);
uint16_t checksum(const void *, int);
void yuka_show_cdp_hosts(int, int);
void yuka_stats(int);
void yuka_show_detail(int);

#endif /* YUKA_H_INC */
