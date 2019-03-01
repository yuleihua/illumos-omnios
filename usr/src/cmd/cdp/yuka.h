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
#define YUKA_H_INC

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

/* data link addresses */
#define DLADDR_MAX 16
typedef union u_dladdr {
	unsigned char a[DLADDR_MAX];
	uint64_t qa[DLADDR_MAX / 8];
} t_data_link_addr;

/* dlsap addresses */
typedef uint8_t t_dlsap_addr[ sizeof(t_data_link_addr) + sizeof(t_uscalar_t) ];

struct yuka_dlpi_info {
	int data_link_addr_len;
	int sap_length; /* as returned by DL_INFO_ACK */
	uint8_t dev_addr[8];
};

typedef struct yuka_packet {
	uint8_t *buf;
	int bufsize;
	int insertpos;
	uint16_t framelen;
	int framepos;
	int llcstart;
	int llclen;
	int ipstart;
} yuka_packet_t;

#define YUKA_PRIMBUFMAX 512
#define YUKA_BUFMAX (64*1024)
typedef struct yuka_buffer_pair {
	struct strbuf ctlbuf;
	struct strbuf databuf;
} t_buffer_pair;

typedef struct st_yuka_session {
	int id_yuka_session;
	int fd;
	char *device;
	struct yuka_dlpi_info const *link;
	yuka_packet_t * cdpinfo;
	yuka_packet_t * sndframe;
	t_buffer_pair rcv;
	time_t dtime;
	int frames_in;
	int frames_out;
	int bytes_in;
	int bytes_out;
} yuka_session;

struct yuka_string_list {
	char * str;
	struct yuka_string_list * next;
};

void PutData(yuka_session *ses, const void *data, int data_len);
void Error(char *str, ...);
void Warn(char *str, ...);
void xdump(const unsigned char *p, int l);
void nbytes_hex(const char *s1, const uchar_t *b, int n, const char *s2);

int mac_equal(const void *ma, const void *mb);
int add_long(yuka_packet_t *lfp, uint32_t v);
uint32_t get_long(const uint8_t *rfp);
uint32_t get_long_m(const uint8_t **rfp);
int add_ip(yuka_packet_t * lfp, in_addr_t v);
int add_short(yuka_packet_t * lfp, uint16_t v);
uint16_t get_short(const uint8_t *rfp);
uint16_t get_short_m(const uint8_t **rfp);
int add_byte(yuka_packet_t * lfp, uint8_t v);
int add_string(yuka_packet_t * lfp, const uint8_t * v, int len);
uint16_t checksum(const void *ptr, int length);
uint32_t checksum_b(const void *ptr, int length);
uint32_t checksum_p(const void *ptr, int length, uint32_t ac);
uint16_t checksum_f(const void *ptr, int length, uint32_t ac);

#endif

