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

#ifndef YUKA_DLPI_H_INC
#define	YUKA_DLPI_H_INC

#include "yuka.h"

void DlpiSnd(yuka_session_t *, data_link_addr_t, uchar_t *, int);
boolean_t DlpiRcv(yuka_session_t *, yuka_packet_t *,
    dlsap_addr_t, dlsap_addr_t);
void DlpiOpenSession(yuka_session_t *);
void DlpiCloseSession(yuka_session_t *);

char *get_ether_type(int);
void yuka_list_links(void);
void yuka_get_links(struct yuka_string_list **);
void yuka_free_links(struct yuka_string_list *);

#endif /* YUKA_DLPI_H_INC */
