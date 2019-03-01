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
#define YUKA_DLPI_H_INC

#include "yuka.h"

void dlsap_to_dl_plus_sap(yuka_session const *ses, uint8_t const *dlsap, t_data_link_addr *dl_addr, t_uscalar_t *psap);
void dl_plus_sap_to_dlsap(yuka_session const *ses, const t_data_link_addr *dl_addr, t_uscalar_t sap, uint8_t *dlsap);
t_uscalar_t bytes_to_uscalar(uchar_t const *p, int l);
void uscalar_to_bytes(uchar_t *p, int l, t_uscalar_t u);

void yuka_list_links();
void yuka_get_links(struct yuka_string_list ** slist);
void yuka_free_links(struct yuka_string_list * slist);
void DlpiSnd(yuka_session *ses, t_dlsap_addr dlsap_addr, uchar_t *buf, int len);
void DlpiRcv(yuka_session *ses, t_dlsap_addr src_addr, t_dlsap_addr dest_addr);

#endif

