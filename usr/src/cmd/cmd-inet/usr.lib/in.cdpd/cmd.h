/*
 * CDDL HEADER START
 *
 *
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source. A copy of the CDDL is also available via the Internet at
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2015, 2018, 2019, Meisaka Yukara
 * Copyright 2018, 2019 Prominic.NET Inc. All Rights reserved.
 * Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
 */

#ifndef YUKA_CMD_H_INC
#define	YUKA_CMD_H_INC

#define	YUKA_SOCKET		"/var/run/cdpd_socket"
#define	YUKA_CLIENT_TIMEOUT	5000	/* msec */

#define	YUKA_CMD_SHOW		1
#define	YUKA_CMD_SHOW_CDP	1
#define	YUKA_CMD_SHOW_DETAIL	2

#define	YUKA_CMD_REAP		2

#define	YUKA_CMD_STATS		3

#define	YUKA_FMT_TEXT		0
#define	YUKA_FMT_PARSE		1
#define	YUKA_FMT_JSON		2
#define	YUKA_FMT_XML		3

#endif /* YUKA_CMD_H_INC */
