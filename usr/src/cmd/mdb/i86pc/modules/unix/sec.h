/*
 * CDDL HEADER
 *
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source. A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2018 OmniOS Community Edition (OmniOSce) Association.
 */

#ifndef	_I86SEC_H
#define	_I86SEC_H

#ifdef	__cplusplus
extern "C" {
#endif

extern int sec_dcmd(uintptr_t addr, uint_t flags, int argc,
	const mdb_arg_t *argv);

extern void sec_help(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _I86SEC_H */
