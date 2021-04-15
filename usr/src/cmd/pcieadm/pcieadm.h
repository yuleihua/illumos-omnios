/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2021 Oxide Computer Company
 */

#ifndef _PCIEADM_H
#define	_PCIEADM_H

/*
 * Common definitions for pcieadm(1M).
 */

#include <libdevinfo.h>
#include <pcidb.h>
#include <priv.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct pcieadm pcieadm_t;

typedef struct pcieadm_cmdtab {
	const char *pct_name;
	int (*pct_func)(pcieadm_t *, int, char **);
	void (*pct_use)(FILE *);
} pcieadm_cmdtab_t;

struct pcieadm {
	uint_t pia_indent;
	di_node_t pia_root;
	const char *pia_devstr;
	di_node_t pia_devi;
	di_node_t pia_nexus;
	pcidb_hdl_t *pia_pcidb;
	const pcieadm_cmdtab_t *pia_cmdtab;
	priv_set_t *pia_priv_init;
	priv_set_t *pia_priv_min;
	priv_set_t *pia_priv_eff;
};

typedef struct {
	void *pdw_arg;
	int (*pdw_func)(di_node_t, void *);
} pcieadm_di_walk_t;

/*
 * Config space related
 */
typedef boolean_t (*pcieadm_cfgspace_f)(uint32_t, uint8_t, void *, void *);

/*
 * Utilities
 */
extern void pcieadm_di_walk(pcieadm_t *, pcieadm_di_walk_t *);
extern void pcieadm_init_cfgspace_kernel(pcieadm_t *, pcieadm_cfgspace_f *,
    void **);
extern void pcieadm_fini_cfgspace_kernel(void *);
extern void pcieadm_init_cfgspace_file(pcieadm_t *, const char *,
    pcieadm_cfgspace_f *, void **);
extern void pcieadm_fini_cfgspace_file(void *);
extern void pcieadm_find_nexus(pcieadm_t *);
extern void pcieadm_find_dip(pcieadm_t *, const char *);
extern boolean_t pcieadm_di_node_is_pci(di_node_t);

/*
 * Output related
 */
extern const char *pcieadm_progname;
extern void pcieadm_indent(void);
extern void pcieadm_deindent(void);
extern void pcieadm_print(const char *, ...);
extern void pcieadm_ofmt_errx(const char *, ...);

/*
 * Command tabs
 */
extern int pcieadm_save_cfgspace(pcieadm_t *, int, char *[]);
extern void pcieadm_save_cfgspace_usage(FILE *);
extern int pcieadm_show_cfgspace(pcieadm_t *, int, char *[]);
extern void pcieadm_show_cfgspace_usage(FILE *);
extern int pcieadm_show_devs(pcieadm_t *, int, char *[]);
extern void pcieadm_show_devs_usage(FILE *);

#define	EXIT_USAGE	2

/*
 * Privilege related. Note there are no centralized functions around raising and
 * lowering privs as that unfortunately makes ROPs more easy to execute.
 */
extern void pcieadm_init_privs(pcieadm_t *);

/*
 * XXX Maybe not here:
 */
#define	BITX(u, h, l)   (((u) >> (l)) & ((1LU << ((h) - (l) + 1LU)) - 1LU))

#ifdef __cplusplus
}
#endif

#endif /* _PCIEADM_H */
