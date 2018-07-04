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

#include <limits.h>
#include <sys/mdb_modapi.h>
#include <sys/sysinfo.h>
#include <sys/sunmdi.h>
#include <sys/x86_archext.h>

int
/* LINTED E_FUNC_ARG_UNUSED */
sec_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint64_t kpti_enable;
	int x86_use_pcid, x86_use_invpcid;
	void *fset;
	GElf_Sym sym;
	size_t sz;
	int opt_p = FALSE;

	if (mdb_getopts(argc, argv, 'p', MDB_OPT_SETBITS, TRUE, &opt_p) != argc)
		return (DCMD_USAGE);

	/* Meltdown (CVE-2017-5754) */

	if (mdb_readvar(&kpti_enable, "kpti_enable") == -1)
		kpti_enable = 2;
	if (mdb_readvar(&x86_use_pcid, "x86_use_pcid") == -1)
		x86_use_pcid = -1;
	if (mdb_readvar(&x86_use_invpcid, "x86_use_invpcid") == -1)
		x86_use_invpcid = -1;

	sz = sizeof (uchar_t) * BT_SIZEOFMAP(NUM_X86_FEATURES);
	fset = mdb_zalloc(sz, UM_NOSLEEP);
	if (fset == NULL) {
		mdb_warn("failed to allocate memory for x86_featureset");
		return (DCMD_ERR);
	}
	if (mdb_readvar(fset, "x86_featureset") != sz) {
		mdb_warn("failed to read x86_featureset");
		mdb_free(fset, sz);
		return (DCMD_ERR);
	}

	if (opt_p)
		mdb_printf("meltdown:CVE-2017-5754:%s\n",
		    kpti_enable == 1 ? "protected" : "not-protected");
	else
	{
		mdb_printf("= Meltdown (CVE-2017-5754)\n");
		mdb_printf("    Status: %s\n",
		    kpti_enable == 1 ? "PROTECTED" : "NOT PROTECTED");
		mdb_printf("            KPTI is %s\n",
		    kpti_enable == 2 ? "not available" :
		    (kpti_enable ? "enabled" : "disabled"));
		mdb_printf("            PCID is %s\n",
		    !BT_TEST((ulong_t *)fset, X86FSET_PCID) ?
		    "not supported by this processor" :
		    (x86_use_pcid == 1 ? "in-use" : "disabled"));
		mdb_printf("            INVPCID is %s\n",
		    !BT_TEST((ulong_t *)fset, X86FSET_INVPCID) ?
		    "not supported by this processor" :
		    (x86_use_pcid == 1 && x86_use_invpcid == 1 ?
		    "in-use" : "disabled"));
	}

	mdb_free(fset, sz);

	/* Lazy FPU (CVE-2018-3665) */

	int eager = mdb_lookup_by_name("fp_exec", &sym) == 0;

	if (opt_p)
		mdb_printf("lazy fpu:CVE-2018-3665:%s\n",
		    eager ? "protected" : "not-protected");
	else
	{
		mdb_printf("= Lazy FPU (CVE-2018-3665)\n");
		mdb_printf("    Status: %s\n",
		    eager == 1 ? "PROTECTED" : "NOT PROTECTED");
		mdb_printf(
		    "            System is using %s FPU register restore\n",
		    eager ? "eager" : "lazy");
	}

	return (DCMD_OK);
}

void
sec_help(void)
{
	mdb_printf(
	    "Prints information about the status of kernel protection\n"
	    "against processor vulnerabilities.\n");
	mdb_printf(
	    "    -p    Output information in a format suitable for parsing\n");
}
