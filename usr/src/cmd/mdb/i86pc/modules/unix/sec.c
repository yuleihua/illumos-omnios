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

enum vuln_status { VULN_UNKNOWN = 0, VULN_INVULN, VULN_PROT, VULN_NOTPROT };

static char *
vuln_name(enum vuln_status vuln, int p)
{
	switch (vuln) {
	case VULN_INVULN:
		return p ? "not vulnerable" : "NOT VULNERABLE";
		break;
	case VULN_PROT:
		return p ? "protected" : "PROTECTED";
		break;
	case VULN_NOTPROT:
		return p ? "not protected" : "NOT PROTECTED";
		break;
	case VULN_UNKNOWN:
	default:
		break;
	}
	return p ? "unknown" : "UNKNOWN";
}

int
/* LINTED E_FUNC_ARG_UNUSED */
sec_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	void *fset;
	GElf_Sym sym;
	size_t sz;
	int opt_p = FALSE;
	enum vuln_status vuln = VULN_UNKNOWN;

	if (mdb_getopts(argc, argv, 'p', MDB_OPT_SETBITS, TRUE, &opt_p) != argc)
		return (DCMD_USAGE);

	/* Retrieve CPU feature list */
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

	/* Meltdown (CVE-2017-5754) */

	int x86_use_pcid, x86_use_invpcid;
	uint64_t kpti_enable;

	if (mdb_readvar(&kpti_enable, "kpti_enable") == -1)
		kpti_enable = 2;
	if (mdb_readvar(&x86_use_pcid, "x86_use_pcid") == -1)
		x86_use_pcid = -1;
	if (mdb_readvar(&x86_use_invpcid, "x86_use_invpcid") == -1)
		x86_use_invpcid = -1;

	if (opt_p) {
		mdb_printf("meltdown:CVE-2017-5754:%s\n",
		    kpti_enable == 1 ? vuln_name(VULN_PROT, opt_p) :
		    vuln_name(VULN_NOTPROT, opt_p));
	} else {
		mdb_printf("= Meltdown (CVE-2017-5754)\n");
		mdb_printf("    Status: %s\n",
		    kpti_enable == 1 ? vuln_name(VULN_PROT, opt_p) :
		    vuln_name(VULN_NOTPROT, opt_p));
		mdb_printf("            KPTI is %s\n",
		    kpti_enable == 2 ? "not available" :
		    (kpti_enable ? "enabled" : "disabled"));
		mdb_printf("            PCID is %s\n",
		    !BT_TEST((ulong_t *)fset, X86FSET_PCID) ?
		    "not supported by this processor" :
		    (x86_use_pcid == 1 ? "in use" : "disabled"));
		mdb_printf("            INVPCID is %s\n",
		    !BT_TEST((ulong_t *)fset, X86FSET_INVPCID) ?
		    "not supported by this processor" :
		    (x86_use_pcid == 1 && x86_use_invpcid == 1 ?
		    "in use" : "disabled"));
		mdb_printf("\n");
	}

	/* Lazy FPU (CVE-2018-3665) */

	int eager = mdb_lookup_by_name("fp_exec", &sym) == 0;

	if (opt_p) {
		mdb_printf("lazy fpu:CVE-2018-3665:%s\n",
		    eager == 1 ? vuln_name(VULN_PROT, opt_p) :
		    vuln_name(VULN_NOTPROT, opt_p));
	} else {
		mdb_printf("= Lazy FPU (CVE-2018-3665)\n");
		mdb_printf("    Status: %s\n",
		    eager == 1 ? vuln_name(VULN_PROT, opt_p) :
		    vuln_name(VULN_NOTPROT, opt_p));
		mdb_printf(
		    "            System is using %s FPU register restore\n",
		    eager ? "eager" : "lazy");
		mdb_printf("\n");
	}

	/* Foreshadow/L1TF (CVE-2018-3646) */

	int ht_exclusion, rdcl_no, flush_cmd, l1d_vm_no;

	if (mdb_readvar(&ht_exclusion, "ht_exclusion") == -1)
		ht_exclusion = 0;

	rdcl_no = BT_TEST((ulong_t *)fset, X86FSET_RDCL_NO);
	flush_cmd = BT_TEST((ulong_t *)fset, X86FSET_FLUSH_CMD);
	l1d_vm_no = BT_TEST((ulong_t *)fset, X86FSET_L1D_VM_NO);

	if (rdcl_no)
		vuln = VULN_INVULN;
	else if (!ht_exclusion)
		vuln = VULN_NOTPROT;
	else if (l1d_vm_no)
		/* Flush cmd not required, ht-exclusion is enough */
		vuln = VULN_PROT;
	else if (flush_cmd)
		vuln = VULN_PROT;
	else
		vuln = VULN_NOTPROT;

	if (opt_p) {
		mdb_printf("foreshadow:CVE-2018-3646:%s\n",
		    vuln_name(vuln, opt_p));
	} else {
		mdb_printf("= Foreshadow/L1TF (CVE-2018-3646)\n");
		mdb_printf("    Status: %s%c\n", vuln_name(vuln, opt_p),
		    vuln == VULN_NOTPROT ? '*' : ' ');
		if (rdcl_no)
			mdb_printf("            CPU reports not vulnerable "
			    "(RDCL_NO)\n");
		if (l1d_vm_no)
			mdb_printf("            CPU reports cache flush not "
			    "required (L1D_VM_NO)\n");
		mdb_printf(
		    "            HT Exclusion is %s\n",
		    ht_exclusion ? "enabled" : "disabled");
		mdb_printf(
		    "            L1 Cache flush is %s\n",
		    flush_cmd ? "available" : "not supported");
		if (vuln == VULN_NOTPROT)
			mdb_printf(
			    "            * - Not necessary if hyperthreading "
			    "is disabled/not present.\n");
		mdb_printf("\n");
	}

	/* Free feature set */

	mdb_free(fset, sz);

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
