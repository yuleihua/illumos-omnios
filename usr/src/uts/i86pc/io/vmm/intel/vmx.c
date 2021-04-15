/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2011 NetApp, Inc.
 * All rights reserved.
 * Copyright (c) 2018 Joyent, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */
/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 *
 * Copyright 2015 Pluribus Networks Inc.
 * Copyright 2018 Joyent, Inc.
 * Copyright 2020 Oxide Computer Company
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/smp.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/pcpu.h>
#include <sys/proc.h>
#include <sys/sysctl.h>

#ifndef __FreeBSD__
#include <sys/x86_archext.h>
#include <sys/smp_impldefs.h>
#include <sys/smt.h>
#include <sys/hma.h>
#include <sys/trap.h>
#endif

#include <vm/vm.h>
#include <vm/pmap.h>

#include <machine/psl.h>
#include <machine/cpufunc.h>
#include <machine/md_var.h>
#include <machine/reg.h>
#include <machine/segments.h>
#include <machine/smp.h>
#include <machine/specialreg.h>
#include <machine/vmparam.h>

#include <machine/vmm.h>
#include <machine/vmm_dev.h>
#include <sys/vmm_instruction_emul.h>
#include "vmm_lapic.h"
#include "vmm_host.h"
#include "vmm_ioport.h"
#include "vmm_ktr.h"
#include "vmm_stat.h"
#include "vatpic.h"
#include "vlapic.h"
#include "vlapic_priv.h"

#include "ept.h"
#include "vmcs.h"
#include "vmx.h"
#include "vmx_msr.h"
#include "x86.h"
#include "vmx_controls.h"

#define	PINBASED_CTLS_ONE_SETTING					\
	(PINBASED_EXTINT_EXITING	|				\
	PINBASED_NMI_EXITING		|				\
	PINBASED_VIRTUAL_NMI)
#define	PINBASED_CTLS_ZERO_SETTING	0

#define	PROCBASED_CTLS_WINDOW_SETTING					\
	(PROCBASED_INT_WINDOW_EXITING	|				\
	PROCBASED_NMI_WINDOW_EXITING)

#ifdef __FreeBSD__
#define	PROCBASED_CTLS_ONE_SETTING					\
	(PROCBASED_SECONDARY_CONTROLS	|				\
	PROCBASED_MWAIT_EXITING		|				\
	PROCBASED_MONITOR_EXITING	|				\
	PROCBASED_IO_EXITING		|				\
	PROCBASED_MSR_BITMAPS		|				\
	PROCBASED_CTLS_WINDOW_SETTING	|				\
	PROCBASED_CR8_LOAD_EXITING	|				\
	PROCBASED_CR8_STORE_EXITING)
#else
/* We consider TSC offset a necessity for unsynched TSC handling */
#define	PROCBASED_CTLS_ONE_SETTING					\
	(PROCBASED_SECONDARY_CONTROLS	|				\
	PROCBASED_TSC_OFFSET		|				\
	PROCBASED_MWAIT_EXITING		|				\
	PROCBASED_MONITOR_EXITING	|				\
	PROCBASED_IO_EXITING		|				\
	PROCBASED_MSR_BITMAPS		|				\
	PROCBASED_CTLS_WINDOW_SETTING	|				\
	PROCBASED_CR8_LOAD_EXITING	|				\
	PROCBASED_CR8_STORE_EXITING)
#endif /* __FreeBSD__ */

#define	PROCBASED_CTLS_ZERO_SETTING	\
	(PROCBASED_CR3_LOAD_EXITING |	\
	PROCBASED_CR3_STORE_EXITING |	\
	PROCBASED_IO_BITMAPS)

/*
 * EPT and Unrestricted Guest are considered necessities.  The latter is not a
 * requirement on FreeBSD, where grub2-bhyve is used to load guests directly
 * without a bootrom starting in real mode.
 */
#define	PROCBASED_CTLS2_ONE_SETTING		\
	(PROCBASED2_ENABLE_EPT |		\
	PROCBASED2_UNRESTRICTED_GUEST)
#define	PROCBASED_CTLS2_ZERO_SETTING	0

#define	VM_EXIT_CTLS_ONE_SETTING					\
	(VM_EXIT_SAVE_DEBUG_CONTROLS		|			\
	VM_EXIT_HOST_LMA			|			\
	VM_EXIT_LOAD_PAT			|			\
	VM_EXIT_SAVE_EFER			|			\
	VM_EXIT_LOAD_EFER			|			\
	VM_EXIT_ACKNOWLEDGE_INTERRUPT)

#define	VM_EXIT_CTLS_ZERO_SETTING	0

#define	VM_ENTRY_CTLS_ONE_SETTING					\
	(VM_ENTRY_LOAD_DEBUG_CONTROLS		|			\
	VM_ENTRY_LOAD_EFER)

#define	VM_ENTRY_CTLS_ZERO_SETTING					\
	(VM_ENTRY_INTO_SMM			|			\
	VM_ENTRY_DEACTIVATE_DUAL_MONITOR)

#define	HANDLED		1
#define	UNHANDLED	0

static MALLOC_DEFINE(M_VMX, "vmx", "vmx");
static MALLOC_DEFINE(M_VLAPIC, "vlapic", "vlapic");

SYSCTL_DECL(_hw_vmm);
SYSCTL_NODE(_hw_vmm, OID_AUTO, vmx, CTLFLAG_RW | CTLFLAG_MPSAFE, NULL,
    NULL);

static uint32_t pinbased_ctls, procbased_ctls, procbased_ctls2;
static uint32_t exit_ctls, entry_ctls;

static uint64_t cr0_ones_mask, cr0_zeros_mask;

static uint64_t cr4_ones_mask, cr4_zeros_mask;

static int vmx_initialized;

/* Do not flush RSB upon vmexit */
static int no_flush_rsb;

/*
 * Optional capabilities
 */
#ifdef __FreeBSD__
SYSCTL_DECL(_hw_vmm_vmx);
static SYSCTL_NODE(_hw_vmm_vmx, OID_AUTO, cap,
    CTLFLAG_RW | CTLFLAG_MPSAFE, NULL,
    NULL);
#endif

/* HLT triggers a VM-exit */
static int cap_halt_exit;

/* PAUSE triggers a VM-exit */
static int cap_pause_exit;

/* Monitor trap flag */
static int cap_monitor_trap;

/* Guests are allowed to use INVPCID */
static int cap_invpcid;

/* Extra capabilities (VMX_CAP_*) beyond the minimum */
static enum vmx_caps vmx_capabilities;

/* APICv posted interrupt vector */
static int pirvec = -1;

#ifdef __FreeBSD__
static struct unrhdr *vpid_unr;
#endif /* __FreeBSD__ */
static uint_t vpid_alloc_failed;

int guest_l1d_flush;
int guest_l1d_flush_sw;

/* MSR save region is composed of an array of 'struct msr_entry' */
struct msr_entry {
	uint32_t	index;
	uint32_t	reserved;
	uint64_t	val;
};

static struct msr_entry msr_load_list[1] __aligned(16);

/*
 * The definitions of SDT probes for VMX.
 */

/* BEGIN CSTYLED */
SDT_PROBE_DEFINE3(vmm, vmx, exit, entry,
    "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE4(vmm, vmx, exit, taskswitch,
    "struct vmx *", "int", "struct vm_exit *", "struct vm_task_switch *");

SDT_PROBE_DEFINE4(vmm, vmx, exit, craccess,
    "struct vmx *", "int", "struct vm_exit *", "uint64_t");

SDT_PROBE_DEFINE4(vmm, vmx, exit, rdmsr,
    "struct vmx *", "int", "struct vm_exit *", "uint32_t");

SDT_PROBE_DEFINE5(vmm, vmx, exit, wrmsr,
    "struct vmx *", "int", "struct vm_exit *", "uint32_t", "uint64_t");

SDT_PROBE_DEFINE3(vmm, vmx, exit, halt,
    "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE3(vmm, vmx, exit, mtrap,
    "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE3(vmm, vmx, exit, pause,
    "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE3(vmm, vmx, exit, intrwindow,
    "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE4(vmm, vmx, exit, interrupt,
    "struct vmx *", "int", "struct vm_exit *", "uint32_t");

SDT_PROBE_DEFINE3(vmm, vmx, exit, nmiwindow,
    "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE3(vmm, vmx, exit, inout,
    "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE3(vmm, vmx, exit, cpuid,
    "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE5(vmm, vmx, exit, exception,
    "struct vmx *", "int", "struct vm_exit *", "uint32_t", "int");

SDT_PROBE_DEFINE5(vmm, vmx, exit, nestedfault,
    "struct vmx *", "int", "struct vm_exit *", "uint64_t", "uint64_t");

SDT_PROBE_DEFINE4(vmm, vmx, exit, mmiofault,
    "struct vmx *", "int", "struct vm_exit *", "uint64_t");

SDT_PROBE_DEFINE3(vmm, vmx, exit, eoi,
    "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE3(vmm, vmx, exit, apicaccess,
    "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE4(vmm, vmx, exit, apicwrite,
    "struct vmx *", "int", "struct vm_exit *", "struct vlapic *");

SDT_PROBE_DEFINE3(vmm, vmx, exit, xsetbv,
    "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE3(vmm, vmx, exit, monitor,
    "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE3(vmm, vmx, exit, mwait,
    "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE3(vmm, vmx, exit, vminsn,
    "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE4(vmm, vmx, exit, unknown,
    "struct vmx *", "int", "struct vm_exit *", "uint32_t");

SDT_PROBE_DEFINE4(vmm, vmx, exit, return,
    "struct vmx *", "int", "struct vm_exit *", "int");
/* END CSTYLED */

/*
 * Use the last page below 4GB as the APIC access address. This address is
 * occupied by the boot firmware so it is guaranteed that it will not conflict
 * with a page in system memory.
 */
#define	APIC_ACCESS_ADDRESS	0xFFFFF000

static int vmx_getdesc(void *arg, int vcpu, int reg, struct seg_desc *desc);
static int vmx_getreg(void *arg, int vcpu, int reg, uint64_t *retval);
static void vmx_apply_tsc_adjust(struct vmx *, int);
static void vmx_apicv_sync_tmr(struct vlapic *vlapic);
static void vmx_tpr_shadow_enter(struct vlapic *vlapic);
static void vmx_tpr_shadow_exit(struct vlapic *vlapic);

static int
vmx_allow_x2apic_msrs(struct vmx *vmx)
{
	int i, error;

	error = 0;

	/*
	 * Allow readonly access to the following x2APIC MSRs from the guest.
	 */
	error += guest_msr_ro(vmx, MSR_APIC_ID);
	error += guest_msr_ro(vmx, MSR_APIC_VERSION);
	error += guest_msr_ro(vmx, MSR_APIC_LDR);
	error += guest_msr_ro(vmx, MSR_APIC_SVR);

	for (i = 0; i < 8; i++)
		error += guest_msr_ro(vmx, MSR_APIC_ISR0 + i);

	for (i = 0; i < 8; i++)
		error += guest_msr_ro(vmx, MSR_APIC_TMR0 + i);

	for (i = 0; i < 8; i++)
		error += guest_msr_ro(vmx, MSR_APIC_IRR0 + i);

	error += guest_msr_ro(vmx, MSR_APIC_ESR);
	error += guest_msr_ro(vmx, MSR_APIC_LVT_TIMER);
	error += guest_msr_ro(vmx, MSR_APIC_LVT_THERMAL);
	error += guest_msr_ro(vmx, MSR_APIC_LVT_PCINT);
	error += guest_msr_ro(vmx, MSR_APIC_LVT_LINT0);
	error += guest_msr_ro(vmx, MSR_APIC_LVT_LINT1);
	error += guest_msr_ro(vmx, MSR_APIC_LVT_ERROR);
	error += guest_msr_ro(vmx, MSR_APIC_ICR_TIMER);
	error += guest_msr_ro(vmx, MSR_APIC_DCR_TIMER);
	error += guest_msr_ro(vmx, MSR_APIC_ICR);

	/*
	 * Allow TPR, EOI and SELF_IPI MSRs to be read and written by the guest.
	 *
	 * These registers get special treatment described in the section
	 * "Virtualizing MSR-Based APIC Accesses".
	 */
	error += guest_msr_rw(vmx, MSR_APIC_TPR);
	error += guest_msr_rw(vmx, MSR_APIC_EOI);
	error += guest_msr_rw(vmx, MSR_APIC_SELF_IPI);

	return (error);
}

static ulong_t
vmx_fix_cr0(ulong_t cr0)
{
	return ((cr0 | cr0_ones_mask) & ~cr0_zeros_mask);
}

static ulong_t
vmx_fix_cr4(ulong_t cr4)
{
	return ((cr4 | cr4_ones_mask) & ~cr4_zeros_mask);
}

static void
vpid_free(int vpid)
{
	if (vpid < 0 || vpid > 0xffff)
		panic("vpid_free: invalid vpid %d", vpid);

	/*
	 * VPIDs [0,VM_MAXCPU] are special and are not allocated from
	 * the unit number allocator.
	 */

	if (vpid > VM_MAXCPU)
#ifdef __FreeBSD__
		free_unr(vpid_unr, vpid);
#else
		hma_vmx_vpid_free((uint16_t)vpid);
#endif
}

static void
vpid_alloc(uint16_t *vpid, int num)
{
	int i, x;

	if (num <= 0 || num > VM_MAXCPU)
		panic("invalid number of vpids requested: %d", num);

	/*
	 * If the "enable vpid" execution control is not enabled then the
	 * VPID is required to be 0 for all vcpus.
	 */
	if ((procbased_ctls2 & PROCBASED2_ENABLE_VPID) == 0) {
		for (i = 0; i < num; i++)
			vpid[i] = 0;
		return;
	}

	/*
	 * Allocate a unique VPID for each vcpu from the unit number allocator.
	 */
	for (i = 0; i < num; i++) {
#ifdef __FreeBSD__
		x = alloc_unr(vpid_unr);
#else
		uint16_t tmp;

		tmp = hma_vmx_vpid_alloc();
		x = (tmp == 0) ? -1 : tmp;
#endif
		if (x == -1)
			break;
		else
			vpid[i] = x;
	}

	if (i < num) {
		atomic_add_int(&vpid_alloc_failed, 1);

		/*
		 * If the unit number allocator does not have enough unique
		 * VPIDs then we need to allocate from the [1,VM_MAXCPU] range.
		 *
		 * These VPIDs are not be unique across VMs but this does not
		 * affect correctness because the combined mappings are also
		 * tagged with the EP4TA which is unique for each VM.
		 *
		 * It is still sub-optimal because the invvpid will invalidate
		 * combined mappings for a particular VPID across all EP4TAs.
		 */
		while (i-- > 0)
			vpid_free(vpid[i]);

		for (i = 0; i < num; i++)
			vpid[i] = i + 1;
	}
}

static int
vmx_cleanup(void)
{
	/* This is taken care of by the hma registration */
	return (0);
}

static void
vmx_restore(void)
{
	/* No-op on illumos */
}

static int
vmx_init(int ipinum)
{
	int error;
	uint64_t fixed0, fixed1;
	uint32_t tmp;
	enum vmx_caps avail_caps = VMX_CAP_NONE;

	/* Check support for primary processor-based VM-execution controls */
	error = vmx_set_ctlreg(MSR_VMX_PROCBASED_CTLS,
	    MSR_VMX_TRUE_PROCBASED_CTLS,
	    PROCBASED_CTLS_ONE_SETTING,
	    PROCBASED_CTLS_ZERO_SETTING, &procbased_ctls);
	if (error) {
		printf("vmx_init: processor does not support desired primary "
		    "processor-based controls\n");
		return (error);
	}

	/* Clear the processor-based ctl bits that are set on demand */
	procbased_ctls &= ~PROCBASED_CTLS_WINDOW_SETTING;

	/* Check support for secondary processor-based VM-execution controls */
	error = vmx_set_ctlreg(MSR_VMX_PROCBASED_CTLS2,
	    MSR_VMX_PROCBASED_CTLS2,
	    PROCBASED_CTLS2_ONE_SETTING,
	    PROCBASED_CTLS2_ZERO_SETTING, &procbased_ctls2);
	if (error) {
		printf("vmx_init: processor does not support desired secondary "
		    "processor-based controls\n");
		return (error);
	}

	/* Check support for VPID */
	error = vmx_set_ctlreg(MSR_VMX_PROCBASED_CTLS2,
	    MSR_VMX_PROCBASED_CTLS2,
	    PROCBASED2_ENABLE_VPID,
	    0, &tmp);
	if (error == 0)
		procbased_ctls2 |= PROCBASED2_ENABLE_VPID;

	/* Check support for pin-based VM-execution controls */
	error = vmx_set_ctlreg(MSR_VMX_PINBASED_CTLS,
	    MSR_VMX_TRUE_PINBASED_CTLS,
	    PINBASED_CTLS_ONE_SETTING,
	    PINBASED_CTLS_ZERO_SETTING, &pinbased_ctls);
	if (error) {
		printf("vmx_init: processor does not support desired "
		    "pin-based controls\n");
		return (error);
	}

	/* Check support for VM-exit controls */
	error = vmx_set_ctlreg(MSR_VMX_EXIT_CTLS, MSR_VMX_TRUE_EXIT_CTLS,
	    VM_EXIT_CTLS_ONE_SETTING,
	    VM_EXIT_CTLS_ZERO_SETTING,
	    &exit_ctls);
	if (error) {
		printf("vmx_init: processor does not support desired "
		    "exit controls\n");
		return (error);
	}

	/* Check support for VM-entry controls */
	error = vmx_set_ctlreg(MSR_VMX_ENTRY_CTLS, MSR_VMX_TRUE_ENTRY_CTLS,
	    VM_ENTRY_CTLS_ONE_SETTING, VM_ENTRY_CTLS_ZERO_SETTING,
	    &entry_ctls);
	if (error) {
		printf("vmx_init: processor does not support desired "
		    "entry controls\n");
		return (error);
	}

	/*
	 * Check support for optional features by testing them
	 * as individual bits
	 */
	cap_halt_exit = (vmx_set_ctlreg(MSR_VMX_PROCBASED_CTLS,
	    MSR_VMX_TRUE_PROCBASED_CTLS,
	    PROCBASED_HLT_EXITING, 0,
	    &tmp) == 0);

	cap_monitor_trap = (vmx_set_ctlreg(MSR_VMX_PROCBASED_CTLS,
	    MSR_VMX_PROCBASED_CTLS,
	    PROCBASED_MTF, 0,
	    &tmp) == 0);

	cap_pause_exit = (vmx_set_ctlreg(MSR_VMX_PROCBASED_CTLS,
	    MSR_VMX_TRUE_PROCBASED_CTLS,
	    PROCBASED_PAUSE_EXITING, 0,
	    &tmp) == 0);

	cap_invpcid = (vmx_set_ctlreg(MSR_VMX_PROCBASED_CTLS2,
	    MSR_VMX_PROCBASED_CTLS2, PROCBASED2_ENABLE_INVPCID, 0,
	    &tmp) == 0);

	/*
	 * Check for APIC virtualization capabilities:
	 * - TPR shadowing
	 * - Full APICv (with or without x2APIC support)
	 * - Posted interrupt handling
	 */
	if (vmx_set_ctlreg(MSR_VMX_PROCBASED_CTLS, MSR_VMX_TRUE_PROCBASED_CTLS,
	    PROCBASED_USE_TPR_SHADOW, 0, &tmp) == 0) {
		avail_caps |= VMX_CAP_TPR_SHADOW;

		const uint32_t apicv_bits =
		    PROCBASED2_VIRTUALIZE_APIC_ACCESSES |
		    PROCBASED2_APIC_REGISTER_VIRTUALIZATION |
		    PROCBASED2_VIRTUALIZE_X2APIC_MODE |
		    PROCBASED2_VIRTUAL_INTERRUPT_DELIVERY;
		if (vmx_set_ctlreg(MSR_VMX_PROCBASED_CTLS2,
		    MSR_VMX_PROCBASED_CTLS2, apicv_bits, 0, &tmp) == 0) {
			avail_caps |= VMX_CAP_APICV;

			/*
			 * It may make sense in the future to differentiate
			 * hardware (or software) configurations with APICv but
			 * no support for accelerating x2APIC mode.
			 */
			avail_caps |= VMX_CAP_APICV_X2APIC;

			error = vmx_set_ctlreg(MSR_VMX_PINBASED_CTLS,
			    MSR_VMX_TRUE_PINBASED_CTLS,
			    PINBASED_POSTED_INTERRUPT, 0, &tmp);
			if (error == 0) {
				/*
				 * If the PSM-provided interfaces for requesting
				 * and using a PIR IPI vector are present, use
				 * them for posted interrupts.
				 */
				if (psm_get_pir_ipivect != NULL &&
				    psm_send_pir_ipi != NULL) {
					pirvec = psm_get_pir_ipivect();
					avail_caps |= VMX_CAP_APICV_PIR;
				}
			}
		}
	}

	/* Initialize EPT */
	error = ept_init(ipinum);
	if (error) {
		printf("vmx_init: ept initialization failed (%d)\n", error);
		return (error);
	}

#ifdef __FreeBSD__
	guest_l1d_flush = (cpu_ia32_arch_caps &
	    IA32_ARCH_CAP_SKIP_L1DFL_VMENTRY) == 0;
	TUNABLE_INT_FETCH("hw.vmm.l1d_flush", &guest_l1d_flush);

	/*
	 * L1D cache flush is enabled.  Use IA32_FLUSH_CMD MSR when
	 * available.  Otherwise fall back to the software flush
	 * method which loads enough data from the kernel text to
	 * flush existing L1D content, both on VMX entry and on NMI
	 * return.
	 */
	if (guest_l1d_flush) {
		if ((cpu_stdext_feature3 & CPUID_STDEXT3_L1D_FLUSH) == 0) {
			guest_l1d_flush_sw = 1;
			TUNABLE_INT_FETCH("hw.vmm.l1d_flush_sw",
			    &guest_l1d_flush_sw);
		}
		if (guest_l1d_flush_sw) {
			if (nmi_flush_l1d_sw <= 1)
				nmi_flush_l1d_sw = 1;
		} else {
			msr_load_list[0].index = MSR_IA32_FLUSH_CMD;
			msr_load_list[0].val = IA32_FLUSH_CMD_L1D;
		}
	}
#else
	/* L1D flushing is taken care of by smt_acquire() and friends */
	guest_l1d_flush = 0;
#endif /* __FreeBSD__ */

	/*
	 * Stash the cr0 and cr4 bits that must be fixed to 0 or 1
	 */
	fixed0 = rdmsr(MSR_VMX_CR0_FIXED0);
	fixed1 = rdmsr(MSR_VMX_CR0_FIXED1);
	cr0_ones_mask = fixed0 & fixed1;
	cr0_zeros_mask = ~fixed0 & ~fixed1;

	/*
	 * Since Unrestricted Guest was already verified present, CR0_PE and
	 * CR0_PG are allowed to be set to zero in VMX non-root operation
	 */
	cr0_ones_mask &= ~(CR0_PG | CR0_PE);

	/*
	 * Do not allow the guest to set CR0_NW or CR0_CD.
	 */
	cr0_zeros_mask |= (CR0_NW | CR0_CD);

	fixed0 = rdmsr(MSR_VMX_CR4_FIXED0);
	fixed1 = rdmsr(MSR_VMX_CR4_FIXED1);
	cr4_ones_mask = fixed0 & fixed1;
	cr4_zeros_mask = ~fixed0 & ~fixed1;

	vmx_msr_init();

	vmx_capabilities = avail_caps;
	vmx_initialized = 1;

	return (0);
}

static void
vmx_trigger_hostintr(int vector)
{
#ifdef __FreeBSD__
	uintptr_t func;
	struct gate_descriptor *gd;

	gd = &idt[vector];

	KASSERT(vector >= 32 && vector <= 255, ("vmx_trigger_hostintr: "
	    "invalid vector %d", vector));
	KASSERT(gd->gd_p == 1, ("gate descriptor for vector %d not present",
	    vector));
	KASSERT(gd->gd_type == SDT_SYSIGT, ("gate descriptor for vector %d "
	    "has invalid type %d", vector, gd->gd_type));
	KASSERT(gd->gd_dpl == SEL_KPL, ("gate descriptor for vector %d "
	    "has invalid dpl %d", vector, gd->gd_dpl));
	KASSERT(gd->gd_selector == GSEL(GCODE_SEL, SEL_KPL), ("gate descriptor "
	    "for vector %d has invalid selector %d", vector, gd->gd_selector));
	KASSERT(gd->gd_ist == 0, ("gate descriptor for vector %d has invalid "
	    "IST %d", vector, gd->gd_ist));

	func = ((long)gd->gd_hioffset << 16 | gd->gd_looffset);
	vmx_call_isr(func);
#else
	VERIFY(vector >= 32 && vector <= 255);
	vmx_call_isr(vector - 32);
#endif /* __FreeBSD__ */
}

static void *
vmx_vminit(struct vm *vm, pmap_t pmap)
{
	uint16_t vpid[VM_MAXCPU];
	int i, error, datasel;
	struct vmx *vmx;
	uint32_t exc_bitmap;
	uint16_t maxcpus;
	uint32_t proc_ctls, proc2_ctls, pin_ctls;

	vmx = malloc(sizeof (struct vmx), M_VMX, M_WAITOK | M_ZERO);
	if ((uintptr_t)vmx & PAGE_MASK) {
		panic("malloc of struct vmx not aligned on %d byte boundary",
		    PAGE_SIZE);
	}
	vmx->vm = vm;

	vmx->eptp = eptp(vtophys((vm_offset_t)pmap->pm_pml4));

	/*
	 * Clean up EPTP-tagged guest physical and combined mappings
	 *
	 * VMX transitions are not required to invalidate any guest physical
	 * mappings. So, it may be possible for stale guest physical mappings
	 * to be present in the processor TLBs.
	 *
	 * Combined mappings for this EP4TA are also invalidated for all VPIDs.
	 */
	ept_invalidate_mappings(vmx->eptp);

	msr_bitmap_initialize(vmx->msr_bitmap);

	/*
	 * It is safe to allow direct access to MSR_GSBASE and MSR_FSBASE.
	 * The guest FSBASE and GSBASE are saved and restored during
	 * vm-exit and vm-entry respectively. The host FSBASE and GSBASE are
	 * always restored from the vmcs host state area on vm-exit.
	 *
	 * The SYSENTER_CS/ESP/EIP MSRs are identical to FS/GSBASE in
	 * how they are saved/restored so can be directly accessed by the
	 * guest.
	 *
	 * MSR_EFER is saved and restored in the guest VMCS area on a
	 * VM exit and entry respectively. It is also restored from the
	 * host VMCS area on a VM exit.
	 *
	 * The TSC MSR is exposed read-only. Writes are disallowed as
	 * that will impact the host TSC.  If the guest does a write
	 * the "use TSC offsetting" execution control is enabled and the
	 * difference between the host TSC and the guest TSC is written
	 * into the TSC offset in the VMCS.
	 */
	if (guest_msr_rw(vmx, MSR_GSBASE) ||
	    guest_msr_rw(vmx, MSR_FSBASE) ||
	    guest_msr_rw(vmx, MSR_SYSENTER_CS_MSR) ||
	    guest_msr_rw(vmx, MSR_SYSENTER_ESP_MSR) ||
	    guest_msr_rw(vmx, MSR_SYSENTER_EIP_MSR) ||
	    guest_msr_rw(vmx, MSR_EFER) ||
	    guest_msr_ro(vmx, MSR_TSC))
		panic("vmx_vminit: error setting guest msr access");

	vpid_alloc(vpid, VM_MAXCPU);

	/* Grab the established defaults */
	proc_ctls = procbased_ctls;
	proc2_ctls = procbased_ctls2;
	pin_ctls = pinbased_ctls;
	/* For now, default to the available capabilities */
	vmx->vmx_caps = vmx_capabilities;

	if (vmx_cap_en(vmx, VMX_CAP_TPR_SHADOW)) {
		proc_ctls |= PROCBASED_USE_TPR_SHADOW;
		proc_ctls &= ~PROCBASED_CR8_LOAD_EXITING;
		proc_ctls &= ~PROCBASED_CR8_STORE_EXITING;
	}
	if (vmx_cap_en(vmx, VMX_CAP_APICV)) {
		ASSERT(vmx_cap_en(vmx, VMX_CAP_TPR_SHADOW));

		proc2_ctls |= (PROCBASED2_VIRTUALIZE_APIC_ACCESSES |
		    PROCBASED2_APIC_REGISTER_VIRTUALIZATION |
		    PROCBASED2_VIRTUAL_INTERRUPT_DELIVERY);

		error = vm_map_mmio(vm, DEFAULT_APIC_BASE, PAGE_SIZE,
		    APIC_ACCESS_ADDRESS);
		/* XXX this should really return an error to the caller */
		KASSERT(error == 0, ("vm_map_mmio(apicbase) error %d", error));
	}
	if (vmx_cap_en(vmx, VMX_CAP_APICV_PIR)) {
		ASSERT(vmx_cap_en(vmx, VMX_CAP_APICV));

		pin_ctls |= PINBASED_POSTED_INTERRUPT;
	}

	maxcpus = vm_get_maxcpus(vm);
	datasel = vmm_get_host_datasel();
	for (i = 0; i < maxcpus; i++) {
		/*
		 * Cache physical address lookups for various components which
		 * may be required inside the critical_enter() section implied
		 * by VMPTRLD() below.
		 */
		vm_paddr_t msr_bitmap_pa = vtophys(vmx->msr_bitmap);
		vm_paddr_t apic_page_pa = vtophys(&vmx->apic_page[i]);
		vm_paddr_t pir_desc_pa = vtophys(&vmx->pir_desc[i]);

		vmx->vmcs_pa[i] = (uintptr_t)vtophys(&vmx->vmcs[i]);
		vmcs_initialize(&vmx->vmcs[i], vmx->vmcs_pa[i]);

		vmx_msr_guest_init(vmx, i);

		vmcs_load(vmx->vmcs_pa[i]);

		vmcs_write(VMCS_HOST_IA32_PAT, vmm_get_host_pat());
		vmcs_write(VMCS_HOST_IA32_EFER, vmm_get_host_efer());

		/* Load the control registers */
		vmcs_write(VMCS_HOST_CR0, vmm_get_host_cr0());
		vmcs_write(VMCS_HOST_CR4, vmm_get_host_cr4() | CR4_VMXE);

		/* Load the segment selectors */
		vmcs_write(VMCS_HOST_CS_SELECTOR, vmm_get_host_codesel());

		vmcs_write(VMCS_HOST_ES_SELECTOR, datasel);
		vmcs_write(VMCS_HOST_SS_SELECTOR, datasel);
		vmcs_write(VMCS_HOST_DS_SELECTOR, datasel);

		vmcs_write(VMCS_HOST_FS_SELECTOR, vmm_get_host_fssel());
		vmcs_write(VMCS_HOST_GS_SELECTOR, vmm_get_host_gssel());
		vmcs_write(VMCS_HOST_TR_SELECTOR, vmm_get_host_tsssel());

		/*
		 * Configure host sysenter MSRs to be restored on VM exit.
		 * The thread-specific MSR_INTC_SEP_ESP value is loaded in
		 * vmx_run.
		 */
		vmcs_write(VMCS_HOST_IA32_SYSENTER_CS, KCS_SEL);
		vmcs_write(VMCS_HOST_IA32_SYSENTER_EIP,
		    rdmsr(MSR_SYSENTER_EIP_MSR));

		/* instruction pointer */
		if (no_flush_rsb) {
			vmcs_write(VMCS_HOST_RIP, (uint64_t)vmx_exit_guest);
		} else {
			vmcs_write(VMCS_HOST_RIP,
			    (uint64_t)vmx_exit_guest_flush_rsb);
		}

		/* link pointer */
		vmcs_write(VMCS_LINK_POINTER, ~0);

		vmcs_write(VMCS_EPTP, vmx->eptp);
		vmcs_write(VMCS_PIN_BASED_CTLS, pin_ctls);
		vmcs_write(VMCS_PRI_PROC_BASED_CTLS, proc_ctls);
		vmcs_write(VMCS_SEC_PROC_BASED_CTLS, proc2_ctls);
		vmcs_write(VMCS_EXIT_CTLS, exit_ctls);
		vmcs_write(VMCS_ENTRY_CTLS, entry_ctls);
		vmcs_write(VMCS_MSR_BITMAP, msr_bitmap_pa);
		vmcs_write(VMCS_VPID, vpid[i]);

		if (guest_l1d_flush && !guest_l1d_flush_sw) {
			vmcs_write(VMCS_ENTRY_MSR_LOAD, pmap_kextract(
			    (vm_offset_t)&msr_load_list[0]));
			vmcs_write(VMCS_ENTRY_MSR_LOAD_COUNT,
			    nitems(msr_load_list));
			vmcs_write(VMCS_EXIT_MSR_STORE, 0);
			vmcs_write(VMCS_EXIT_MSR_STORE_COUNT, 0);
		}

		/* exception bitmap */
		if (vcpu_trace_exceptions(vm, i))
			exc_bitmap = 0xffffffff;
		else
			exc_bitmap = 1 << IDT_MC;
		vmcs_write(VMCS_EXCEPTION_BITMAP, exc_bitmap);

		vmx->ctx[i].guest_dr6 = DBREG_DR6_RESERVED1;
		vmcs_write(VMCS_GUEST_DR7, DBREG_DR7_RESERVED1);

		if (vmx_cap_en(vmx, VMX_CAP_TPR_SHADOW)) {
			vmcs_write(VMCS_VIRTUAL_APIC, apic_page_pa);
		}

		if (vmx_cap_en(vmx, VMX_CAP_APICV)) {
			vmcs_write(VMCS_APIC_ACCESS, APIC_ACCESS_ADDRESS);
			vmcs_write(VMCS_EOI_EXIT0, 0);
			vmcs_write(VMCS_EOI_EXIT1, 0);
			vmcs_write(VMCS_EOI_EXIT2, 0);
			vmcs_write(VMCS_EOI_EXIT3, 0);
		}
		if (vmx_cap_en(vmx, VMX_CAP_APICV_PIR)) {
			vmcs_write(VMCS_PIR_VECTOR, pirvec);
			vmcs_write(VMCS_PIR_DESC, pir_desc_pa);
		}

		/*
		 * Set up the CR0/4 masks and configure the read shadow state
		 * to the power-on register value from the Intel Sys Arch.
		 *  CR0 - 0x60000010
		 *  CR4 - 0
		 */
		vmcs_write(VMCS_CR0_MASK, cr0_ones_mask | cr0_zeros_mask);
		vmcs_write(VMCS_CR0_SHADOW, 0x60000010);
		vmcs_write(VMCS_CR4_MASK, cr4_ones_mask | cr4_zeros_mask);
		vmcs_write(VMCS_CR4_SHADOW, 0);

		vmcs_clear(vmx->vmcs_pa[i]);

		vmx->cap[i].set = 0;
		vmx->cap[i].proc_ctls = proc_ctls;
		vmx->cap[i].proc_ctls2 = proc2_ctls;
		vmx->cap[i].exc_bitmap = exc_bitmap;

		vmx->state[i].nextrip = ~0;
		vmx->state[i].lastcpu = NOCPU;
		vmx->state[i].vpid = vpid[i];


		vmx->ctx[i].pmap = pmap;
	}

	return (vmx);
}

static int
vmx_handle_cpuid(struct vm *vm, int vcpu, struct vmxctx *vmxctx)
{
#ifdef __FreeBSD__
	int handled, func;

	func = vmxctx->guest_rax;
#else
	int handled;
#endif

	handled = x86_emulate_cpuid(vm, vcpu, (uint64_t *)&vmxctx->guest_rax,
	    (uint64_t *)&vmxctx->guest_rbx, (uint64_t *)&vmxctx->guest_rcx,
	    (uint64_t *)&vmxctx->guest_rdx);
	return (handled);
}

static __inline void
vmx_run_trace(struct vmx *vmx, int vcpu)
{
#ifdef KTR
	VCPU_CTR1(vmx->vm, vcpu, "Resume execution at %lx", vmcs_guest_rip());
#endif
}

static __inline void
vmx_astpending_trace(struct vmx *vmx, int vcpu, uint64_t rip)
{
#ifdef KTR
	VCPU_CTR1(vmx->vm, vcpu, "astpending vmexit at 0x%0lx", rip);
#endif
}

static VMM_STAT_INTEL(VCPU_INVVPID_SAVED, "Number of vpid invalidations saved");
static VMM_STAT_INTEL(VCPU_INVVPID_DONE, "Number of vpid invalidations done");

#define	INVVPID_TYPE_ADDRESS		0UL
#define	INVVPID_TYPE_SINGLE_CONTEXT	1UL
#define	INVVPID_TYPE_ALL_CONTEXTS	2UL

struct invvpid_desc {
	uint16_t	vpid;
	uint16_t	_res1;
	uint32_t	_res2;
	uint64_t	linear_addr;
};
CTASSERT(sizeof (struct invvpid_desc) == 16);

static __inline void
invvpid(uint64_t type, struct invvpid_desc desc)
{
	int error;

	__asm __volatile("invvpid %[desc], %[type];"
	    VMX_SET_ERROR_CODE_ASM
	    : [error] "=r" (error)
	    : [desc] "m" (desc), [type] "r" (type)
	    : "memory");

	if (error)
		panic("invvpid error %d", error);
}

/*
 * Invalidate guest mappings identified by its vpid from the TLB.
 */
static __inline void
vmx_invvpid(struct vmx *vmx, int vcpu, pmap_t pmap, int running)
{
	struct vmxstate *vmxstate;
	struct invvpid_desc invvpid_desc;

	vmxstate = &vmx->state[vcpu];
	if (vmxstate->vpid == 0)
		return;

	if (!running) {
		/*
		 * Set the 'lastcpu' to an invalid host cpu.
		 *
		 * This will invalidate TLB entries tagged with the vcpu's
		 * vpid the next time it runs via vmx_set_pcpu_defaults().
		 */
		vmxstate->lastcpu = NOCPU;
		return;
	}

#ifdef __FreeBSD__
	KASSERT(curthread->td_critnest > 0, ("%s: vcpu %d running outside "
	    "critical section", __func__, vcpu));
#endif

	/*
	 * Invalidate all mappings tagged with 'vpid'
	 *
	 * We do this because this vcpu was executing on a different host
	 * cpu when it last ran. We do not track whether it invalidated
	 * mappings associated with its 'vpid' during that run. So we must
	 * assume that the mappings associated with 'vpid' on 'curcpu' are
	 * stale and invalidate them.
	 *
	 * Note that we incur this penalty only when the scheduler chooses to
	 * move the thread associated with this vcpu between host cpus.
	 *
	 * Note also that this will invalidate mappings tagged with 'vpid'
	 * for "all" EP4TAs.
	 */
	if (pmap->pm_eptgen == vmx->eptgen[curcpu]) {
		invvpid_desc._res1 = 0;
		invvpid_desc._res2 = 0;
		invvpid_desc.vpid = vmxstate->vpid;
		invvpid_desc.linear_addr = 0;
		invvpid(INVVPID_TYPE_SINGLE_CONTEXT, invvpid_desc);
		vmm_stat_incr(vmx->vm, vcpu, VCPU_INVVPID_DONE, 1);
	} else {
		/*
		 * The invvpid can be skipped if an invept is going to
		 * be performed before entering the guest. The invept
		 * will invalidate combined mappings tagged with
		 * 'vmx->eptp' for all vpids.
		 */
		vmm_stat_incr(vmx->vm, vcpu, VCPU_INVVPID_SAVED, 1);
	}
}

static void
vmx_set_pcpu_defaults(struct vmx *vmx, int vcpu, pmap_t pmap)
{
	struct vmxstate *vmxstate;

	/*
	 * Regardless of whether the VM appears to have migrated between CPUs,
	 * save the host sysenter stack pointer.  As it points to the kernel
	 * stack of each thread, the correct value must be maintained for every
	 * trip into the critical section.
	 */
	vmcs_write(VMCS_HOST_IA32_SYSENTER_ESP, rdmsr(MSR_SYSENTER_ESP_MSR));

	/*
	 * Perform any needed TSC_OFFSET adjustment based on TSC_MSR writes or
	 * migration between host CPUs with differing TSC values.
	 */
	vmx_apply_tsc_adjust(vmx, vcpu);

	vmxstate = &vmx->state[vcpu];
	if (vmxstate->lastcpu == curcpu)
		return;

	vmxstate->lastcpu = curcpu;

	vmm_stat_incr(vmx->vm, vcpu, VCPU_MIGRATIONS, 1);

	/* Load the per-CPU IDT address */
	vmcs_write(VMCS_HOST_IDTR_BASE, vmm_get_host_idtrbase());
	vmcs_write(VMCS_HOST_TR_BASE, vmm_get_host_trbase());
	vmcs_write(VMCS_HOST_GDTR_BASE, vmm_get_host_gdtrbase());
	vmcs_write(VMCS_HOST_GS_BASE, vmm_get_host_gsbase());
	vmx_invvpid(vmx, vcpu, pmap, 1);
}

/*
 * We depend on 'procbased_ctls' to have the Interrupt Window Exiting bit set.
 */
CTASSERT((PROCBASED_CTLS_ONE_SETTING & PROCBASED_INT_WINDOW_EXITING) != 0);

static __inline void
vmx_set_int_window_exiting(struct vmx *vmx, int vcpu)
{

	if ((vmx->cap[vcpu].proc_ctls & PROCBASED_INT_WINDOW_EXITING) == 0) {
		vmx->cap[vcpu].proc_ctls |= PROCBASED_INT_WINDOW_EXITING;
		vmcs_write(VMCS_PRI_PROC_BASED_CTLS, vmx->cap[vcpu].proc_ctls);
		VCPU_CTR0(vmx->vm, vcpu, "Enabling interrupt window exiting");
	}
}

static __inline void
vmx_clear_int_window_exiting(struct vmx *vmx, int vcpu)
{

	KASSERT((vmx->cap[vcpu].proc_ctls & PROCBASED_INT_WINDOW_EXITING) != 0,
	    ("intr_window_exiting not set: %x", vmx->cap[vcpu].proc_ctls));
	vmx->cap[vcpu].proc_ctls &= ~PROCBASED_INT_WINDOW_EXITING;
	vmcs_write(VMCS_PRI_PROC_BASED_CTLS, vmx->cap[vcpu].proc_ctls);
	VCPU_CTR0(vmx->vm, vcpu, "Disabling interrupt window exiting");
}

static __inline bool
vmx_nmi_window_exiting(struct vmx *vmx, int vcpu)
{
	return ((vmx->cap[vcpu].proc_ctls & PROCBASED_NMI_WINDOW_EXITING) != 0);
}

static __inline void
vmx_set_nmi_window_exiting(struct vmx *vmx, int vcpu)
{
	if (!vmx_nmi_window_exiting(vmx, vcpu)) {
		vmx->cap[vcpu].proc_ctls |= PROCBASED_NMI_WINDOW_EXITING;
		vmcs_write(VMCS_PRI_PROC_BASED_CTLS, vmx->cap[vcpu].proc_ctls);
	}
}

static __inline void
vmx_clear_nmi_window_exiting(struct vmx *vmx, int vcpu)
{
	ASSERT(vmx_nmi_window_exiting(vmx, vcpu));
	vmx->cap[vcpu].proc_ctls &= ~PROCBASED_NMI_WINDOW_EXITING;
	vmcs_write(VMCS_PRI_PROC_BASED_CTLS, vmx->cap[vcpu].proc_ctls);
}

/*
 * Set the TSC adjustment, taking into account the offsets measured between
 * host physical CPUs.  This is required even if the guest has not set a TSC
 * offset since vCPUs inherit the TSC offset of whatever physical CPU it has
 * migrated onto.  Without this mitigation, un-synched host TSCs will convey
 * the appearance of TSC time-travel to the guest as its vCPUs migrate.
 */
static void
vmx_apply_tsc_adjust(struct vmx *vmx, int vcpu)
{
	const uint64_t offset = vcpu_tsc_offset(vmx->vm, vcpu, true);

	ASSERT(vmx->cap[vcpu].proc_ctls & PROCBASED_TSC_OFFSET);

	if (vmx->tsc_offset_active[vcpu] != offset) {
		vmcs_write(VMCS_TSC_OFFSET, offset);
		vmx->tsc_offset_active[vcpu] = offset;
	}
}

#define	NMI_BLOCKING	(VMCS_INTERRUPTIBILITY_NMI_BLOCKING |		\
			VMCS_INTERRUPTIBILITY_MOVSS_BLOCKING)
#define	HWINTR_BLOCKING	(VMCS_INTERRUPTIBILITY_STI_BLOCKING |		\
			VMCS_INTERRUPTIBILITY_MOVSS_BLOCKING)

static void
vmx_inject_nmi(struct vmx *vmx, int vcpu)
{
	ASSERT0(vmcs_read(VMCS_GUEST_INTERRUPTIBILITY) & NMI_BLOCKING);
	ASSERT0(vmcs_read(VMCS_ENTRY_INTR_INFO) & VMCS_INTR_VALID);

	/*
	 * Inject the virtual NMI. The vector must be the NMI IDT entry
	 * or the VMCS entry check will fail.
	 */
	vmcs_write(VMCS_ENTRY_INTR_INFO,
	    IDT_NMI | VMCS_INTR_T_NMI | VMCS_INTR_VALID);

	/* Clear the request */
	vm_nmi_clear(vmx->vm, vcpu);
}

/*
 * Inject exceptions, NMIs, and ExtINTs.
 *
 * The logic behind these are complicated and may involve mutex contention, so
 * the injection is performed without the protection of host CPU interrupts
 * being disabled.  This means a racing notification could be "lost",
 * necessitating a later call to vmx_inject_recheck() to close that window
 * of opportunity.
 */
static enum event_inject_state
vmx_inject_events(struct vmx *vmx, int vcpu, uint64_t rip)
{
	uint64_t entryinfo;
	uint32_t gi, info;
	int vector;
	enum event_inject_state state;

	gi = vmcs_read(VMCS_GUEST_INTERRUPTIBILITY);
	info = vmcs_read(VMCS_ENTRY_INTR_INFO);
	state = EIS_CAN_INJECT;

	/* Clear any interrupt blocking if the guest %rip has changed */
	if (vmx->state[vcpu].nextrip != rip && (gi & HWINTR_BLOCKING) != 0) {
		gi &= ~HWINTR_BLOCKING;
		vmcs_write(VMCS_GUEST_INTERRUPTIBILITY, gi);
	}

	/*
	 * It could be that an interrupt is already pending for injection from
	 * the VMCS.  This would be the case if the vCPU exited for conditions
	 * such as an AST before a vm-entry delivered the injection.
	 */
	if ((info & VMCS_INTR_VALID) != 0) {
		return (EIS_EV_EXISTING | EIS_REQ_EXIT);
	}

	if (vm_entry_intinfo(vmx->vm, vcpu, &entryinfo)) {
		ASSERT(entryinfo & VMCS_INTR_VALID);

		info = entryinfo;
		vector = info & 0xff;
		if (vector == IDT_BP || vector == IDT_OF) {
			/*
			 * VT-x requires #BP and #OF to be injected as software
			 * exceptions.
			 */
			info &= ~VMCS_INTR_T_MASK;
			info |= VMCS_INTR_T_SWEXCEPTION;
		}

		if (info & VMCS_INTR_DEL_ERRCODE) {
			vmcs_write(VMCS_ENTRY_EXCEPTION_ERROR, entryinfo >> 32);
		}

		vmcs_write(VMCS_ENTRY_INTR_INFO, info);
		state = EIS_EV_INJECTED;
	}

	if (vm_nmi_pending(vmx->vm, vcpu)) {
		/*
		 * If there are no conditions blocking NMI injection then inject
		 * it directly here otherwise enable "NMI window exiting" to
		 * inject it as soon as we can.
		 *
		 * According to the Intel manual, some CPUs do not allow NMI
		 * injection when STI_BLOCKING is active.  That check is
		 * enforced here, regardless of CPU capability.  If running on a
		 * CPU without such a restriction it will immediately exit and
		 * the NMI will be injected in the "NMI window exiting" handler.
		 */
		if ((gi & (HWINTR_BLOCKING | NMI_BLOCKING)) == 0) {
			if (state == EIS_CAN_INJECT) {
				vmx_inject_nmi(vmx, vcpu);
				state = EIS_EV_INJECTED;
			} else {
				return (state | EIS_REQ_EXIT);
			}
		} else {
			vmx_set_nmi_window_exiting(vmx, vcpu);
		}
	}

	if (vm_extint_pending(vmx->vm, vcpu)) {
		if (state != EIS_CAN_INJECT) {
			return (state | EIS_REQ_EXIT);
		}
		if ((gi & HWINTR_BLOCKING) != 0 ||
		    (vmcs_read(VMCS_GUEST_RFLAGS) & PSL_I) == 0) {
			return (EIS_GI_BLOCK);
		}

		/* Ask the legacy pic for a vector to inject */
		vatpic_pending_intr(vmx->vm, &vector);

		/*
		 * From the Intel SDM, Volume 3, Section "Maskable
		 * Hardware Interrupts":
		 * - maskable interrupt vectors [0,255] can be delivered
		 *   through the INTR pin.
		 */
		KASSERT(vector >= 0 && vector <= 255,
		    ("invalid vector %d from INTR", vector));

		/* Inject the interrupt */
		vmcs_write(VMCS_ENTRY_INTR_INFO,
		    VMCS_INTR_T_HWINTR | VMCS_INTR_VALID | vector);

		vm_extint_clear(vmx->vm, vcpu);
		vatpic_intr_accepted(vmx->vm, vector);
		state = EIS_EV_INJECTED;
	}

	return (state);
}

/*
 * Inject any interrupts pending on the vLAPIC.
 *
 * This is done with host CPU interrupts disabled so notification IPIs, either
 * from the standard vCPU notification or APICv posted interrupts, will be
 * queued on the host APIC and recognized when entering VMX context.
 */
static enum event_inject_state
vmx_inject_vlapic(struct vmx *vmx, int vcpu, struct vlapic *vlapic)
{
	int vector;

	if (!vlapic_pending_intr(vlapic, &vector)) {
		return (EIS_CAN_INJECT);
	}

	/*
	 * From the Intel SDM, Volume 3, Section "Maskable
	 * Hardware Interrupts":
	 * - maskable interrupt vectors [16,255] can be delivered
	 *   through the local APIC.
	 */
	KASSERT(vector >= 16 && vector <= 255,
	    ("invalid vector %d from local APIC", vector));

	if (vmx_cap_en(vmx, VMX_CAP_APICV)) {
		uint16_t status_old = vmcs_read(VMCS_GUEST_INTR_STATUS);
		uint16_t status_new = (status_old & 0xff00) | vector;

		/*
		 * The APICv state will have been synced into the vLAPIC
		 * as part of vlapic_pending_intr().  Prepare the VMCS
		 * for the to-be-injected pending interrupt.
		 */
		if (status_new > status_old) {
			vmcs_write(VMCS_GUEST_INTR_STATUS, status_new);
			VCPU_CTR2(vlapic->vm, vlapic->vcpuid,
			    "vmx_inject_interrupts: guest_intr_status "
			    "changed from 0x%04x to 0x%04x",
			    status_old, status_new);
		}

		/*
		 * Ensure VMCS state regarding EOI traps is kept in sync
		 * with the TMRs in the vlapic.
		 */
		vmx_apicv_sync_tmr(vlapic);

		/*
		 * The rest of the injection process for injecting the
		 * interrupt(s) is handled by APICv. It does not preclude other
		 * event injection from occurring.
		 */
		return (EIS_CAN_INJECT);
	}

	ASSERT0(vmcs_read(VMCS_ENTRY_INTR_INFO) & VMCS_INTR_VALID);

	/* Does guest interruptability block injection? */
	if ((vmcs_read(VMCS_GUEST_INTERRUPTIBILITY) & HWINTR_BLOCKING) != 0 ||
	    (vmcs_read(VMCS_GUEST_RFLAGS) & PSL_I) == 0) {
		return (EIS_GI_BLOCK);
	}

	/* Inject the interrupt */
	vmcs_write(VMCS_ENTRY_INTR_INFO,
	    VMCS_INTR_T_HWINTR | VMCS_INTR_VALID | vector);

	/* Update the Local APIC ISR */
	vlapic_intr_accepted(vlapic, vector);

	return (EIS_EV_INJECTED);
}

/*
 * Re-check for events to be injected.
 *
 * Once host CPU interrupts are disabled, check for the presence of any events
 * which require injection processing.  If an exit is required upon injection,
 * or once the guest becomes interruptable, that will be configured too.
 */
static bool
vmx_inject_recheck(struct vmx *vmx, int vcpu, enum event_inject_state state)
{
	if (state == EIS_CAN_INJECT) {
		if (vm_nmi_pending(vmx->vm, vcpu) &&
		    !vmx_nmi_window_exiting(vmx, vcpu)) {
			/* queued NMI not blocked by NMI-window-exiting */
			return (true);
		}
		if (vm_extint_pending(vmx->vm, vcpu)) {
			/* queued ExtINT not blocked by existing injection */
			return (true);
		}
	} else {
		if ((state & EIS_REQ_EXIT) != 0) {
			/*
			 * Use a self-IPI to force an immediate exit after
			 * event injection has occurred.
			 */
			poke_cpu(CPU->cpu_id);
		} else {
			/*
			 * If any event is being injected, an exit immediately
			 * upon becoming interruptable again will allow pending
			 * or newly queued events to be injected in a timely
			 * manner.
			 */
			vmx_set_int_window_exiting(vmx, vcpu);
		}
	}
	return (false);
}

/*
 * If the Virtual NMIs execution control is '1' then the logical processor
 * tracks virtual-NMI blocking in the Guest Interruptibility-state field of
 * the VMCS. An IRET instruction in VMX non-root operation will remove any
 * virtual-NMI blocking.
 *
 * This unblocking occurs even if the IRET causes a fault. In this case the
 * hypervisor needs to restore virtual-NMI blocking before resuming the guest.
 */
static void
vmx_restore_nmi_blocking(struct vmx *vmx, int vcpuid)
{
	uint32_t gi;

	VCPU_CTR0(vmx->vm, vcpuid, "Restore Virtual-NMI blocking");
	gi = vmcs_read(VMCS_GUEST_INTERRUPTIBILITY);
	gi |= VMCS_INTERRUPTIBILITY_NMI_BLOCKING;
	vmcs_write(VMCS_GUEST_INTERRUPTIBILITY, gi);
}

static void
vmx_clear_nmi_blocking(struct vmx *vmx, int vcpuid)
{
	uint32_t gi;

	VCPU_CTR0(vmx->vm, vcpuid, "Clear Virtual-NMI blocking");
	gi = vmcs_read(VMCS_GUEST_INTERRUPTIBILITY);
	gi &= ~VMCS_INTERRUPTIBILITY_NMI_BLOCKING;
	vmcs_write(VMCS_GUEST_INTERRUPTIBILITY, gi);
}

static void
vmx_assert_nmi_blocking(struct vmx *vmx, int vcpuid)
{
	uint32_t gi;

	gi = vmcs_read(VMCS_GUEST_INTERRUPTIBILITY);
	KASSERT(gi & VMCS_INTERRUPTIBILITY_NMI_BLOCKING,
	    ("NMI blocking is not in effect %x", gi));
}

static int
vmx_emulate_xsetbv(struct vmx *vmx, int vcpu, struct vm_exit *vmexit)
{
	struct vmxctx *vmxctx;
	uint64_t xcrval;
	const struct xsave_limits *limits;

	vmxctx = &vmx->ctx[vcpu];
	limits = vmm_get_xsave_limits();

	/*
	 * Note that the processor raises a GP# fault on its own if
	 * xsetbv is executed for CPL != 0, so we do not have to
	 * emulate that fault here.
	 */

	/* Only xcr0 is supported. */
	if (vmxctx->guest_rcx != 0) {
		vm_inject_gp(vmx->vm, vcpu);
		return (HANDLED);
	}

	/* We only handle xcr0 if both the host and guest have XSAVE enabled. */
	if (!limits->xsave_enabled ||
	    !(vmcs_read(VMCS_GUEST_CR4) & CR4_XSAVE)) {
		vm_inject_ud(vmx->vm, vcpu);
		return (HANDLED);
	}

	xcrval = vmxctx->guest_rdx << 32 | (vmxctx->guest_rax & 0xffffffff);
	if ((xcrval & ~limits->xcr0_allowed) != 0) {
		vm_inject_gp(vmx->vm, vcpu);
		return (HANDLED);
	}

	if (!(xcrval & XFEATURE_ENABLED_X87)) {
		vm_inject_gp(vmx->vm, vcpu);
		return (HANDLED);
	}

	/* AVX (YMM_Hi128) requires SSE. */
	if (xcrval & XFEATURE_ENABLED_AVX &&
	    (xcrval & XFEATURE_AVX) != XFEATURE_AVX) {
		vm_inject_gp(vmx->vm, vcpu);
		return (HANDLED);
	}

	/*
	 * AVX512 requires base AVX (YMM_Hi128) as well as OpMask,
	 * ZMM_Hi256, and Hi16_ZMM.
	 */
	if (xcrval & XFEATURE_AVX512 &&
	    (xcrval & (XFEATURE_AVX512 | XFEATURE_AVX)) !=
	    (XFEATURE_AVX512 | XFEATURE_AVX)) {
		vm_inject_gp(vmx->vm, vcpu);
		return (HANDLED);
	}

	/*
	 * Intel MPX requires both bound register state flags to be
	 * set.
	 */
	if (((xcrval & XFEATURE_ENABLED_BNDREGS) != 0) !=
	    ((xcrval & XFEATURE_ENABLED_BNDCSR) != 0)) {
		vm_inject_gp(vmx->vm, vcpu);
		return (HANDLED);
	}

	/*
	 * This runs "inside" vmrun() with the guest's FPU state, so
	 * modifying xcr0 directly modifies the guest's xcr0, not the
	 * host's.
	 */
	load_xcr(0, xcrval);
	return (HANDLED);
}

static uint64_t
vmx_get_guest_reg(struct vmx *vmx, int vcpu, int ident)
{
	const struct vmxctx *vmxctx;

	vmxctx = &vmx->ctx[vcpu];

	switch (ident) {
	case 0:
		return (vmxctx->guest_rax);
	case 1:
		return (vmxctx->guest_rcx);
	case 2:
		return (vmxctx->guest_rdx);
	case 3:
		return (vmxctx->guest_rbx);
	case 4:
		return (vmcs_read(VMCS_GUEST_RSP));
	case 5:
		return (vmxctx->guest_rbp);
	case 6:
		return (vmxctx->guest_rsi);
	case 7:
		return (vmxctx->guest_rdi);
	case 8:
		return (vmxctx->guest_r8);
	case 9:
		return (vmxctx->guest_r9);
	case 10:
		return (vmxctx->guest_r10);
	case 11:
		return (vmxctx->guest_r11);
	case 12:
		return (vmxctx->guest_r12);
	case 13:
		return (vmxctx->guest_r13);
	case 14:
		return (vmxctx->guest_r14);
	case 15:
		return (vmxctx->guest_r15);
	default:
		panic("invalid vmx register %d", ident);
	}
}

static void
vmx_set_guest_reg(struct vmx *vmx, int vcpu, int ident, uint64_t regval)
{
	struct vmxctx *vmxctx;

	vmxctx = &vmx->ctx[vcpu];

	switch (ident) {
	case 0:
		vmxctx->guest_rax = regval;
		break;
	case 1:
		vmxctx->guest_rcx = regval;
		break;
	case 2:
		vmxctx->guest_rdx = regval;
		break;
	case 3:
		vmxctx->guest_rbx = regval;
		break;
	case 4:
		vmcs_write(VMCS_GUEST_RSP, regval);
		break;
	case 5:
		vmxctx->guest_rbp = regval;
		break;
	case 6:
		vmxctx->guest_rsi = regval;
		break;
	case 7:
		vmxctx->guest_rdi = regval;
		break;
	case 8:
		vmxctx->guest_r8 = regval;
		break;
	case 9:
		vmxctx->guest_r9 = regval;
		break;
	case 10:
		vmxctx->guest_r10 = regval;
		break;
	case 11:
		vmxctx->guest_r11 = regval;
		break;
	case 12:
		vmxctx->guest_r12 = regval;
		break;
	case 13:
		vmxctx->guest_r13 = regval;
		break;
	case 14:
		vmxctx->guest_r14 = regval;
		break;
	case 15:
		vmxctx->guest_r15 = regval;
		break;
	default:
		panic("invalid vmx register %d", ident);
	}
}

static int
vmx_emulate_cr0_access(struct vmx *vmx, int vcpu, uint64_t exitqual)
{
	uint64_t crval, regval;

	/* We only handle mov to %cr0 at this time */
	if ((exitqual & 0xf0) != 0x00)
		return (UNHANDLED);

	regval = vmx_get_guest_reg(vmx, vcpu, (exitqual >> 8) & 0xf);

	vmcs_write(VMCS_CR0_SHADOW, regval);

	crval = regval | cr0_ones_mask;
	crval &= ~cr0_zeros_mask;
	vmcs_write(VMCS_GUEST_CR0, crval);

	if (regval & CR0_PG) {
		uint64_t efer, entry_ctls;

		/*
		 * If CR0.PG is 1 and EFER.LME is 1 then EFER.LMA and
		 * the "IA-32e mode guest" bit in VM-entry control must be
		 * equal.
		 */
		efer = vmcs_read(VMCS_GUEST_IA32_EFER);
		if (efer & EFER_LME) {
			efer |= EFER_LMA;
			vmcs_write(VMCS_GUEST_IA32_EFER, efer);
			entry_ctls = vmcs_read(VMCS_ENTRY_CTLS);
			entry_ctls |= VM_ENTRY_GUEST_LMA;
			vmcs_write(VMCS_ENTRY_CTLS, entry_ctls);
		}
	}

	return (HANDLED);
}

static int
vmx_emulate_cr4_access(struct vmx *vmx, int vcpu, uint64_t exitqual)
{
	uint64_t crval, regval;

	/* We only handle mov to %cr4 at this time */
	if ((exitqual & 0xf0) != 0x00)
		return (UNHANDLED);

	regval = vmx_get_guest_reg(vmx, vcpu, (exitqual >> 8) & 0xf);

	vmcs_write(VMCS_CR4_SHADOW, regval);

	crval = regval | cr4_ones_mask;
	crval &= ~cr4_zeros_mask;
	vmcs_write(VMCS_GUEST_CR4, crval);

	return (HANDLED);
}

static int
vmx_emulate_cr8_access(struct vmx *vmx, int vcpu, uint64_t exitqual)
{
	struct vlapic *vlapic;
	uint64_t cr8;
	int regnum;

	/* We only handle mov %cr8 to/from a register at this time. */
	if ((exitqual & 0xe0) != 0x00) {
		return (UNHANDLED);
	}

	vlapic = vm_lapic(vmx->vm, vcpu);
	regnum = (exitqual >> 8) & 0xf;
	if (exitqual & 0x10) {
		cr8 = vlapic_get_cr8(vlapic);
		vmx_set_guest_reg(vmx, vcpu, regnum, cr8);
	} else {
		cr8 = vmx_get_guest_reg(vmx, vcpu, regnum);
		vlapic_set_cr8(vlapic, cr8);
	}

	return (HANDLED);
}

/*
 * From section "Guest Register State" in the Intel SDM: CPL = SS.DPL
 */
static int
vmx_cpl(void)
{
	uint32_t ssar;

	ssar = vmcs_read(VMCS_GUEST_SS_ACCESS_RIGHTS);
	return ((ssar >> 5) & 0x3);
}

static enum vm_cpu_mode
vmx_cpu_mode(void)
{
	uint32_t csar;

	if (vmcs_read(VMCS_GUEST_IA32_EFER) & EFER_LMA) {
		csar = vmcs_read(VMCS_GUEST_CS_ACCESS_RIGHTS);
		if (csar & 0x2000)
			return (CPU_MODE_64BIT);	/* CS.L = 1 */
		else
			return (CPU_MODE_COMPATIBILITY);
	} else if (vmcs_read(VMCS_GUEST_CR0) & CR0_PE) {
		return (CPU_MODE_PROTECTED);
	} else {
		return (CPU_MODE_REAL);
	}
}

static enum vm_paging_mode
vmx_paging_mode(void)
{

	if (!(vmcs_read(VMCS_GUEST_CR0) & CR0_PG))
		return (PAGING_MODE_FLAT);
	if (!(vmcs_read(VMCS_GUEST_CR4) & CR4_PAE))
		return (PAGING_MODE_32);
	if (vmcs_read(VMCS_GUEST_IA32_EFER) & EFER_LME)
		return (PAGING_MODE_64);
	else
		return (PAGING_MODE_PAE);
}

static void
vmx_paging_info(struct vm_guest_paging *paging)
{
	paging->cr3 = vmcs_guest_cr3();
	paging->cpl = vmx_cpl();
	paging->cpu_mode = vmx_cpu_mode();
	paging->paging_mode = vmx_paging_mode();
}

static void
vmexit_mmio_emul(struct vm_exit *vmexit, struct vie *vie, uint64_t gpa,
    uint64_t gla)
{
	struct vm_guest_paging paging;
	uint32_t csar;

	vmexit->exitcode = VM_EXITCODE_MMIO_EMUL;
	vmexit->inst_length = 0;
	vmexit->u.mmio_emul.gpa = gpa;
	vmexit->u.mmio_emul.gla = gla;
	vmx_paging_info(&paging);

	switch (paging.cpu_mode) {
	case CPU_MODE_REAL:
		vmexit->u.mmio_emul.cs_base = vmcs_read(VMCS_GUEST_CS_BASE);
		vmexit->u.mmio_emul.cs_d = 0;
		break;
	case CPU_MODE_PROTECTED:
	case CPU_MODE_COMPATIBILITY:
		vmexit->u.mmio_emul.cs_base = vmcs_read(VMCS_GUEST_CS_BASE);
		csar = vmcs_read(VMCS_GUEST_CS_ACCESS_RIGHTS);
		vmexit->u.mmio_emul.cs_d = SEG_DESC_DEF32(csar);
		break;
	default:
		vmexit->u.mmio_emul.cs_base = 0;
		vmexit->u.mmio_emul.cs_d = 0;
		break;
	}

	vie_init_mmio(vie, NULL, 0, &paging, gpa);
}

static void
vmexit_inout(struct vm_exit *vmexit, struct vie *vie, uint64_t qual,
    uint32_t eax)
{
	struct vm_guest_paging paging;
	struct vm_inout *inout;

	inout = &vmexit->u.inout;

	inout->bytes = (qual & 0x7) + 1;
	inout->flags = 0;
	inout->flags |= (qual & 0x8) ? INOUT_IN : 0;
	inout->flags |= (qual & 0x10) ? INOUT_STR : 0;
	inout->flags |= (qual & 0x20) ? INOUT_REP : 0;
	inout->port = (uint16_t)(qual >> 16);
	inout->eax = eax;
	if (inout->flags & INOUT_STR) {
		uint64_t inst_info;

		inst_info = vmcs_read(VMCS_EXIT_INSTRUCTION_INFO);

		/*
		 * According to the SDM, bits 9:7 encode the address size of the
		 * ins/outs operation, but only values 0/1/2 are expected,
		 * corresponding to 16/32/64 bit sizes.
		 */
		inout->addrsize = 2 << BITX(inst_info, 9, 7);
		VERIFY(inout->addrsize == 2 || inout->addrsize == 4 ||
		    inout->addrsize == 8);

		if (inout->flags & INOUT_IN) {
			/*
			 * The bits describing the segment in INSTRUCTION_INFO
			 * are not defined for ins, leaving it to system
			 * software to assume %es (encoded as 0)
			 */
			inout->segment = 0;
		} else {
			/*
			 * Bits 15-17 encode the segment for OUTS.
			 * This value follows the standard x86 segment order.
			 */
			inout->segment = (inst_info >> 15) & 0x7;
		}
	}

	vmexit->exitcode = VM_EXITCODE_INOUT;
	vmx_paging_info(&paging);
	vie_init_inout(vie, inout, vmexit->inst_length, &paging);

	/* The in/out emulation will handle advancing %rip */
	vmexit->inst_length = 0;
}

static int
ept_fault_type(uint64_t ept_qual)
{
	int fault_type;

	if (ept_qual & EPT_VIOLATION_DATA_WRITE)
		fault_type = VM_PROT_WRITE;
	else if (ept_qual & EPT_VIOLATION_INST_FETCH)
		fault_type = VM_PROT_EXECUTE;
	else
		fault_type = VM_PROT_READ;

	return (fault_type);
}

static bool
ept_emulation_fault(uint64_t ept_qual)
{
	int read, write;

	/* EPT fault on an instruction fetch doesn't make sense here */
	if (ept_qual & EPT_VIOLATION_INST_FETCH)
		return (false);

	/* EPT fault must be a read fault or a write fault */
	read = ept_qual & EPT_VIOLATION_DATA_READ ? 1 : 0;
	write = ept_qual & EPT_VIOLATION_DATA_WRITE ? 1 : 0;
	if ((read | write) == 0)
		return (false);

	/*
	 * The EPT violation must have been caused by accessing a
	 * guest-physical address that is a translation of a guest-linear
	 * address.
	 */
	if ((ept_qual & EPT_VIOLATION_GLA_VALID) == 0 ||
	    (ept_qual & EPT_VIOLATION_XLAT_VALID) == 0) {
		return (false);
	}

	return (true);
}

static __inline int
apic_access_virtualization(struct vmx *vmx, int vcpuid)
{
	uint32_t proc_ctls2;

	proc_ctls2 = vmx->cap[vcpuid].proc_ctls2;
	return ((proc_ctls2 & PROCBASED2_VIRTUALIZE_APIC_ACCESSES) ? 1 : 0);
}

static __inline int
x2apic_virtualization(struct vmx *vmx, int vcpuid)
{
	uint32_t proc_ctls2;

	proc_ctls2 = vmx->cap[vcpuid].proc_ctls2;
	return ((proc_ctls2 & PROCBASED2_VIRTUALIZE_X2APIC_MODE) ? 1 : 0);
}

static int
vmx_handle_apic_write(struct vmx *vmx, int vcpuid, struct vlapic *vlapic,
    uint64_t qual)
{
	int handled, offset;
	uint32_t *apic_regs, vector;

	handled = HANDLED;
	offset = APIC_WRITE_OFFSET(qual);

	if (!apic_access_virtualization(vmx, vcpuid)) {
		/*
		 * In general there should not be any APIC write VM-exits
		 * unless APIC-access virtualization is enabled.
		 *
		 * However self-IPI virtualization can legitimately trigger
		 * an APIC-write VM-exit so treat it specially.
		 */
		if (x2apic_virtualization(vmx, vcpuid) &&
		    offset == APIC_OFFSET_SELF_IPI) {
			apic_regs = (uint32_t *)(vlapic->apic_page);
			vector = apic_regs[APIC_OFFSET_SELF_IPI / 4];
			vlapic_self_ipi_handler(vlapic, vector);
			return (HANDLED);
		} else
			return (UNHANDLED);
	}

	switch (offset) {
	case APIC_OFFSET_ID:
		vlapic_id_write_handler(vlapic);
		break;
	case APIC_OFFSET_LDR:
		vlapic_ldr_write_handler(vlapic);
		break;
	case APIC_OFFSET_DFR:
		vlapic_dfr_write_handler(vlapic);
		break;
	case APIC_OFFSET_SVR:
		vlapic_svr_write_handler(vlapic);
		break;
	case APIC_OFFSET_ESR:
		vlapic_esr_write_handler(vlapic);
		break;
	case APIC_OFFSET_ICR_LOW:
		if (vlapic_icrlo_write_handler(vlapic) != 0) {
			handled = UNHANDLED;
		}
		break;
	case APIC_OFFSET_CMCI_LVT:
	case APIC_OFFSET_TIMER_LVT ... APIC_OFFSET_ERROR_LVT:
		vlapic_lvt_write_handler(vlapic, offset);
		break;
	case APIC_OFFSET_TIMER_ICR:
		vlapic_icrtmr_write_handler(vlapic);
		break;
	case APIC_OFFSET_TIMER_DCR:
		vlapic_dcr_write_handler(vlapic);
		break;
	default:
		handled = UNHANDLED;
		break;
	}
	return (handled);
}

static bool
apic_access_fault(struct vmx *vmx, int vcpuid, uint64_t gpa)
{

	if (apic_access_virtualization(vmx, vcpuid) &&
	    (gpa >= DEFAULT_APIC_BASE && gpa < DEFAULT_APIC_BASE + PAGE_SIZE))
		return (true);
	else
		return (false);
}

static int
vmx_handle_apic_access(struct vmx *vmx, int vcpuid, struct vm_exit *vmexit)
{
	uint64_t qual;
	int access_type, offset, allowed;
	struct vie *vie;

	if (!apic_access_virtualization(vmx, vcpuid))
		return (UNHANDLED);

	qual = vmexit->u.vmx.exit_qualification;
	access_type = APIC_ACCESS_TYPE(qual);
	offset = APIC_ACCESS_OFFSET(qual);

	allowed = 0;
	if (access_type == 0) {
		/*
		 * Read data access to the following registers is expected.
		 */
		switch (offset) {
		case APIC_OFFSET_APR:
		case APIC_OFFSET_PPR:
		case APIC_OFFSET_RRR:
		case APIC_OFFSET_CMCI_LVT:
		case APIC_OFFSET_TIMER_CCR:
			allowed = 1;
			break;
		default:
			break;
		}
	} else if (access_type == 1) {
		/*
		 * Write data access to the following registers is expected.
		 */
		switch (offset) {
		case APIC_OFFSET_VER:
		case APIC_OFFSET_APR:
		case APIC_OFFSET_PPR:
		case APIC_OFFSET_RRR:
		case APIC_OFFSET_ISR0 ... APIC_OFFSET_ISR7:
		case APIC_OFFSET_TMR0 ... APIC_OFFSET_TMR7:
		case APIC_OFFSET_IRR0 ... APIC_OFFSET_IRR7:
		case APIC_OFFSET_CMCI_LVT:
		case APIC_OFFSET_TIMER_CCR:
			allowed = 1;
			break;
		default:
			break;
		}
	}

	if (allowed) {
		vie = vm_vie_ctx(vmx->vm, vcpuid);
		vmexit_mmio_emul(vmexit, vie, DEFAULT_APIC_BASE + offset,
		    VIE_INVALID_GLA);
	}

	/*
	 * Regardless of whether the APIC-access is allowed this handler
	 * always returns UNHANDLED:
	 * - if the access is allowed then it is handled by emulating the
	 *   instruction that caused the VM-exit (outside the critical section)
	 * - if the access is not allowed then it will be converted to an
	 *   exitcode of VM_EXITCODE_VMX and will be dealt with in userland.
	 */
	return (UNHANDLED);
}

static enum task_switch_reason
vmx_task_switch_reason(uint64_t qual)
{
	int reason;

	reason = (qual >> 30) & 0x3;
	switch (reason) {
	case 0:
		return (TSR_CALL);
	case 1:
		return (TSR_IRET);
	case 2:
		return (TSR_JMP);
	case 3:
		return (TSR_IDT_GATE);
	default:
		panic("%s: invalid reason %d", __func__, reason);
	}
}

static int
emulate_wrmsr(struct vmx *vmx, int vcpuid, uint_t num, uint64_t val)
{
	int error;

	if (lapic_msr(num))
		error = lapic_wrmsr(vmx->vm, vcpuid, num, val);
	else
		error = vmx_wrmsr(vmx, vcpuid, num, val);

	return (error);
}

static int
emulate_rdmsr(struct vmx *vmx, int vcpuid, uint_t num)
{
	uint64_t result;
	int error;

	if (lapic_msr(num))
		error = lapic_rdmsr(vmx->vm, vcpuid, num, &result);
	else
		error = vmx_rdmsr(vmx, vcpuid, num, &result);

	if (error == 0) {
		vmx->ctx[vcpuid].guest_rax = (uint32_t)result;
		vmx->ctx[vcpuid].guest_rdx = result >> 32;
	}

	return (error);
}

#ifndef __FreeBSD__
#define	__predict_false(x)	(x)
#endif

static int
vmx_exit_process(struct vmx *vmx, int vcpu, struct vm_exit *vmexit)
{
	int error, errcode, errcode_valid, handled;
	struct vmxctx *vmxctx;
	struct vie *vie;
	struct vlapic *vlapic;
	struct vm_task_switch *ts;
	uint32_t eax, ecx, edx, idtvec_info, idtvec_err, intr_info;
	uint32_t intr_type, intr_vec, reason;
	uint64_t exitintinfo, qual, gpa;

	CTASSERT((PINBASED_CTLS_ONE_SETTING & PINBASED_VIRTUAL_NMI) != 0);
	CTASSERT((PINBASED_CTLS_ONE_SETTING & PINBASED_NMI_EXITING) != 0);

	handled = UNHANDLED;
	vmxctx = &vmx->ctx[vcpu];

	qual = vmexit->u.vmx.exit_qualification;
	reason = vmexit->u.vmx.exit_reason;
	vmexit->exitcode = VM_EXITCODE_BOGUS;

	vmm_stat_incr(vmx->vm, vcpu, VMEXIT_COUNT, 1);
	SDT_PROBE3(vmm, vmx, exit, entry, vmx, vcpu, vmexit);

	/*
	 * VM-entry failures during or after loading guest state.
	 *
	 * These VM-exits are uncommon but must be handled specially
	 * as most VM-exit fields are not populated as usual.
	 */
	if (__predict_false(reason == EXIT_REASON_MCE_DURING_ENTRY)) {
		VCPU_CTR0(vmx->vm, vcpu, "Handling MCE during VM-entry");
#ifdef __FreeBSD__
		__asm __volatile("int $18");
#else
		vmm_call_trap(T_MCE);
#endif
		return (1);
	}

	/*
	 * VM exits that can be triggered during event delivery need to
	 * be handled specially by re-injecting the event if the IDT
	 * vectoring information field's valid bit is set.
	 *
	 * See "Information for VM Exits During Event Delivery" in Intel SDM
	 * for details.
	 */
	idtvec_info = vmcs_idt_vectoring_info();
	if (idtvec_info & VMCS_IDT_VEC_VALID) {
		idtvec_info &= ~(1 << 12); /* clear undefined bit */
		exitintinfo = idtvec_info;
		if (idtvec_info & VMCS_IDT_VEC_ERRCODE_VALID) {
			idtvec_err = vmcs_idt_vectoring_err();
			exitintinfo |= (uint64_t)idtvec_err << 32;
		}
		error = vm_exit_intinfo(vmx->vm, vcpu, exitintinfo);
		KASSERT(error == 0, ("%s: vm_set_intinfo error %d",
		    __func__, error));

		/*
		 * If 'virtual NMIs' are being used and the VM-exit
		 * happened while injecting an NMI during the previous
		 * VM-entry, then clear "blocking by NMI" in the
		 * Guest Interruptibility-State so the NMI can be
		 * reinjected on the subsequent VM-entry.
		 *
		 * However, if the NMI was being delivered through a task
		 * gate, then the new task must start execution with NMIs
		 * blocked so don't clear NMI blocking in this case.
		 */
		intr_type = idtvec_info & VMCS_INTR_T_MASK;
		if (intr_type == VMCS_INTR_T_NMI) {
			if (reason != EXIT_REASON_TASK_SWITCH)
				vmx_clear_nmi_blocking(vmx, vcpu);
			else
				vmx_assert_nmi_blocking(vmx, vcpu);
		}

		/*
		 * Update VM-entry instruction length if the event being
		 * delivered was a software interrupt or software exception.
		 */
		if (intr_type == VMCS_INTR_T_SWINTR ||
		    intr_type == VMCS_INTR_T_PRIV_SWEXCEPTION ||
		    intr_type == VMCS_INTR_T_SWEXCEPTION) {
			vmcs_write(VMCS_ENTRY_INST_LENGTH, vmexit->inst_length);
		}
	}

	switch (reason) {
	case EXIT_REASON_TASK_SWITCH:
		ts = &vmexit->u.task_switch;
		ts->tsssel = qual & 0xffff;
		ts->reason = vmx_task_switch_reason(qual);
		ts->ext = 0;
		ts->errcode_valid = 0;
		vmx_paging_info(&ts->paging);
		/*
		 * If the task switch was due to a CALL, JMP, IRET, software
		 * interrupt (INT n) or software exception (INT3, INTO),
		 * then the saved %rip references the instruction that caused
		 * the task switch. The instruction length field in the VMCS
		 * is valid in this case.
		 *
		 * In all other cases (e.g., NMI, hardware exception) the
		 * saved %rip is one that would have been saved in the old TSS
		 * had the task switch completed normally so the instruction
		 * length field is not needed in this case and is explicitly
		 * set to 0.
		 */
		if (ts->reason == TSR_IDT_GATE) {
			KASSERT(idtvec_info & VMCS_IDT_VEC_VALID,
			    ("invalid idtvec_info %x for IDT task switch",
			    idtvec_info));
			intr_type = idtvec_info & VMCS_INTR_T_MASK;
			if (intr_type != VMCS_INTR_T_SWINTR &&
			    intr_type != VMCS_INTR_T_SWEXCEPTION &&
			    intr_type != VMCS_INTR_T_PRIV_SWEXCEPTION) {
				/* Task switch triggered by external event */
				ts->ext = 1;
				vmexit->inst_length = 0;
				if (idtvec_info & VMCS_IDT_VEC_ERRCODE_VALID) {
					ts->errcode_valid = 1;
					ts->errcode = vmcs_idt_vectoring_err();
				}
			}
		}
		vmexit->exitcode = VM_EXITCODE_TASK_SWITCH;
		SDT_PROBE4(vmm, vmx, exit, taskswitch, vmx, vcpu, vmexit, ts);
		VCPU_CTR4(vmx->vm, vcpu, "task switch reason %d, tss 0x%04x, "
		    "%s errcode 0x%016lx", ts->reason, ts->tsssel,
		    ts->ext ? "external" : "internal",
		    ((uint64_t)ts->errcode << 32) | ts->errcode_valid);
		break;
	case EXIT_REASON_CR_ACCESS:
		vmm_stat_incr(vmx->vm, vcpu, VMEXIT_CR_ACCESS, 1);
		SDT_PROBE4(vmm, vmx, exit, craccess, vmx, vcpu, vmexit, qual);
		switch (qual & 0xf) {
		case 0:
			handled = vmx_emulate_cr0_access(vmx, vcpu, qual);
			break;
		case 4:
			handled = vmx_emulate_cr4_access(vmx, vcpu, qual);
			break;
		case 8:
			handled = vmx_emulate_cr8_access(vmx, vcpu, qual);
			break;
		}
		break;
	case EXIT_REASON_RDMSR:
		vmm_stat_incr(vmx->vm, vcpu, VMEXIT_RDMSR, 1);
		ecx = vmxctx->guest_rcx;
		VCPU_CTR1(vmx->vm, vcpu, "rdmsr 0x%08x", ecx);
		SDT_PROBE4(vmm, vmx, exit, rdmsr, vmx, vcpu, vmexit, ecx);
		error = emulate_rdmsr(vmx, vcpu, ecx);
		if (error == 0) {
			handled = HANDLED;
		} else if (error > 0) {
			vmexit->exitcode = VM_EXITCODE_RDMSR;
			vmexit->u.msr.code = ecx;
		} else {
			/* Return to userspace with a valid exitcode */
			KASSERT(vmexit->exitcode != VM_EXITCODE_BOGUS,
			    ("emulate_rdmsr retu with bogus exitcode"));
		}
		break;
	case EXIT_REASON_WRMSR:
		vmm_stat_incr(vmx->vm, vcpu, VMEXIT_WRMSR, 1);
		eax = vmxctx->guest_rax;
		ecx = vmxctx->guest_rcx;
		edx = vmxctx->guest_rdx;
		VCPU_CTR2(vmx->vm, vcpu, "wrmsr 0x%08x value 0x%016lx",
		    ecx, (uint64_t)edx << 32 | eax);
		SDT_PROBE5(vmm, vmx, exit, wrmsr, vmx, vmexit, vcpu, ecx,
		    (uint64_t)edx << 32 | eax);
		error = emulate_wrmsr(vmx, vcpu, ecx,
		    (uint64_t)edx << 32 | eax);
		if (error == 0) {
			handled = HANDLED;
		} else if (error > 0) {
			vmexit->exitcode = VM_EXITCODE_WRMSR;
			vmexit->u.msr.code = ecx;
			vmexit->u.msr.wval = (uint64_t)edx << 32 | eax;
		} else {
			/* Return to userspace with a valid exitcode */
			KASSERT(vmexit->exitcode != VM_EXITCODE_BOGUS,
			    ("emulate_wrmsr retu with bogus exitcode"));
		}
		break;
	case EXIT_REASON_HLT:
		vmm_stat_incr(vmx->vm, vcpu, VMEXIT_HLT, 1);
		SDT_PROBE3(vmm, vmx, exit, halt, vmx, vcpu, vmexit);
		vmexit->exitcode = VM_EXITCODE_HLT;
		vmexit->u.hlt.rflags = vmcs_read(VMCS_GUEST_RFLAGS);
		break;
	case EXIT_REASON_MTF:
		vmm_stat_incr(vmx->vm, vcpu, VMEXIT_MTRAP, 1);
		SDT_PROBE3(vmm, vmx, exit, mtrap, vmx, vcpu, vmexit);
		vmexit->exitcode = VM_EXITCODE_MTRAP;
		vmexit->inst_length = 0;
		break;
	case EXIT_REASON_PAUSE:
		vmm_stat_incr(vmx->vm, vcpu, VMEXIT_PAUSE, 1);
		SDT_PROBE3(vmm, vmx, exit, pause, vmx, vcpu, vmexit);
		vmexit->exitcode = VM_EXITCODE_PAUSE;
		break;
	case EXIT_REASON_INTR_WINDOW:
		vmm_stat_incr(vmx->vm, vcpu, VMEXIT_INTR_WINDOW, 1);
		SDT_PROBE3(vmm, vmx, exit, intrwindow, vmx, vcpu, vmexit);
		vmx_clear_int_window_exiting(vmx, vcpu);
		return (1);
	case EXIT_REASON_EXT_INTR:
		/*
		 * External interrupts serve only to cause VM exits and allow
		 * the host interrupt handler to run.
		 *
		 * If this external interrupt triggers a virtual interrupt
		 * to a VM, then that state will be recorded by the
		 * host interrupt handler in the VM's softc. We will inject
		 * this virtual interrupt during the subsequent VM enter.
		 */
		intr_info = vmcs_read(VMCS_EXIT_INTR_INFO);
		SDT_PROBE4(vmm, vmx, exit, interrupt,
		    vmx, vcpu, vmexit, intr_info);

		/*
		 * XXX: Ignore this exit if VMCS_INTR_VALID is not set.
		 * This appears to be a bug in VMware Fusion?
		 */
		if (!(intr_info & VMCS_INTR_VALID))
			return (1);
		KASSERT((intr_info & VMCS_INTR_VALID) != 0 &&
		    (intr_info & VMCS_INTR_T_MASK) == VMCS_INTR_T_HWINTR,
		    ("VM exit interruption info invalid: %x", intr_info));
		vmx_trigger_hostintr(intr_info & 0xff);

		/*
		 * This is special. We want to treat this as an 'handled'
		 * VM-exit but not increment the instruction pointer.
		 */
		vmm_stat_incr(vmx->vm, vcpu, VMEXIT_EXTINT, 1);
		return (1);
	case EXIT_REASON_NMI_WINDOW:
		SDT_PROBE3(vmm, vmx, exit, nmiwindow, vmx, vcpu, vmexit);
		/* Exit to allow the pending virtual NMI to be injected */
		if (vm_nmi_pending(vmx->vm, vcpu))
			vmx_inject_nmi(vmx, vcpu);
		vmx_clear_nmi_window_exiting(vmx, vcpu);
		vmm_stat_incr(vmx->vm, vcpu, VMEXIT_NMI_WINDOW, 1);
		return (1);
	case EXIT_REASON_INOUT:
		vmm_stat_incr(vmx->vm, vcpu, VMEXIT_INOUT, 1);
		vie = vm_vie_ctx(vmx->vm, vcpu);
		vmexit_inout(vmexit, vie, qual, (uint32_t)vmxctx->guest_rax);
		SDT_PROBE3(vmm, vmx, exit, inout, vmx, vcpu, vmexit);
		break;
	case EXIT_REASON_CPUID:
		vmm_stat_incr(vmx->vm, vcpu, VMEXIT_CPUID, 1);
		SDT_PROBE3(vmm, vmx, exit, cpuid, vmx, vcpu, vmexit);
		handled = vmx_handle_cpuid(vmx->vm, vcpu, vmxctx);
		break;
	case EXIT_REASON_EXCEPTION:
		vmm_stat_incr(vmx->vm, vcpu, VMEXIT_EXCEPTION, 1);
		intr_info = vmcs_read(VMCS_EXIT_INTR_INFO);
		KASSERT((intr_info & VMCS_INTR_VALID) != 0,
		    ("VM exit interruption info invalid: %x", intr_info));

		intr_vec = intr_info & 0xff;
		intr_type = intr_info & VMCS_INTR_T_MASK;

		/*
		 * If Virtual NMIs control is 1 and the VM-exit is due to a
		 * fault encountered during the execution of IRET then we must
		 * restore the state of "virtual-NMI blocking" before resuming
		 * the guest.
		 *
		 * See "Resuming Guest Software after Handling an Exception".
		 * See "Information for VM Exits Due to Vectored Events".
		 */
		if ((idtvec_info & VMCS_IDT_VEC_VALID) == 0 &&
		    (intr_vec != IDT_DF) &&
		    (intr_info & EXIT_QUAL_NMIUDTI) != 0)
			vmx_restore_nmi_blocking(vmx, vcpu);

		/*
		 * The NMI has already been handled in vmx_exit_handle_nmi().
		 */
		if (intr_type == VMCS_INTR_T_NMI)
			return (1);

		/*
		 * Call the machine check handler by hand. Also don't reflect
		 * the machine check back into the guest.
		 */
		if (intr_vec == IDT_MC) {
			VCPU_CTR0(vmx->vm, vcpu, "Vectoring to MCE handler");
#ifdef __FreeBSD__
			__asm __volatile("int $18");
#else
			vmm_call_trap(T_MCE);
#endif
			return (1);
		}

		/*
		 * If the hypervisor has requested user exits for
		 * debug exceptions, bounce them out to userland.
		 */
		if (intr_type == VMCS_INTR_T_SWEXCEPTION &&
		    intr_vec == IDT_BP &&
		    (vmx->cap[vcpu].set & (1 << VM_CAP_BPT_EXIT))) {
			vmexit->exitcode = VM_EXITCODE_BPT;
			vmexit->u.bpt.inst_length = vmexit->inst_length;
			vmexit->inst_length = 0;
			break;
		}

		if (intr_vec == IDT_PF) {
			vmxctx->guest_cr2 = qual;
		}

		/*
		 * Software exceptions exhibit trap-like behavior. This in
		 * turn requires populating the VM-entry instruction length
		 * so that the %rip in the trap frame is past the INT3/INTO
		 * instruction.
		 */
		if (intr_type == VMCS_INTR_T_SWEXCEPTION)
			vmcs_write(VMCS_ENTRY_INST_LENGTH, vmexit->inst_length);

		/* Reflect all other exceptions back into the guest */
		errcode_valid = errcode = 0;
		if (intr_info & VMCS_INTR_DEL_ERRCODE) {
			errcode_valid = 1;
			errcode = vmcs_read(VMCS_EXIT_INTR_ERRCODE);
		}
		VCPU_CTR2(vmx->vm, vcpu, "Reflecting exception %d/%x into "
		    "the guest", intr_vec, errcode);
		SDT_PROBE5(vmm, vmx, exit, exception,
		    vmx, vcpu, vmexit, intr_vec, errcode);
		error = vm_inject_exception(vmx->vm, vcpu, intr_vec,
		    errcode_valid, errcode, 0);
		KASSERT(error == 0, ("%s: vm_inject_exception error %d",
		    __func__, error));
		return (1);

	case EXIT_REASON_EPT_FAULT:
		/*
		 * If 'gpa' lies within the address space allocated to
		 * memory then this must be a nested page fault otherwise
		 * this must be an instruction that accesses MMIO space.
		 */
		gpa = vmcs_gpa();
		if (vm_mem_allocated(vmx->vm, vcpu, gpa) ||
		    apic_access_fault(vmx, vcpu, gpa)) {
			vmexit->exitcode = VM_EXITCODE_PAGING;
			vmexit->inst_length = 0;
			vmexit->u.paging.gpa = gpa;
			vmexit->u.paging.fault_type = ept_fault_type(qual);
			vmm_stat_incr(vmx->vm, vcpu, VMEXIT_NESTED_FAULT, 1);
			SDT_PROBE5(vmm, vmx, exit, nestedfault,
			    vmx, vcpu, vmexit, gpa, qual);
		} else if (ept_emulation_fault(qual)) {
			vie = vm_vie_ctx(vmx->vm, vcpu);
			vmexit_mmio_emul(vmexit, vie, gpa, vmcs_gla());
			vmm_stat_incr(vmx->vm, vcpu, VMEXIT_MMIO_EMUL, 1);
			SDT_PROBE4(vmm, vmx, exit, mmiofault,
			    vmx, vcpu, vmexit, gpa);
		}
		/*
		 * If Virtual NMIs control is 1 and the VM-exit is due to an
		 * EPT fault during the execution of IRET then we must restore
		 * the state of "virtual-NMI blocking" before resuming.
		 *
		 * See description of "NMI unblocking due to IRET" in
		 * "Exit Qualification for EPT Violations".
		 */
		if ((idtvec_info & VMCS_IDT_VEC_VALID) == 0 &&
		    (qual & EXIT_QUAL_NMIUDTI) != 0)
			vmx_restore_nmi_blocking(vmx, vcpu);
		break;
	case EXIT_REASON_VIRTUALIZED_EOI:
		vmexit->exitcode = VM_EXITCODE_IOAPIC_EOI;
		vmexit->u.ioapic_eoi.vector = qual & 0xFF;
		SDT_PROBE3(vmm, vmx, exit, eoi, vmx, vcpu, vmexit);
		vmexit->inst_length = 0;	/* trap-like */
		break;
	case EXIT_REASON_APIC_ACCESS:
		SDT_PROBE3(vmm, vmx, exit, apicaccess, vmx, vcpu, vmexit);
		handled = vmx_handle_apic_access(vmx, vcpu, vmexit);
		break;
	case EXIT_REASON_APIC_WRITE:
		/*
		 * APIC-write VM exit is trap-like so the %rip is already
		 * pointing to the next instruction.
		 */
		vmexit->inst_length = 0;
		vlapic = vm_lapic(vmx->vm, vcpu);
		SDT_PROBE4(vmm, vmx, exit, apicwrite,
		    vmx, vcpu, vmexit, vlapic);
		handled = vmx_handle_apic_write(vmx, vcpu, vlapic, qual);
		break;
	case EXIT_REASON_XSETBV:
		SDT_PROBE3(vmm, vmx, exit, xsetbv, vmx, vcpu, vmexit);
		handled = vmx_emulate_xsetbv(vmx, vcpu, vmexit);
		break;
	case EXIT_REASON_MONITOR:
		SDT_PROBE3(vmm, vmx, exit, monitor, vmx, vcpu, vmexit);
		vmexit->exitcode = VM_EXITCODE_MONITOR;
		break;
	case EXIT_REASON_MWAIT:
		SDT_PROBE3(vmm, vmx, exit, mwait, vmx, vcpu, vmexit);
		vmexit->exitcode = VM_EXITCODE_MWAIT;
		break;
	case EXIT_REASON_TPR:
		vlapic = vm_lapic(vmx->vm, vcpu);
		vlapic_sync_tpr(vlapic);
		vmexit->inst_length = 0;
		handled = HANDLED;
		break;
	case EXIT_REASON_VMCALL:
	case EXIT_REASON_VMCLEAR:
	case EXIT_REASON_VMLAUNCH:
	case EXIT_REASON_VMPTRLD:
	case EXIT_REASON_VMPTRST:
	case EXIT_REASON_VMREAD:
	case EXIT_REASON_VMRESUME:
	case EXIT_REASON_VMWRITE:
	case EXIT_REASON_VMXOFF:
	case EXIT_REASON_VMXON:
		SDT_PROBE3(vmm, vmx, exit, vminsn, vmx, vcpu, vmexit);
		vmexit->exitcode = VM_EXITCODE_VMINSN;
		break;
	default:
		SDT_PROBE4(vmm, vmx, exit, unknown,
		    vmx, vcpu, vmexit, reason);
		vmm_stat_incr(vmx->vm, vcpu, VMEXIT_UNKNOWN, 1);
		break;
	}

	if (handled) {
		/*
		 * It is possible that control is returned to userland
		 * even though we were able to handle the VM exit in the
		 * kernel.
		 *
		 * In such a case we want to make sure that the userland
		 * restarts guest execution at the instruction *after*
		 * the one we just processed. Therefore we update the
		 * guest rip in the VMCS and in 'vmexit'.
		 */
		vmexit->rip += vmexit->inst_length;
		vmexit->inst_length = 0;
		vmcs_write(VMCS_GUEST_RIP, vmexit->rip);
	} else {
		if (vmexit->exitcode == VM_EXITCODE_BOGUS) {
			/*
			 * If this VM exit was not claimed by anybody then
			 * treat it as a generic VMX exit.
			 */
			vmexit->exitcode = VM_EXITCODE_VMX;
			vmexit->u.vmx.status = VM_SUCCESS;
			vmexit->u.vmx.inst_type = 0;
			vmexit->u.vmx.inst_error = 0;
		} else {
			/*
			 * The exitcode and collateral have been populated.
			 * The VM exit will be processed further in userland.
			 */
		}
	}

	SDT_PROBE4(vmm, vmx, exit, return,
	    vmx, vcpu, vmexit, handled);
	return (handled);
}

static void
vmx_exit_inst_error(struct vmxctx *vmxctx, int rc, struct vm_exit *vmexit)
{

	KASSERT(vmxctx->inst_fail_status != VM_SUCCESS,
	    ("vmx_exit_inst_error: invalid inst_fail_status %d",
	    vmxctx->inst_fail_status));

	vmexit->inst_length = 0;
	vmexit->exitcode = VM_EXITCODE_VMX;
	vmexit->u.vmx.status = vmxctx->inst_fail_status;
	vmexit->u.vmx.inst_error = vmcs_instruction_error();
	vmexit->u.vmx.exit_reason = ~0;
	vmexit->u.vmx.exit_qualification = ~0;

	switch (rc) {
	case VMX_VMRESUME_ERROR:
	case VMX_VMLAUNCH_ERROR:
	case VMX_INVEPT_ERROR:
#ifndef __FreeBSD__
	case VMX_VMWRITE_ERROR:
#endif
		vmexit->u.vmx.inst_type = rc;
		break;
	default:
		panic("vm_exit_inst_error: vmx_enter_guest returned %d", rc);
	}
}

/*
 * If the NMI-exiting VM execution control is set to '1' then an NMI in
 * non-root operation causes a VM-exit. NMI blocking is in effect so it is
 * sufficient to simply vector to the NMI handler via a software interrupt.
 * However, this must be done before maskable interrupts are enabled
 * otherwise the "iret" issued by an interrupt handler will incorrectly
 * clear NMI blocking.
 */
static __inline void
vmx_exit_handle_nmi(struct vmx *vmx, int vcpuid, struct vm_exit *vmexit)
{
	uint32_t intr_info;

	KASSERT((read_rflags() & PSL_I) == 0, ("interrupts enabled"));

	if (vmexit->u.vmx.exit_reason != EXIT_REASON_EXCEPTION)
		return;

	intr_info = vmcs_read(VMCS_EXIT_INTR_INFO);
	KASSERT((intr_info & VMCS_INTR_VALID) != 0,
	    ("VM exit interruption info invalid: %x", intr_info));

	if ((intr_info & VMCS_INTR_T_MASK) == VMCS_INTR_T_NMI) {
		KASSERT((intr_info & 0xff) == IDT_NMI, ("VM exit due "
		    "to NMI has invalid vector: %x", intr_info));
		VCPU_CTR0(vmx->vm, vcpuid, "Vectoring to NMI handler");
#ifdef __FreeBSD__
		__asm __volatile("int $2");
#else
		vmm_call_trap(T_NMIFLT);
#endif
	}
}

static __inline void
vmx_dr_enter_guest(struct vmxctx *vmxctx)
{
	uint64_t rflags;

	/* Save host control debug registers. */
	vmxctx->host_dr7 = rdr7();
	vmxctx->host_debugctl = rdmsr(MSR_DEBUGCTLMSR);

	/*
	 * Disable debugging in DR7 and DEBUGCTL to avoid triggering
	 * exceptions in the host based on the guest DRx values.  The
	 * guest DR7 and DEBUGCTL are saved/restored in the VMCS.
	 */
	load_dr7(0);
	wrmsr(MSR_DEBUGCTLMSR, 0);

	/*
	 * Disable single stepping the kernel to avoid corrupting the
	 * guest DR6.  A debugger might still be able to corrupt the
	 * guest DR6 by setting a breakpoint after this point and then
	 * single stepping.
	 */
	rflags = read_rflags();
	vmxctx->host_tf = rflags & PSL_T;
	write_rflags(rflags & ~PSL_T);

	/* Save host debug registers. */
	vmxctx->host_dr0 = rdr0();
	vmxctx->host_dr1 = rdr1();
	vmxctx->host_dr2 = rdr2();
	vmxctx->host_dr3 = rdr3();
	vmxctx->host_dr6 = rdr6();

	/* Restore guest debug registers. */
	load_dr0(vmxctx->guest_dr0);
	load_dr1(vmxctx->guest_dr1);
	load_dr2(vmxctx->guest_dr2);
	load_dr3(vmxctx->guest_dr3);
	load_dr6(vmxctx->guest_dr6);
}

static __inline void
vmx_dr_leave_guest(struct vmxctx *vmxctx)
{

	/* Save guest debug registers. */
	vmxctx->guest_dr0 = rdr0();
	vmxctx->guest_dr1 = rdr1();
	vmxctx->guest_dr2 = rdr2();
	vmxctx->guest_dr3 = rdr3();
	vmxctx->guest_dr6 = rdr6();

	/*
	 * Restore host debug registers.  Restore DR7, DEBUGCTL, and
	 * PSL_T last.
	 */
	load_dr0(vmxctx->host_dr0);
	load_dr1(vmxctx->host_dr1);
	load_dr2(vmxctx->host_dr2);
	load_dr3(vmxctx->host_dr3);
	load_dr6(vmxctx->host_dr6);
	wrmsr(MSR_DEBUGCTLMSR, vmxctx->host_debugctl);
	load_dr7(vmxctx->host_dr7);
	write_rflags(read_rflags() | vmxctx->host_tf);
}

static int
vmx_run(void *arg, int vcpu, uint64_t rip, pmap_t pmap)
{
	int rc, handled, launched;
	struct vmx *vmx;
	struct vm *vm;
	struct vmxctx *vmxctx;
	uintptr_t vmcs_pa;
	struct vm_exit *vmexit;
	struct vlapic *vlapic;
	uint32_t exit_reason;
#ifdef __FreeBSD__
	struct region_descriptor gdtr, idtr;
	uint16_t ldt_sel;
#endif
	bool tpr_shadow_active;

	vmx = arg;
	vm = vmx->vm;
	vmcs_pa = vmx->vmcs_pa[vcpu];
	vmxctx = &vmx->ctx[vcpu];
	vlapic = vm_lapic(vm, vcpu);
	vmexit = vm_exitinfo(vm, vcpu);
	launched = 0;
	tpr_shadow_active = vmx_cap_en(vmx, VMX_CAP_TPR_SHADOW) &&
	    !vmx_cap_en(vmx, VMX_CAP_APICV) &&
	    (vmx->cap[vcpu].proc_ctls & PROCBASED_USE_TPR_SHADOW) != 0;

	KASSERT(vmxctx->pmap == pmap,
	    ("pmap %p different than ctx pmap %p", pmap, vmxctx->pmap));

	vmx_msr_guest_enter(vmx, vcpu);

	vmcs_load(vmcs_pa);

#ifndef __FreeBSD__
	VERIFY(vmx->vmcs_state[vcpu] == VS_NONE && curthread->t_preempt != 0);
	vmx->vmcs_state[vcpu] = VS_LOADED;
#endif

	/*
	 * XXX
	 * We do this every time because we may setup the virtual machine
	 * from a different process than the one that actually runs it.
	 *
	 * If the life of a virtual machine was spent entirely in the context
	 * of a single process we could do this once in vmx_vminit().
	 */
	vmcs_write(VMCS_HOST_CR3, rcr3());

	vmcs_write(VMCS_GUEST_RIP, rip);
	vmx_set_pcpu_defaults(vmx, vcpu, pmap);
	do {
		enum event_inject_state inject_state;

		KASSERT(vmcs_guest_rip() == rip, ("%s: vmcs guest rip mismatch "
		    "%lx/%lx", __func__, vmcs_guest_rip(), rip));

		handled = UNHANDLED;

		/*
		 * Perform initial event/exception/interrupt injection before
		 * host CPU interrupts are disabled.
		 */
		inject_state = vmx_inject_events(vmx, vcpu, rip);

		/*
		 * Interrupts are disabled from this point on until the
		 * guest starts executing. This is done for the following
		 * reasons:
		 *
		 * If an AST is asserted on this thread after the check below,
		 * then the IPI_AST notification will not be lost, because it
		 * will cause a VM exit due to external interrupt as soon as
		 * the guest state is loaded.
		 *
		 * A posted interrupt after vmx_inject_vlapic() will not be
		 * "lost" because it will be held pending in the host APIC
		 * because interrupts are disabled. The pending interrupt will
		 * be recognized as soon as the guest state is loaded.
		 *
		 * The same reasoning applies to the IPI generated by
		 * pmap_invalidate_ept().
		 */
		disable_intr();

		/*
		 * If not precluded by existing events, inject any interrupt
		 * pending on the vLAPIC.  As a lock-less operation, it is safe
		 * (and prudent) to perform with host CPU interrupts disabled.
		 */
		if (inject_state == EIS_CAN_INJECT) {
			inject_state = vmx_inject_vlapic(vmx, vcpu, vlapic);
		}

		/*
		 * Check for vCPU bail-out conditions.  This must be done after
		 * vmx_inject_events() to detect a triple-fault condition.
		 */
		if (vcpu_entry_bailout_checks(vmx->vm, vcpu, rip)) {
			enable_intr();
			break;
		}

		if (vcpu_run_state_pending(vm, vcpu)) {
			enable_intr();
			vm_exit_run_state(vmx->vm, vcpu, rip);
			break;
		}

		/*
		 * If subsequent activity queued events which require injection
		 * handling, take another lap to handle them.
		 */
		if (vmx_inject_recheck(vmx, vcpu, inject_state)) {
			enable_intr();
			handled = HANDLED;
			continue;
		}

#ifndef __FreeBSD__
		if ((rc = smt_acquire()) != 1) {
			enable_intr();
			vmexit->rip = rip;
			vmexit->inst_length = 0;
			if (rc == -1) {
				vmexit->exitcode = VM_EXITCODE_HT;
			} else {
				vmexit->exitcode = VM_EXITCODE_BOGUS;
				handled = HANDLED;
			}
			break;
		}

		/*
		 * If this thread has gone off-cpu due to mutex operations
		 * during vmx_run, the VMCS will have been unloaded, forcing a
		 * re-VMLAUNCH as opposed to VMRESUME.
		 */
		launched = (vmx->vmcs_state[vcpu] & VS_LAUNCHED) != 0;
		/*
		 * Restoration of the GDT limit is taken care of by
		 * vmx_savectx().  Since the maximum practical index for the
		 * IDT is 255, restoring its limits from the post-VMX-exit
		 * default of 0xffff is not a concern.
		 *
		 * Only 64-bit hypervisor callers are allowed, which forgoes
		 * the need to restore any LDT descriptor.  Toss an error to
		 * anyone attempting to break that rule.
		 */
		if (curproc->p_model != DATAMODEL_LP64) {
			smt_release();
			enable_intr();
			bzero(vmexit, sizeof (*vmexit));
			vmexit->rip = rip;
			vmexit->exitcode = VM_EXITCODE_VMX;
			vmexit->u.vmx.status = VM_FAIL_INVALID;
			handled = UNHANDLED;
			break;
		}
#else
		/*
		 * VM exits restore the base address but not the
		 * limits of GDTR and IDTR.  The VMCS only stores the
		 * base address, so VM exits set the limits to 0xffff.
		 * Save and restore the full GDTR and IDTR to restore
		 * the limits.
		 *
		 * The VMCS does not save the LDTR at all, and VM
		 * exits clear LDTR as if a NULL selector were loaded.
		 * The userspace hypervisor probably doesn't use a
		 * LDT, but save and restore it to be safe.
		 */
		sgdt(&gdtr);
		sidt(&idtr);
		ldt_sel = sldt();
#endif

		if (tpr_shadow_active) {
			vmx_tpr_shadow_enter(vlapic);
		}

		vmx_run_trace(vmx, vcpu);
		vmx_dr_enter_guest(vmxctx);
		rc = vmx_enter_guest(vmxctx, vmx, launched);
		vmx_dr_leave_guest(vmxctx);

#ifndef	__FreeBSD__
		vmx->vmcs_state[vcpu] |= VS_LAUNCHED;
		smt_release();
#else
		bare_lgdt(&gdtr);
		lidt(&idtr);
		lldt(ldt_sel);
#endif

		if (tpr_shadow_active) {
			vmx_tpr_shadow_exit(vlapic);
		}

		/* Collect some information for VM exit processing */
		vmexit->rip = rip = vmcs_guest_rip();
		vmexit->inst_length = vmexit_instruction_length();
		vmexit->u.vmx.exit_reason = exit_reason = vmcs_exit_reason();
		vmexit->u.vmx.exit_qualification = vmcs_exit_qualification();

		/* Update 'nextrip' */
		vmx->state[vcpu].nextrip = rip;

		if (rc == VMX_GUEST_VMEXIT) {
			vmx_exit_handle_nmi(vmx, vcpu, vmexit);
			enable_intr();
			handled = vmx_exit_process(vmx, vcpu, vmexit);
		} else {
			enable_intr();
			vmx_exit_inst_error(vmxctx, rc, vmexit);
		}
#ifdef	__FreeBSD__
		launched = 1;
#endif
		DTRACE_PROBE3(vmm__vexit, int, vcpu, uint64_t, rip,
		    uint32_t, exit_reason);
		rip = vmexit->rip;
	} while (handled);

	/* If a VM exit has been handled then the exitcode must be BOGUS */
	if (handled && vmexit->exitcode != VM_EXITCODE_BOGUS) {
		panic("Non-BOGUS exitcode (%d) unexpected for handled VM exit",
		    vmexit->exitcode);
	}

	VCPU_CTR1(vm, vcpu, "returning from vmx_run: exitcode %d",
	    vmexit->exitcode);

	vmcs_clear(vmcs_pa);
	vmx_msr_guest_exit(vmx, vcpu);

#ifndef __FreeBSD__
	VERIFY(vmx->vmcs_state != VS_NONE && curthread->t_preempt != 0);
	vmx->vmcs_state[vcpu] = VS_NONE;
#endif

	return (0);
}

static void
vmx_vmcleanup(void *arg)
{
	int i;
	struct vmx *vmx = arg;
	uint16_t maxcpus;

	if (apic_access_virtualization(vmx, 0))
		vm_unmap_mmio(vmx->vm, DEFAULT_APIC_BASE, PAGE_SIZE);

	maxcpus = vm_get_maxcpus(vmx->vm);
	for (i = 0; i < maxcpus; i++)
		vpid_free(vmx->state[i].vpid);

	free(vmx, M_VMX);
}

static uint64_t *
vmxctx_regptr(struct vmxctx *vmxctx, int reg)
{
	switch (reg) {
	case VM_REG_GUEST_RAX:
		return (&vmxctx->guest_rax);
	case VM_REG_GUEST_RBX:
		return (&vmxctx->guest_rbx);
	case VM_REG_GUEST_RCX:
		return (&vmxctx->guest_rcx);
	case VM_REG_GUEST_RDX:
		return (&vmxctx->guest_rdx);
	case VM_REG_GUEST_RSI:
		return (&vmxctx->guest_rsi);
	case VM_REG_GUEST_RDI:
		return (&vmxctx->guest_rdi);
	case VM_REG_GUEST_RBP:
		return (&vmxctx->guest_rbp);
	case VM_REG_GUEST_R8:
		return (&vmxctx->guest_r8);
	case VM_REG_GUEST_R9:
		return (&vmxctx->guest_r9);
	case VM_REG_GUEST_R10:
		return (&vmxctx->guest_r10);
	case VM_REG_GUEST_R11:
		return (&vmxctx->guest_r11);
	case VM_REG_GUEST_R12:
		return (&vmxctx->guest_r12);
	case VM_REG_GUEST_R13:
		return (&vmxctx->guest_r13);
	case VM_REG_GUEST_R14:
		return (&vmxctx->guest_r14);
	case VM_REG_GUEST_R15:
		return (&vmxctx->guest_r15);
	case VM_REG_GUEST_CR2:
		return (&vmxctx->guest_cr2);
	case VM_REG_GUEST_DR0:
		return (&vmxctx->guest_dr0);
	case VM_REG_GUEST_DR1:
		return (&vmxctx->guest_dr1);
	case VM_REG_GUEST_DR2:
		return (&vmxctx->guest_dr2);
	case VM_REG_GUEST_DR3:
		return (&vmxctx->guest_dr3);
	case VM_REG_GUEST_DR6:
		return (&vmxctx->guest_dr6);
	default:
		break;
	}
	return (NULL);
}

static int
vmx_getreg(void *arg, int vcpu, int reg, uint64_t *retval)
{
	int running, hostcpu, err;
	struct vmx *vmx = arg;
	uint64_t *regp;

	running = vcpu_is_running(vmx->vm, vcpu, &hostcpu);
	if (running && hostcpu != curcpu)
		panic("vmx_getreg: %s%d is running", vm_name(vmx->vm), vcpu);

	/* VMCS access not required for ctx reads */
	if ((regp = vmxctx_regptr(&vmx->ctx[vcpu], reg)) != NULL) {
		*retval = *regp;
		return (0);
	}

	if (!running) {
		vmcs_load(vmx->vmcs_pa[vcpu]);
	}

	err = EINVAL;
	if (reg == VM_REG_GUEST_INTR_SHADOW) {
		uint64_t gi = vmcs_read(VMCS_GUEST_INTERRUPTIBILITY);
		*retval = (gi & HWINTR_BLOCKING) ? 1 : 0;
		err = 0;
	} else {
		uint32_t encoding;

		encoding = vmcs_field_encoding(reg);
		if (encoding != VMCS_INVALID_ENCODING) {
			*retval = vmcs_read(encoding);
			err = 0;
		}
	}

	if (!running) {
		vmcs_clear(vmx->vmcs_pa[vcpu]);
	}

	return (err);
}

static int
vmx_setreg(void *arg, int vcpu, int reg, uint64_t val)
{
	int running, hostcpu, error;
	struct vmx *vmx = arg;
	uint64_t *regp;

	running = vcpu_is_running(vmx->vm, vcpu, &hostcpu);
	if (running && hostcpu != curcpu)
		panic("vmx_setreg: %s%d is running", vm_name(vmx->vm), vcpu);

	/* VMCS access not required for ctx writes */
	if ((regp = vmxctx_regptr(&vmx->ctx[vcpu], reg)) != NULL) {
		*regp = val;
		return (0);
	}

	if (!running) {
		vmcs_load(vmx->vmcs_pa[vcpu]);
	}

	if (reg == VM_REG_GUEST_INTR_SHADOW) {
		if (val != 0) {
			/*
			 * Forcing the vcpu into an interrupt shadow is not
			 * presently supported.
			 */
			error = EINVAL;
		} else {
			uint64_t gi;

			gi = vmcs_read(VMCS_GUEST_INTERRUPTIBILITY);
			gi &= ~HWINTR_BLOCKING;
			vmcs_write(VMCS_GUEST_INTERRUPTIBILITY, gi);
			error = 0;
		}
	} else {
		uint32_t encoding;

		error = 0;
		encoding = vmcs_field_encoding(reg);
		switch (encoding) {
		case VMCS_GUEST_IA32_EFER:
			/*
			 * If the "load EFER" VM-entry control is 1 then the
			 * value of EFER.LMA must be identical to "IA-32e mode
			 * guest" bit in the VM-entry control.
			 */
			if ((entry_ctls & VM_ENTRY_LOAD_EFER) != 0) {
				uint64_t ctls;

				ctls = vmcs_read(VMCS_ENTRY_CTLS);
				if (val & EFER_LMA) {
					ctls |= VM_ENTRY_GUEST_LMA;
				} else {
					ctls &= ~VM_ENTRY_GUEST_LMA;
				}
				vmcs_write(VMCS_ENTRY_CTLS, ctls);
			}
			vmcs_write(encoding, val);
			break;
		case VMCS_GUEST_CR0:
			/*
			 * The guest is not allowed to modify certain bits in
			 * %cr0 and %cr4.  To maintain the illusion of full
			 * control, they have shadow versions which contain the
			 * guest-perceived (via reads from the register) values
			 * as opposed to the guest-effective values.
			 *
			 * This is detailed in the SDM: Vol. 3 Ch. 24.6.6.
			 */
			vmcs_write(VMCS_CR0_SHADOW, val);
			vmcs_write(encoding, vmx_fix_cr0(val));
			break;
		case VMCS_GUEST_CR4:
			/* See above for detail on %cr4 shadowing */
			vmcs_write(VMCS_CR4_SHADOW, val);
			vmcs_write(encoding, vmx_fix_cr4(val));
			break;
		case VMCS_GUEST_CR3:
			vmcs_write(encoding, val);
			/*
			 * Invalidate the guest vcpu's TLB mappings to emulate
			 * the behavior of updating %cr3.
			 *
			 * XXX the processor retains global mappings when %cr3
			 * is updated but vmx_invvpid() does not.
			 */
			vmx_invvpid(vmx, vcpu, vmx->ctx[vcpu].pmap, running);
			break;
		case VMCS_INVALID_ENCODING:
			error = EINVAL;
			break;
		default:
			vmcs_write(encoding, val);
			break;
		}
	}

	if (!running) {
		vmcs_clear(vmx->vmcs_pa[vcpu]);
	}

	return (error);
}

static int
vmx_getdesc(void *arg, int vcpu, int seg, struct seg_desc *desc)
{
	int hostcpu, running;
	struct vmx *vmx = arg;
	uint32_t base, limit, access;

	running = vcpu_is_running(vmx->vm, vcpu, &hostcpu);
	if (running && hostcpu != curcpu)
		panic("vmx_getdesc: %s%d is running", vm_name(vmx->vm), vcpu);

	if (!running) {
		vmcs_load(vmx->vmcs_pa[vcpu]);
	}

	vmcs_seg_desc_encoding(seg, &base, &limit, &access);
	desc->base = vmcs_read(base);
	desc->limit = vmcs_read(limit);
	if (access != VMCS_INVALID_ENCODING) {
		desc->access = vmcs_read(access);
	} else {
		desc->access = 0;
	}

	if (!running) {
		vmcs_clear(vmx->vmcs_pa[vcpu]);
	}
	return (0);
}

static int
vmx_setdesc(void *arg, int vcpu, int seg, const struct seg_desc *desc)
{
	int hostcpu, running;
	struct vmx *vmx = arg;
	uint32_t base, limit, access;

	running = vcpu_is_running(vmx->vm, vcpu, &hostcpu);
	if (running && hostcpu != curcpu)
		panic("vmx_setdesc: %s%d is running", vm_name(vmx->vm), vcpu);

	if (!running) {
		vmcs_load(vmx->vmcs_pa[vcpu]);
	}

	vmcs_seg_desc_encoding(seg, &base, &limit, &access);
	vmcs_write(base, desc->base);
	vmcs_write(limit, desc->limit);
	if (access != VMCS_INVALID_ENCODING) {
		vmcs_write(access, desc->access);
	}

	if (!running) {
		vmcs_clear(vmx->vmcs_pa[vcpu]);
	}
	return (0);
}

static int
vmx_getcap(void *arg, int vcpu, int type, int *retval)
{
	struct vmx *vmx = arg;
	int vcap;
	int ret;

	ret = ENOENT;

	vcap = vmx->cap[vcpu].set;

	switch (type) {
	case VM_CAP_HALT_EXIT:
		if (cap_halt_exit)
			ret = 0;
		break;
	case VM_CAP_PAUSE_EXIT:
		if (cap_pause_exit)
			ret = 0;
		break;
	case VM_CAP_MTRAP_EXIT:
		if (cap_monitor_trap)
			ret = 0;
		break;
	case VM_CAP_ENABLE_INVPCID:
		if (cap_invpcid)
			ret = 0;
		break;
	case VM_CAP_BPT_EXIT:
		ret = 0;
		break;
	default:
		break;
	}

	if (ret == 0)
		*retval = (vcap & (1 << type)) ? 1 : 0;

	return (ret);
}

static int
vmx_setcap(void *arg, int vcpu, int type, int val)
{
	struct vmx *vmx = arg;
	uint32_t baseval, reg, flag;
	uint32_t *pptr;
	int error;

	error = ENOENT;
	pptr = NULL;

	switch (type) {
	case VM_CAP_HALT_EXIT:
		if (cap_halt_exit) {
			error = 0;
			pptr = &vmx->cap[vcpu].proc_ctls;
			baseval = *pptr;
			flag = PROCBASED_HLT_EXITING;
			reg = VMCS_PRI_PROC_BASED_CTLS;
		}
		break;
	case VM_CAP_MTRAP_EXIT:
		if (cap_monitor_trap) {
			error = 0;
			pptr = &vmx->cap[vcpu].proc_ctls;
			baseval = *pptr;
			flag = PROCBASED_MTF;
			reg = VMCS_PRI_PROC_BASED_CTLS;
		}
		break;
	case VM_CAP_PAUSE_EXIT:
		if (cap_pause_exit) {
			error = 0;
			pptr = &vmx->cap[vcpu].proc_ctls;
			baseval = *pptr;
			flag = PROCBASED_PAUSE_EXITING;
			reg = VMCS_PRI_PROC_BASED_CTLS;
		}
		break;
	case VM_CAP_ENABLE_INVPCID:
		if (cap_invpcid) {
			error = 0;
			pptr = &vmx->cap[vcpu].proc_ctls2;
			baseval = *pptr;
			flag = PROCBASED2_ENABLE_INVPCID;
			reg = VMCS_SEC_PROC_BASED_CTLS;
		}
		break;
	case VM_CAP_BPT_EXIT:
		error = 0;

		/* Don't change the bitmap if we are tracing all exceptions. */
		if (vmx->cap[vcpu].exc_bitmap != 0xffffffff) {
			pptr = &vmx->cap[vcpu].exc_bitmap;
			baseval = *pptr;
			flag = (1 << IDT_BP);
			reg = VMCS_EXCEPTION_BITMAP;
		}
		break;
	default:
		break;
	}

	if (error != 0) {
		return (error);
	}

	if (pptr != NULL) {
		if (val) {
			baseval |= flag;
		} else {
			baseval &= ~flag;
		}
		vmcs_load(vmx->vmcs_pa[vcpu]);
		vmcs_write(reg, baseval);
		vmcs_clear(vmx->vmcs_pa[vcpu]);

		/*
		 * Update optional stored flags, and record
		 * setting
		 */
		*pptr = baseval;
	}

	if (val) {
		vmx->cap[vcpu].set |= (1 << type);
	} else {
		vmx->cap[vcpu].set &= ~(1 << type);
	}

	return (0);
}

struct vlapic_vtx {
	struct vlapic	vlapic;

	/* Align to the nearest cacheline */
	uint8_t		_pad[64 - (sizeof (struct vlapic) % 64)];

	/* TMR handling state for posted interrupts */
	uint32_t	tmr_active[8];
	uint32_t	pending_level[8];
	uint32_t	pending_edge[8];

	struct pir_desc	*pir_desc;
	struct vmx	*vmx;
	uint_t	pending_prio;
	boolean_t	tmr_sync;
};

CTASSERT((offsetof(struct vlapic_vtx, tmr_active) & 63) == 0);

#define	VPR_PRIO_BIT(vpr)	(1 << ((vpr) >> 4))

static vcpu_notify_t
vmx_apicv_set_ready(struct vlapic *vlapic, int vector, bool level)
{
	struct vlapic_vtx *vlapic_vtx;
	struct pir_desc *pir_desc;
	uint32_t mask, tmrval;
	int idx;
	vcpu_notify_t notify = VCPU_NOTIFY_NONE;

	vlapic_vtx = (struct vlapic_vtx *)vlapic;
	pir_desc = vlapic_vtx->pir_desc;
	idx = vector / 32;
	mask = 1UL << (vector % 32);

	/*
	 * If the currently asserted TMRs do not match the state requested by
	 * the incoming interrupt, an exit will be required to reconcile those
	 * bits in the APIC page.  This will keep the vLAPIC behavior in line
	 * with the architecturally defined expectations.
	 *
	 * If actors of mixed types (edge and level) are racing against the same
	 * vector (toggling its TMR bit back and forth), the results could
	 * inconsistent.  Such circumstances are considered a rare edge case and
	 * are never expected to be found in the wild.
	 */
	tmrval = atomic_load_acq_int(&vlapic_vtx->tmr_active[idx]);
	if (!level) {
		if ((tmrval & mask) != 0) {
			/* Edge-triggered interrupt needs TMR de-asserted */
			atomic_set_int(&vlapic_vtx->pending_edge[idx], mask);
			atomic_store_rel_long(&pir_desc->pending, 1);
			return (VCPU_NOTIFY_EXIT);
		}
	} else {
		if ((tmrval & mask) == 0) {
			/* Level-triggered interrupt needs TMR asserted */
			atomic_set_int(&vlapic_vtx->pending_level[idx], mask);
			atomic_store_rel_long(&pir_desc->pending, 1);
			return (VCPU_NOTIFY_EXIT);
		}
	}

	/*
	 * If the interrupt request does not require manipulation of the TMRs
	 * for delivery, set it in PIR descriptor.  It cannot be inserted into
	 * the APIC page while the vCPU might be running.
	 */
	atomic_set_int(&pir_desc->pir[idx], mask);

	/*
	 * A notification is required whenever the 'pending' bit makes a
	 * transition from 0->1.
	 *
	 * Even if the 'pending' bit is already asserted, notification about
	 * the incoming interrupt may still be necessary.  For example, if a
	 * vCPU is HLTed with a high PPR, a low priority interrupt would cause
	 * the 0->1 'pending' transition with a notification, but the vCPU
	 * would ignore the interrupt for the time being.  The same vCPU would
	 * need to then be notified if a high-priority interrupt arrived which
	 * satisfied the PPR.
	 *
	 * The priorities of interrupts injected while 'pending' is asserted
	 * are tracked in a custom bitfield 'pending_prio'.  Should the
	 * to-be-injected interrupt exceed the priorities already present, the
	 * notification is sent.  The priorities recorded in 'pending_prio' are
	 * cleared whenever the 'pending' bit makes another 0->1 transition.
	 */
	if (atomic_cmpset_long(&pir_desc->pending, 0, 1) != 0) {
		notify = VCPU_NOTIFY_APIC;
		vlapic_vtx->pending_prio = 0;
	} else {
		const uint_t old_prio = vlapic_vtx->pending_prio;
		const uint_t prio_bit = VPR_PRIO_BIT(vector & APIC_TPR_INT);

		if ((old_prio & prio_bit) == 0 && prio_bit > old_prio) {
			atomic_set_int(&vlapic_vtx->pending_prio, prio_bit);
			notify = VCPU_NOTIFY_APIC;
		}
	}

	return (notify);
}

static void
vmx_apicv_accepted(struct vlapic *vlapic, int vector)
{
	/*
	 * When APICv is enabled for an instance, the traditional interrupt
	 * injection method (populating ENTRY_INTR_INFO in the VMCS) is not
	 * used and the CPU does the heavy lifting of virtual interrupt
	 * delivery.  For that reason vmx_intr_accepted() should never be called
	 * when APICv is enabled.
	 */
	panic("vmx_intr_accepted: not expected to be called");
}

static void
vmx_apicv_sync_tmr(struct vlapic *vlapic)
{
	struct vlapic_vtx *vlapic_vtx;
	const uint32_t *tmrs;

	vlapic_vtx = (struct vlapic_vtx *)vlapic;
	tmrs = &vlapic_vtx->tmr_active[0];

	if (!vlapic_vtx->tmr_sync) {
		return;
	}

	vmcs_write(VMCS_EOI_EXIT0, ((uint64_t)tmrs[1] << 32) | tmrs[0]);
	vmcs_write(VMCS_EOI_EXIT1, ((uint64_t)tmrs[3] << 32) | tmrs[2]);
	vmcs_write(VMCS_EOI_EXIT2, ((uint64_t)tmrs[5] << 32) | tmrs[4]);
	vmcs_write(VMCS_EOI_EXIT3, ((uint64_t)tmrs[7] << 32) | tmrs[6]);
	vlapic_vtx->tmr_sync = B_FALSE;
}

static void
vmx_enable_x2apic_mode_ts(struct vlapic *vlapic)
{
	struct vmx *vmx;
	uint32_t proc_ctls;
	int vcpuid;

	vcpuid = vlapic->vcpuid;
	vmx = ((struct vlapic_vtx *)vlapic)->vmx;

	proc_ctls = vmx->cap[vcpuid].proc_ctls;
	proc_ctls &= ~PROCBASED_USE_TPR_SHADOW;
	proc_ctls |= PROCBASED_CR8_LOAD_EXITING;
	proc_ctls |= PROCBASED_CR8_STORE_EXITING;
	vmx->cap[vcpuid].proc_ctls = proc_ctls;

	vmcs_load(vmx->vmcs_pa[vcpuid]);
	vmcs_write(VMCS_PRI_PROC_BASED_CTLS, proc_ctls);
	vmcs_clear(vmx->vmcs_pa[vcpuid]);
}

static void
vmx_enable_x2apic_mode_vid(struct vlapic *vlapic)
{
	struct vmx *vmx;
	uint32_t proc_ctls2;
	int vcpuid, error;

	vcpuid = vlapic->vcpuid;
	vmx = ((struct vlapic_vtx *)vlapic)->vmx;

	proc_ctls2 = vmx->cap[vcpuid].proc_ctls2;
	KASSERT((proc_ctls2 & PROCBASED2_VIRTUALIZE_APIC_ACCESSES) != 0,
	    ("%s: invalid proc_ctls2 %x", __func__, proc_ctls2));

	proc_ctls2 &= ~PROCBASED2_VIRTUALIZE_APIC_ACCESSES;
	proc_ctls2 |= PROCBASED2_VIRTUALIZE_X2APIC_MODE;
	vmx->cap[vcpuid].proc_ctls2 = proc_ctls2;

	vmcs_load(vmx->vmcs_pa[vcpuid]);
	vmcs_write(VMCS_SEC_PROC_BASED_CTLS, proc_ctls2);
	vmcs_clear(vmx->vmcs_pa[vcpuid]);

	if (vlapic->vcpuid == 0) {
		/*
		 * The nested page table mappings are shared by all vcpus
		 * so unmap the APIC access page just once.
		 */
		error = vm_unmap_mmio(vmx->vm, DEFAULT_APIC_BASE, PAGE_SIZE);
		KASSERT(error == 0, ("%s: vm_unmap_mmio error %d",
		    __func__, error));

		/*
		 * The MSR bitmap is shared by all vcpus so modify it only
		 * once in the context of vcpu 0.
		 */
		error = vmx_allow_x2apic_msrs(vmx);
		KASSERT(error == 0, ("%s: vmx_allow_x2apic_msrs error %d",
		    __func__, error));
	}
}

static void
vmx_apicv_notify(struct vlapic *vlapic, int hostcpu)
{
	psm_send_pir_ipi(hostcpu);
}

static void
vmx_apicv_sync(struct vlapic *vlapic)
{
	struct vlapic_vtx *vlapic_vtx;
	struct pir_desc *pir_desc;
	struct LAPIC *lapic;
	uint_t i;

	vlapic_vtx = (struct vlapic_vtx *)vlapic;
	pir_desc = vlapic_vtx->pir_desc;
	lapic = vlapic->apic_page;

	if (atomic_cmpset_long(&pir_desc->pending, 1, 0) == 0) {
		return;
	}

	vlapic_vtx->pending_prio = 0;

	/* Make sure the invalid (0-15) vectors are not set */
	ASSERT0(vlapic_vtx->pending_level[0] & 0xffff);
	ASSERT0(vlapic_vtx->pending_edge[0] & 0xffff);
	ASSERT0(pir_desc->pir[0] & 0xffff);

	for (i = 0; i <= 7; i++) {
		uint32_t *tmrp = &lapic->tmr0 + (i * 4);
		uint32_t *irrp = &lapic->irr0 + (i * 4);

		const uint32_t pending_level =
		    atomic_readandclear_int(&vlapic_vtx->pending_level[i]);
		const uint32_t pending_edge =
		    atomic_readandclear_int(&vlapic_vtx->pending_edge[i]);
		const uint32_t pending_inject =
		    atomic_readandclear_int(&pir_desc->pir[i]);

		if (pending_level != 0) {
			/*
			 * Level-triggered interrupts assert their corresponding
			 * bit in the TMR when queued in IRR.
			 */
			*tmrp |= pending_level;
			*irrp |= pending_level;
		}
		if (pending_edge != 0) {
			/*
			 * When queuing an edge-triggered interrupt in IRR, the
			 * corresponding bit in the TMR is cleared.
			 */
			*tmrp &= ~pending_edge;
			*irrp |= pending_edge;
		}
		if (pending_inject != 0) {
			/*
			 * Interrupts which do not require a change to the TMR
			 * (because it already matches the necessary state) can
			 * simply be queued in IRR.
			 */
			*irrp |= pending_inject;
		}

		if (*tmrp != vlapic_vtx->tmr_active[i]) {
			/* Check if VMX EOI triggers require updating. */
			vlapic_vtx->tmr_active[i] = *tmrp;
			vlapic_vtx->tmr_sync = B_TRUE;
		}
	}
}

static void
vmx_tpr_shadow_enter(struct vlapic *vlapic)
{
	/*
	 * When TPR shadowing is enabled, VMX will initiate a guest exit if its
	 * TPR falls below a threshold priority.  That threshold is set to the
	 * current TPR priority, since guest interrupt status should be
	 * re-evaluated if its TPR is set lower.
	 */
	vmcs_write(VMCS_TPR_THRESHOLD, vlapic_get_cr8(vlapic));
}

static void
vmx_tpr_shadow_exit(struct vlapic *vlapic)
{
	/*
	 * Unlike full APICv, where changes to the TPR are reflected in the PPR,
	 * with TPR shadowing, that duty is relegated to the VMM.  Upon exit,
	 * the PPR is updated to reflect any change in the TPR here.
	 */
	vlapic_sync_tpr(vlapic);
}

static struct vlapic *
vmx_vlapic_init(void *arg, int vcpuid)
{
	struct vmx *vmx;
	struct vlapic *vlapic;
	struct vlapic_vtx *vlapic_vtx;

	vmx = arg;

	vlapic = malloc(sizeof (struct vlapic_vtx), M_VLAPIC,
	    M_WAITOK | M_ZERO);
	vlapic->vm = vmx->vm;
	vlapic->vcpuid = vcpuid;
	vlapic->apic_page = (struct LAPIC *)&vmx->apic_page[vcpuid];

	vlapic_vtx = (struct vlapic_vtx *)vlapic;
	vlapic_vtx->pir_desc = &vmx->pir_desc[vcpuid];
	vlapic_vtx->vmx = vmx;

	if (vmx_cap_en(vmx, VMX_CAP_TPR_SHADOW)) {
		vlapic->ops.enable_x2apic_mode = vmx_enable_x2apic_mode_ts;
	}
	if (vmx_cap_en(vmx, VMX_CAP_APICV)) {
		vlapic->ops.set_intr_ready = vmx_apicv_set_ready;
		vlapic->ops.sync_state = vmx_apicv_sync;
		vlapic->ops.intr_accepted = vmx_apicv_accepted;
		vlapic->ops.enable_x2apic_mode = vmx_enable_x2apic_mode_vid;

		if (vmx_cap_en(vmx, VMX_CAP_APICV_PIR)) {
			vlapic->ops.post_intr = vmx_apicv_notify;
		}
	}

	vlapic_init(vlapic);

	return (vlapic);
}

static void
vmx_vlapic_cleanup(void *arg, struct vlapic *vlapic)
{

	vlapic_cleanup(vlapic);
	free(vlapic, M_VLAPIC);
}

#ifndef __FreeBSD__
static void
vmx_savectx(void *arg, int vcpu)
{
	struct vmx *vmx = arg;

	if ((vmx->vmcs_state[vcpu] & VS_LOADED) != 0) {
		vmcs_clear(vmx->vmcs_pa[vcpu]);
		vmx_msr_guest_exit(vmx, vcpu);
		/*
		 * Having VMCLEARed the VMCS, it can no longer be re-entered
		 * with VMRESUME, but must be VMLAUNCHed again.
		 */
		vmx->vmcs_state[vcpu] &= ~VS_LAUNCHED;
	}

	reset_gdtr_limit();
}

static void
vmx_restorectx(void *arg, int vcpu)
{
	struct vmx *vmx = arg;

	ASSERT0(vmx->vmcs_state[vcpu] & VS_LAUNCHED);

	if ((vmx->vmcs_state[vcpu] & VS_LOADED) != 0) {
		vmx_msr_guest_enter(vmx, vcpu);
		vmcs_load(vmx->vmcs_pa[vcpu]);
	}
}
#endif /* __FreeBSD__ */

struct vmm_ops vmm_ops_intel = {
	.init		= vmx_init,
	.cleanup	= vmx_cleanup,
	.resume		= vmx_restore,
	.vminit		= vmx_vminit,
	.vmrun		= vmx_run,
	.vmcleanup	= vmx_vmcleanup,
	.vmgetreg	= vmx_getreg,
	.vmsetreg	= vmx_setreg,
	.vmgetdesc	= vmx_getdesc,
	.vmsetdesc	= vmx_setdesc,
	.vmgetcap	= vmx_getcap,
	.vmsetcap	= vmx_setcap,
	.vmspace_alloc	= ept_vmspace_alloc,
	.vmspace_free	= ept_vmspace_free,
	.vlapic_init	= vmx_vlapic_init,
	.vlapic_cleanup	= vmx_vlapic_cleanup,

#ifndef __FreeBSD__
	.vmsavectx	= vmx_savectx,
	.vmrestorectx	= vmx_restorectx,
#endif
};

#ifndef __FreeBSD__
/* Side-effect free HW validation derived from checks in vmx_init. */
int
vmx_x86_supported(const char **msg)
{
	int error;
	uint32_t tmp;

	ASSERT(msg != NULL);

	/* Check support for primary processor-based VM-execution controls */
	error = vmx_set_ctlreg(MSR_VMX_PROCBASED_CTLS,
	    MSR_VMX_TRUE_PROCBASED_CTLS, PROCBASED_CTLS_ONE_SETTING,
	    PROCBASED_CTLS_ZERO_SETTING, &tmp);
	if (error) {
		*msg = "processor does not support desired primary "
		    "processor-based controls";
		return (error);
	}

	/* Check support for secondary processor-based VM-execution controls */
	error = vmx_set_ctlreg(MSR_VMX_PROCBASED_CTLS2,
	    MSR_VMX_PROCBASED_CTLS2, PROCBASED_CTLS2_ONE_SETTING,
	    PROCBASED_CTLS2_ZERO_SETTING, &tmp);
	if (error) {
		*msg = "processor does not support desired secondary "
		    "processor-based controls";
		return (error);
	}

	/* Check support for pin-based VM-execution controls */
	error = vmx_set_ctlreg(MSR_VMX_PINBASED_CTLS,
	    MSR_VMX_TRUE_PINBASED_CTLS, PINBASED_CTLS_ONE_SETTING,
	    PINBASED_CTLS_ZERO_SETTING, &tmp);
	if (error) {
		*msg = "processor does not support desired pin-based controls";
		return (error);
	}

	/* Check support for VM-exit controls */
	error = vmx_set_ctlreg(MSR_VMX_EXIT_CTLS, MSR_VMX_TRUE_EXIT_CTLS,
	    VM_EXIT_CTLS_ONE_SETTING, VM_EXIT_CTLS_ZERO_SETTING, &tmp);
	if (error) {
		*msg = "processor does not support desired exit controls";
		return (error);
	}

	/* Check support for VM-entry controls */
	error = vmx_set_ctlreg(MSR_VMX_ENTRY_CTLS, MSR_VMX_TRUE_ENTRY_CTLS,
	    VM_ENTRY_CTLS_ONE_SETTING, VM_ENTRY_CTLS_ZERO_SETTING, &tmp);
	if (error) {
		*msg = "processor does not support desired entry controls";
		return (error);
	}

	/* Unrestricted guest is nominally optional, but not for us. */
	error = vmx_set_ctlreg(MSR_VMX_PROCBASED_CTLS2, MSR_VMX_PROCBASED_CTLS2,
	    PROCBASED2_UNRESTRICTED_GUEST, 0, &tmp);
	if (error) {
		*msg = "processor does not support desired unrestricted guest "
		    "controls";
		return (error);
	}

	return (0);
}
#endif
