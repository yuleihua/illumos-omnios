/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2011 NetApp, Inc.
 * All rights reserved.
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
 * Copyright 2020 Joyent, Inc.
 */

#ifndef	_VMM_DEV_H_
#define	_VMM_DEV_H_

#include <machine/vmm.h>

struct vm_memmap {
	vm_paddr_t	gpa;
	int		segid;		/* memory segment */
	vm_ooffset_t	segoff;		/* offset into memory segment */
	size_t		len;		/* mmap length */
	int		prot;		/* RWX */
	int		flags;
};
#define	VM_MEMMAP_F_WIRED	0x01
#define	VM_MEMMAP_F_IOMMU	0x02

#define	VM_MEMSEG_NAME(m)	((m)->name[0] != '\0' ? (m)->name : NULL)
struct vm_memseg {
	int		segid;
	size_t		len;
	char		name[SPECNAMELEN + 1];
};

struct vm_register {
	int		cpuid;
	int		regnum;		/* enum vm_reg_name */
	uint64_t	regval;
};

struct vm_seg_desc {			/* data or code segment */
	int		cpuid;
	int		regnum;		/* enum vm_reg_name */
	struct seg_desc desc;
};

struct vm_register_set {
	int		cpuid;
	unsigned int	count;
	const int	*regnums;	/* enum vm_reg_name */
	uint64_t	*regvals;
};

struct vm_exception {
	int		cpuid;
	int		vector;
	uint32_t	error_code;
	int		error_code_valid;
	int		restart_instruction;
};

struct vm_lapic_msi {
	uint64_t	msg;
	uint64_t	addr;
};

struct vm_lapic_irq {
	int		cpuid;
	int		vector;
};

struct vm_ioapic_irq {
	int		irq;
};

struct vm_isa_irq {
	int		atpic_irq;
	int		ioapic_irq;
};

struct vm_isa_irq_trigger {
	int		atpic_irq;
	enum vm_intr_trigger trigger;
};

struct vm_capability {
	int		cpuid;
	enum vm_cap_type captype;
	int		capval;
	int		allcpus;
};

struct vm_pptdev {
	int		pptfd;
};

struct vm_pptdev_mmio {
	int		pptfd;
	vm_paddr_t	gpa;
	vm_paddr_t	hpa;
	size_t		len;
};

struct vm_pptdev_msi {
	int		vcpu;
	int		pptfd;
	int		numvec;		/* 0 means disabled */
	uint64_t	msg;
	uint64_t	addr;
};

struct vm_pptdev_msix {
	int		vcpu;
	int		pptfd;
	int		idx;
	uint64_t	msg;
	uint32_t	vector_control;
	uint64_t	addr;
};

struct vm_pptdev_limits {
	int		pptfd;
	int		msi_limit;
	int		msix_limit;
};

struct vm_nmi {
	int		cpuid;
};

#ifdef __FreeBSD__
#define	MAX_VM_STATS	64
#else
#define	MAX_VM_STATS	(64 + VM_MAXCPU)
#endif

struct vm_stats {
	int		cpuid;				/* in */
	int		num_entries;			/* out */
	struct timeval	tv;
	uint64_t	statbuf[MAX_VM_STATS];
};

struct vm_stat_desc {
	int		index;				/* in */
	char		desc[128];			/* out */
};

struct vm_x2apic {
	int			cpuid;
	enum x2apic_state	state;
};

struct vm_gpa_pte {
	uint64_t	gpa;				/* in */
	uint64_t	pte[4];				/* out */
	int		ptenum;
};

struct vm_hpet_cap {
	uint32_t	capabilities;	/* lower 32 bits of HPET capabilities */
};

struct vm_suspend {
	enum vm_suspend_how how;
};

struct vm_gla2gpa {
	int		vcpuid;		/* inputs */
	int		prot;		/* PROT_READ or PROT_WRITE */
	uint64_t	gla;
	struct vm_guest_paging paging;
	int		fault;		/* outputs */
	uint64_t	gpa;
};

struct vm_activate_cpu {
	int		vcpuid;
};

struct vm_cpuset {
	int		which;
	int		cpusetsize;
#ifndef _KERNEL
	cpuset_t	*cpus;
#else
	void		*cpus;
#endif
};
#define	VM_ACTIVE_CPUS		0
#define	VM_SUSPENDED_CPUS	1
#define	VM_DEBUG_CPUS		2

struct vm_intinfo {
	int		vcpuid;
	uint64_t	info1;
	uint64_t	info2;
};

struct vm_rtc_time {
	time_t		secs;
};

struct vm_rtc_data {
	int		offset;
	uint8_t		value;
};

struct vm_devmem_offset {
	int		segid;
	off_t		offset;
};

struct vm_cpu_topology {
	uint16_t	sockets;
	uint16_t	cores;
	uint16_t	threads;
	uint16_t	maxcpus;
};

struct vm_readwrite_kernemu_device {
	int		vcpuid;
	unsigned	access_width : 3;
	unsigned	_unused : 29;
	uint64_t	gpa;
	uint64_t	value;
};
_Static_assert(sizeof(struct vm_readwrite_kernemu_device) == 24, "ABI");

enum vcpu_reset_kind {
	VRK_RESET = 0,
	/*
	 * The reset performed by an INIT IPI clears much of the CPU state, but
	 * some portions are left untouched, unlike VRK_RESET, which represents
	 * a "full" reset as if the system was freshly powered on.
	 */
	VRK_INIT = 1,
};

struct vm_vcpu_reset {
	int		vcpuid;
	uint32_t	kind;	/* contains: enum vcpu_reset_kind */
};

struct vm_run_state {
	int		vcpuid;
	uint32_t	state;	/* of enum cpu_init_status type */
	uint8_t		sipi_vector;	/* vector of SIPI, if any */
	uint8_t		_pad[3];
};

#define	VMMCTL_IOC_BASE		(('V' << 16) | ('M' << 8))
#define	VMM_IOC_BASE		(('v' << 16) | ('m' << 8))
#define	VMM_LOCK_IOC_BASE	(('v' << 16) | ('l' << 8))
#define	VMM_CPU_IOC_BASE	(('v' << 16) | ('p' << 8))

/* Operations performed on the vmmctl device */
#define	VMM_CREATE_VM		(VMMCTL_IOC_BASE | 0x01)
#define	VMM_DESTROY_VM		(VMMCTL_IOC_BASE | 0x02)
#define	VMM_VM_SUPPORTED	(VMMCTL_IOC_BASE | 0x03)

/* Operations performed in the context of a given vCPU */
#define	VM_RUN				(VMM_CPU_IOC_BASE | 0x01)
#define	VM_SET_REGISTER			(VMM_CPU_IOC_BASE | 0x02)
#define	VM_GET_REGISTER			(VMM_CPU_IOC_BASE | 0x03)
#define	VM_SET_SEGMENT_DESCRIPTOR	(VMM_CPU_IOC_BASE | 0x04)
#define	VM_GET_SEGMENT_DESCRIPTOR	(VMM_CPU_IOC_BASE | 0x05)
#define	VM_SET_REGISTER_SET		(VMM_CPU_IOC_BASE | 0x06)
#define	VM_GET_REGISTER_SET		(VMM_CPU_IOC_BASE | 0x07)
#define	VM_INJECT_EXCEPTION		(VMM_CPU_IOC_BASE | 0x08)
#define	VM_SET_CAPABILITY		(VMM_CPU_IOC_BASE | 0x09)
#define	VM_GET_CAPABILITY		(VMM_CPU_IOC_BASE | 0x0a)
#define	VM_PPTDEV_MSI			(VMM_CPU_IOC_BASE | 0x0b)
#define	VM_PPTDEV_MSIX			(VMM_CPU_IOC_BASE | 0x0c)
#define	VM_SET_X2APIC_STATE		(VMM_CPU_IOC_BASE | 0x0d)
#define	VM_GLA2GPA			(VMM_CPU_IOC_BASE | 0x0e)
#define	VM_GLA2GPA_NOFAULT		(VMM_CPU_IOC_BASE | 0x0f)
#define	VM_ACTIVATE_CPU			(VMM_CPU_IOC_BASE | 0x10)
#define	VM_SET_INTINFO			(VMM_CPU_IOC_BASE | 0x11)
#define	VM_GET_INTINFO			(VMM_CPU_IOC_BASE | 0x12)
#define	VM_RESTART_INSTRUCTION		(VMM_CPU_IOC_BASE | 0x13)
#define	VM_SET_KERNEMU_DEV		(VMM_CPU_IOC_BASE | 0x14)
#define	VM_GET_KERNEMU_DEV		(VMM_CPU_IOC_BASE | 0x15)
#define	VM_RESET_CPU			(VMM_CPU_IOC_BASE | 0x16)
#define	VM_GET_RUN_STATE		(VMM_CPU_IOC_BASE | 0x17)
#define	VM_SET_RUN_STATE		(VMM_CPU_IOC_BASE | 0x18)

/* Operations requiring write-locking the VM */
#define	VM_REINIT		(VMM_LOCK_IOC_BASE | 0x01)
#define	VM_BIND_PPTDEV		(VMM_LOCK_IOC_BASE | 0x02)
#define	VM_UNBIND_PPTDEV	(VMM_LOCK_IOC_BASE | 0x03)
#define	VM_MAP_PPTDEV_MMIO	(VMM_LOCK_IOC_BASE | 0x04)
#define	VM_ALLOC_MEMSEG		(VMM_LOCK_IOC_BASE | 0x05)
#define	VM_MMAP_MEMSEG		(VMM_LOCK_IOC_BASE | 0x06)
#define	VM_PMTMR_LOCATE		(VMM_LOCK_IOC_BASE | 0x07)

#define	VM_WRLOCK_CYCLE		(VMM_LOCK_IOC_BASE | 0xff)

/* All other ioctls */
#define	VM_GET_GPA_PMAP			(VMM_IOC_BASE | 0x01)
#define	VM_GET_MEMSEG			(VMM_IOC_BASE | 0x02)
#define	VM_MMAP_GETNEXT			(VMM_IOC_BASE | 0x03)

#define	VM_LAPIC_IRQ			(VMM_IOC_BASE | 0x04)
#define	VM_LAPIC_LOCAL_IRQ		(VMM_IOC_BASE | 0x05)
#define	VM_LAPIC_MSI			(VMM_IOC_BASE | 0x06)

#define	VM_IOAPIC_ASSERT_IRQ		(VMM_IOC_BASE | 0x07)
#define	VM_IOAPIC_DEASSERT_IRQ		(VMM_IOC_BASE | 0x08)
#define	VM_IOAPIC_PULSE_IRQ		(VMM_IOC_BASE | 0x09)

#define	VM_ISA_ASSERT_IRQ		(VMM_IOC_BASE | 0x0a)
#define	VM_ISA_DEASSERT_IRQ		(VMM_IOC_BASE | 0x0b)
#define	VM_ISA_PULSE_IRQ		(VMM_IOC_BASE | 0x0c)
#define	VM_ISA_SET_IRQ_TRIGGER		(VMM_IOC_BASE | 0x0d)

#define	VM_RTC_WRITE			(VMM_IOC_BASE | 0x0e)
#define	VM_RTC_READ			(VMM_IOC_BASE | 0x0f)
#define	VM_RTC_SETTIME			(VMM_IOC_BASE | 0x10)
#define	VM_RTC_GETTIME			(VMM_IOC_BASE | 0x11)

#define	VM_SUSPEND			(VMM_IOC_BASE | 0x12)

#define	VM_IOAPIC_PINCOUNT		(VMM_IOC_BASE | 0x13)
#define	VM_GET_PPTDEV_LIMITS		(VMM_IOC_BASE | 0x14)
#define	VM_GET_HPET_CAPABILITIES	(VMM_IOC_BASE | 0x15)

#define	VM_STATS_IOC			(VMM_IOC_BASE | 0x16)
#define	VM_STAT_DESC			(VMM_IOC_BASE | 0x17)

#define	VM_INJECT_NMI			(VMM_IOC_BASE | 0x18)
#define	VM_GET_X2APIC_STATE		(VMM_IOC_BASE | 0x19)
#define	VM_SET_TOPOLOGY			(VMM_IOC_BASE | 0x1a)
#define	VM_GET_TOPOLOGY			(VMM_IOC_BASE | 0x1b)
#define	VM_GET_CPUS			(VMM_IOC_BASE | 0x1c)
#define	VM_SUSPEND_CPU			(VMM_IOC_BASE | 0x1d)
#define	VM_RESUME_CPU			(VMM_IOC_BASE | 0x1e)

#define	VM_PPTDEV_DISABLE_MSIX		(VMM_IOC_BASE | 0x1f)
#define	VM_ARC_RESV			(VMM_IOC_BASE | 0xfe)

#define	VM_DEVMEM_GETOFFSET		(VMM_IOC_BASE | 0xff)

#define	VMM_CTL_DEV		"/dev/vmmctl"

#endif
