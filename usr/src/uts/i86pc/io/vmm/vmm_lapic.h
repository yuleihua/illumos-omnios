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
 * Copyright 2014 Pluribus Networks Inc.
 */

#ifndef _VMM_LAPIC_H_
#define	_VMM_LAPIC_H_

struct vm;

bool lapic_msr(uint_t num);
int lapic_rdmsr(struct vm *vm, int cpu, uint_t msr, uint64_t *rval);
int lapic_wrmsr(struct vm *vm, int cpu, uint_t msr, uint64_t wval);

int lapic_mmio_read(struct vm *vm, int cpu, uint64_t gpa, uint64_t *rval,
    int size);
int lapic_mmio_write(struct vm *vm, int cpu, uint64_t gpa, uint64_t wval,
    int size);

/*
 * Signals to the LAPIC that an interrupt at 'vector' needs to be generated
 * to the 'cpu', the state is recorded in IRR.
 */
int lapic_set_intr(struct vm *vm, int cpu, int vector, bool trig);

#define	LAPIC_TRIG_LEVEL	true
#define	LAPIC_TRIG_EDGE		false
static __inline int
lapic_intr_level(struct vm *vm, int cpu, int vector)
{

	return (lapic_set_intr(vm, cpu, vector, LAPIC_TRIG_LEVEL));
}

static __inline int
lapic_intr_edge(struct vm *vm, int cpu, int vector)
{

	return (lapic_set_intr(vm, cpu, vector, LAPIC_TRIG_EDGE));
}

/*
 * Triggers the LAPIC local interrupt (LVT) 'vector' on 'cpu'.  'cpu' can
 * be set to -1 to trigger the interrupt on all CPUs.
 */
int lapic_set_local_intr(struct vm *vm, int cpu, int vector);

int lapic_intr_msi(struct vm *vm, uint64_t addr, uint64_t msg);

#endif
