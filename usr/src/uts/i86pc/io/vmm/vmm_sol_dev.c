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
/* This file is dual-licensed; see usr/src/contrib/bhyve/LICENSE */

/*
 * Copyright 2015 Pluribus Networks Inc.
 * Copyright 2020 Joyent, Inc.
 * Copyright 2020 OmniOS Community Edition (OmniOSce) Association.
 * Copyright 2020 Oxide Computer Company
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/cpuvar.h>
#include <sys/ioccom.h>
#include <sys/stat.h>
#include <sys/vmsystm.h>
#include <sys/ddi.h>
#include <sys/mkdev.h>
#include <sys/sunddi.h>
#include <sys/fs/dv_node.h>
#include <sys/cpuset.h>
#include <sys/id_space.h>
#include <sys/fs/sdev_plugin.h>
#include <sys/smt.h>

#include <sys/kernel.h>
#include <sys/hma.h>
#include <sys/x86_archext.h>
#include <x86/apicreg.h>

#include <sys/vmm.h>
#include <sys/vmm_kernel.h>
#include <sys/vmm_instruction_emul.h>
#include <sys/vmm_dev.h>
#include <sys/vmm_impl.h>
#include <sys/vmm_drv.h>

#include <vm/vm.h>
#include <vm/seg_dev.h>

#include "io/ppt.h"
#include "io/vatpic.h"
#include "io/vioapic.h"
#include "io/vrtc.h"
#include "io/vhpet.h"
#include "io/vpmtmr.h"
#include "vmm_lapic.h"
#include "vmm_stat.h"
#include "vmm_util.h"
#include "vm/vm_glue.h"

/*
 * Locking details:
 *
 * Driver-wide data (vmmdev_*) , including HMA and sdev registration, is
 * protected by vmmdev_mtx.  The list of vmm_softc_t instances and related data
 * (vmm_*) are protected by vmm_mtx.  Actions requiring both locks must acquire
 * vmmdev_mtx before vmm_mtx.  The sdev plugin functions must not attempt to
 * acquire vmmdev_mtx, as they could deadlock with plugin unregistration.
 */

static kmutex_t		vmmdev_mtx;
static dev_info_t	*vmmdev_dip;
static hma_reg_t	*vmmdev_hma_reg;
static uint_t		vmmdev_hma_ref;
static sdev_plugin_hdl_t vmmdev_sdev_hdl;

static kmutex_t		vmm_mtx;
static list_t		vmm_list;
static list_t		vmm_destroy_list;
static id_space_t	*vmm_minors;
static void		*vmm_statep;

static const char *vmmdev_hvm_name = "bhyve";

/* For sdev plugin (/dev) */
#define	VMM_SDEV_ROOT "/dev/vmm"

/* From uts/i86pc/io/vmm/intel/vmx.c */
extern int vmx_x86_supported(const char **);

/* Holds and hooks from drivers external to vmm */
struct vmm_hold {
	list_node_t	vmh_node;
	vmm_softc_t	*vmh_sc;
	boolean_t	vmh_release_req;
	uint_t		vmh_ioport_hook_cnt;
};

struct vmm_lease {
	list_node_t		vml_node;
	struct vm		*vml_vm;
	boolean_t		vml_expired;
	boolean_t		(*vml_expire_func)(void *);
	void			*vml_expire_arg;
	list_node_t		vml_expire_node;
	struct vmm_hold		*vml_hold;
};

static int vmm_drv_block_hook(vmm_softc_t *, boolean_t);
static void vmm_lease_break_locked(vmm_softc_t *, vmm_lease_t *);

static int
vmmdev_get_memseg(vmm_softc_t *sc, struct vm_memseg *mseg)
{
	int error;
	bool sysmem;

	error = vm_get_memseg(sc->vmm_vm, mseg->segid, &mseg->len, &sysmem,
	    NULL);
	if (error || mseg->len == 0)
		return (error);

	if (!sysmem) {
		vmm_devmem_entry_t *de;
		list_t *dl = &sc->vmm_devmem_list;

		for (de = list_head(dl); de != NULL; de = list_next(dl, de)) {
			if (de->vde_segid == mseg->segid) {
				break;
			}
		}
		if (de != NULL) {
			(void) strlcpy(mseg->name, de->vde_name,
			    sizeof (mseg->name));
		}
	} else {
		bzero(mseg->name, sizeof (mseg->name));
	}

	return (error);
}

/*
 * The 'devmem' hack:
 *
 * On native FreeBSD, bhyve consumers are allowed to create 'devmem' segments
 * in the vm which appear with their own name related to the vm under /dev.
 * Since this would be a hassle from an sdev perspective and would require a
 * new cdev interface (or complicate the existing one), we choose to implement
 * this in a different manner.  When 'devmem' mappings are created, an
 * identifying off_t is communicated back out to userspace.  That off_t,
 * residing above the normal guest memory space, can be used to mmap the
 * 'devmem' mapping from the already-open vm device.
 */

static int
vmmdev_devmem_create(vmm_softc_t *sc, struct vm_memseg *mseg, const char *name)
{
	off_t map_offset;
	vmm_devmem_entry_t *entry;

	if (list_is_empty(&sc->vmm_devmem_list)) {
		map_offset = VM_DEVMEM_START;
	} else {
		entry = list_tail(&sc->vmm_devmem_list);
		map_offset = entry->vde_off + entry->vde_len;
		if (map_offset < entry->vde_off) {
			/* Do not tolerate overflow */
			return (ERANGE);
		}
		/*
		 * XXXJOY: We could choose to search the list for duplicate
		 * names and toss an error.  Since we're using the offset
		 * method for now, it does not make much of a difference.
		 */
	}

	entry = kmem_zalloc(sizeof (*entry), KM_SLEEP);
	entry->vde_segid = mseg->segid;
	entry->vde_len = mseg->len;
	entry->vde_off = map_offset;
	(void) strlcpy(entry->vde_name, name, sizeof (entry->vde_name));
	list_insert_tail(&sc->vmm_devmem_list, entry);

	return (0);
}

static boolean_t
vmmdev_devmem_segid(vmm_softc_t *sc, off_t off, off_t len, int *segidp,
    off_t *map_offp)
{
	list_t *dl = &sc->vmm_devmem_list;
	vmm_devmem_entry_t *de = NULL;
	const off_t map_end = off + len;

	VERIFY(off >= VM_DEVMEM_START);

	if (map_end < off) {
		/* No match on overflow */
		return (B_FALSE);
	}

	for (de = list_head(dl); de != NULL; de = list_next(dl, de)) {
		const off_t item_end = de->vde_off + de->vde_len;

		if (de->vde_off <= off && item_end >= map_end) {
			*segidp = de->vde_segid;
			*map_offp = off - de->vde_off;
			return (B_TRUE);
		}
	}
	return (B_FALSE);
}

static void
vmmdev_devmem_purge(vmm_softc_t *sc)
{
	vmm_devmem_entry_t *entry;

	while ((entry = list_remove_head(&sc->vmm_devmem_list)) != NULL) {
		kmem_free(entry, sizeof (*entry));
	}
}

static int
vmmdev_alloc_memseg(vmm_softc_t *sc, struct vm_memseg *mseg)
{
	int error;
	bool sysmem = true;

	if (VM_MEMSEG_NAME(mseg)) {
		sysmem = false;
	}
	error = vm_alloc_memseg(sc->vmm_vm, mseg->segid, mseg->len, sysmem);

	if (error == 0 && VM_MEMSEG_NAME(mseg)) {
		/*
		 * Rather than create a whole fresh device from which userspace
		 * can mmap this segment, instead make it available at an
		 * offset above where the main guest memory resides.
		 */
		error = vmmdev_devmem_create(sc, mseg, mseg->name);
		if (error != 0) {
			vm_free_memseg(sc->vmm_vm, mseg->segid);
		}
	}
	return (error);
}

/*
 * Resource Locking and Exclusion
 *
 * Much of bhyve depends on key portions of VM state, such as the guest memory
 * map, to remain unchanged while the guest is running.  As ported from
 * FreeBSD, the initial strategy for this resource exclusion hinged on gating
 * access to the instance vCPUs.  Threads acting on a single vCPU, like those
 * performing the work of actually running the guest in VMX/SVM, would lock
 * only that vCPU during ioctl() entry.  For ioctls which would change VM-wide
 * state, all of the vCPUs would be first locked, ensuring that the
 * operation(s) could complete without any other threads stumbling into
 * intermediate states.
 *
 * This approach is largely effective for bhyve.  Common operations, such as
 * running the vCPUs, steer clear of lock contention.  The model begins to
 * break down for operations which do not occur in the context of a specific
 * vCPU.  LAPIC MSI delivery, for example, may be initiated from a worker
 * thread in the bhyve process.  In order to properly protect those vCPU-less
 * operations from encountering invalid states, additional locking is required.
 * This was solved by forcing those operations to lock the VM_MAXCPU-1 vCPU.
 * It does mean that class of operations will be serialized on locking the
 * specific vCPU and that instances sized at VM_MAXCPU will potentially see
 * undue contention on the VM_MAXCPU-1 vCPU.
 *
 * In order to address the shortcomings of this model, the concept of a
 * read/write lock has been added to bhyve.  Operations which change
 * fundamental aspects of a VM (such as the memory map) must acquire the write
 * lock, which also implies locking all of the vCPUs and waiting for all read
 * lock holders to release.  While it increases the cost and waiting time for
 * those few operations, it allows most hot-path operations on the VM (which
 * depend on its configuration remaining stable) to occur with minimal locking.
 *
 * Consumers of the Driver API (see below) are a special case when it comes to
 * this locking, since they may hold a read lock via the drv_lease mechanism
 * for an extended period of time.  Rather than forcing those consumers to
 * continuously poll for a write lock attempt, the lease system forces them to
 * provide a release callback to trigger their clean-up (and potential later
 * reacquisition) of the read lock.
 */

static void
vcpu_lock_one(vmm_softc_t *sc, int vcpu)
{
	ASSERT(vcpu >= 0 && vcpu < VM_MAXCPU);

	/*
	 * Since this state transition is utilizing from_idle=true, it should
	 * not fail, but rather block until it can be successful.
	 */
	VERIFY0(vcpu_set_state(sc->vmm_vm, vcpu, VCPU_FROZEN, true));
}

static void
vcpu_unlock_one(vmm_softc_t *sc, int vcpu)
{
	ASSERT(vcpu >= 0 && vcpu < VM_MAXCPU);

	VERIFY3U(vcpu_get_state(sc->vmm_vm, vcpu, NULL), ==, VCPU_FROZEN);
	vcpu_set_state(sc->vmm_vm, vcpu, VCPU_IDLE, false);
}

static void
vmm_read_lock(vmm_softc_t *sc)
{
	rw_enter(&sc->vmm_rwlock, RW_READER);
}

static void
vmm_read_unlock(vmm_softc_t *sc)
{
	rw_exit(&sc->vmm_rwlock);
}

static void
vmm_write_lock(vmm_softc_t *sc)
{
	int maxcpus;

	/* First lock all the vCPUs */
	maxcpus = vm_get_maxcpus(sc->vmm_vm);
	for (int vcpu = 0; vcpu < maxcpus; vcpu++) {
		vcpu_lock_one(sc, vcpu);
	}

	mutex_enter(&sc->vmm_lease_lock);
	VERIFY3U(sc->vmm_lease_blocker, !=, UINT_MAX);
	sc->vmm_lease_blocker++;
	if (sc->vmm_lease_blocker == 1) {
		list_t *list = &sc->vmm_lease_list;
		vmm_lease_t *lease = list_head(list);

		while (lease != NULL) {
			boolean_t sync_break = B_FALSE;

			if (!lease->vml_expired) {
				void *arg = lease->vml_expire_arg;
				lease->vml_expired = B_TRUE;
				sync_break = lease->vml_expire_func(arg);
			}

			if (sync_break) {
				vmm_lease_t *next;

				/*
				 * These leases which are synchronously broken
				 * result in vmm_read_unlock() calls from a
				 * different thread than the corresponding
				 * vmm_read_lock().  This is acceptable, given
				 * that the rwlock underpinning the whole
				 * mechanism tolerates the behavior.  This
				 * flexibility is _only_ afforded to VM read
				 * lock (RW_READER) holders.
				 */
				next = list_next(list, lease);
				vmm_lease_break_locked(sc, lease);
				lease = next;
			} else {
				lease = list_next(list, lease);
			}
		}
	}
	mutex_exit(&sc->vmm_lease_lock);

	rw_enter(&sc->vmm_rwlock, RW_WRITER);
	/*
	 * For now, the 'maxcpus' value for an instance is fixed at the
	 * compile-time constant of VM_MAXCPU at creation.  If this changes in
	 * the future, allowing for dynamic vCPU resource sizing, acquisition
	 * of the write lock will need to be wary of such changes.
	 */
	VERIFY(maxcpus == vm_get_maxcpus(sc->vmm_vm));
}

static void
vmm_write_unlock(vmm_softc_t *sc)
{
	int maxcpus;

	mutex_enter(&sc->vmm_lease_lock);
	VERIFY3U(sc->vmm_lease_blocker, !=, 0);
	sc->vmm_lease_blocker--;
	if (sc->vmm_lease_blocker == 0) {
		cv_broadcast(&sc->vmm_lease_cv);
	}
	mutex_exit(&sc->vmm_lease_lock);

	/*
	 * The VM write lock _must_ be released from the same thread it was
	 * acquired in, unlike the read lock.
	 */
	VERIFY(rw_write_held(&sc->vmm_rwlock));
	rw_exit(&sc->vmm_rwlock);

	/* Unlock all the vCPUs */
	maxcpus = vm_get_maxcpus(sc->vmm_vm);
	for (int vcpu = 0; vcpu < maxcpus; vcpu++) {
		vcpu_unlock_one(sc, vcpu);
	}
}

static int
vmmdev_do_ioctl(vmm_softc_t *sc, int cmd, intptr_t arg, int md,
    cred_t *credp, int *rvalp)
{
	int error = 0, vcpu = -1;
	void *datap = (void *)arg;
	enum vm_lock_type {
		LOCK_NONE = 0,
		LOCK_VCPU,
		LOCK_READ_HOLD,
		LOCK_WRITE_HOLD
	} lock_type = LOCK_NONE;

	/* Acquire any exclusion resources needed for the operation. */
	switch (cmd) {
	case VM_RUN:
	case VM_GET_REGISTER:
	case VM_SET_REGISTER:
	case VM_GET_SEGMENT_DESCRIPTOR:
	case VM_SET_SEGMENT_DESCRIPTOR:
	case VM_GET_REGISTER_SET:
	case VM_SET_REGISTER_SET:
	case VM_INJECT_EXCEPTION:
	case VM_GET_CAPABILITY:
	case VM_SET_CAPABILITY:
	case VM_PPTDEV_MSI:
	case VM_PPTDEV_MSIX:
	case VM_SET_X2APIC_STATE:
	case VM_GLA2GPA:
	case VM_GLA2GPA_NOFAULT:
	case VM_ACTIVATE_CPU:
	case VM_SET_INTINFO:
	case VM_GET_INTINFO:
	case VM_RESTART_INSTRUCTION:
	case VM_SET_KERNEMU_DEV:
	case VM_GET_KERNEMU_DEV:
	case VM_RESET_CPU:
	case VM_GET_RUN_STATE:
	case VM_SET_RUN_STATE:
		/*
		 * Copy in the ID of the vCPU chosen for this operation.
		 * Since a nefarious caller could update their struct between
		 * this locking and when the rest of the ioctl data is copied
		 * in, it is _critical_ that this local 'vcpu' variable be used
		 * rather than the in-struct one when performing the ioctl.
		 */
		if (ddi_copyin(datap, &vcpu, sizeof (vcpu), md)) {
			return (EFAULT);
		}
		if (vcpu < 0 || vcpu > vm_get_maxcpus(sc->vmm_vm)) {
			return (EINVAL);
		}
		vcpu_lock_one(sc, vcpu);
		lock_type = LOCK_VCPU;
		break;

	case VM_REINIT:
	case VM_BIND_PPTDEV:
	case VM_UNBIND_PPTDEV:
	case VM_MAP_PPTDEV_MMIO:
	case VM_ALLOC_MEMSEG:
	case VM_MMAP_MEMSEG:
	case VM_WRLOCK_CYCLE:
	case VM_PMTMR_LOCATE:
	case VM_ARC_RESV:
		vmm_write_lock(sc);
		lock_type = LOCK_WRITE_HOLD;
		break;

	case VM_GET_GPA_PMAP:
	case VM_GET_MEMSEG:
	case VM_MMAP_GETNEXT:
	case VM_LAPIC_IRQ:
	case VM_INJECT_NMI:
	case VM_IOAPIC_ASSERT_IRQ:
	case VM_IOAPIC_DEASSERT_IRQ:
	case VM_IOAPIC_PULSE_IRQ:
	case VM_LAPIC_MSI:
	case VM_LAPIC_LOCAL_IRQ:
	case VM_GET_X2APIC_STATE:
	case VM_RTC_READ:
	case VM_RTC_WRITE:
	case VM_RTC_SETTIME:
	case VM_RTC_GETTIME:
	case VM_PPTDEV_DISABLE_MSIX:
#ifndef __FreeBSD__
	case VM_DEVMEM_GETOFFSET:
#endif
		vmm_read_lock(sc);
		lock_type = LOCK_READ_HOLD;
		break;

	case VM_IOAPIC_PINCOUNT:
	default:
		break;
	}

	/* Execute the primary logic for the ioctl. */
	switch (cmd) {
	case VM_RUN: {
		struct vm_entry entry;

		if (ddi_copyin(datap, &entry, sizeof (entry), md)) {
			error = EFAULT;
			break;
		}

		if (!(curthread->t_schedflag & TS_VCPU))
			smt_mark_as_vcpu();

		error = vm_run(sc->vmm_vm, vcpu, &entry);

		/*
		 * Unexpected states in vm_run() are expressed through positive
		 * errno-oriented return values.  VM states which expect further
		 * processing in userspace (necessary context via exitinfo) are
		 * expressed through negative return values.  For the time being
		 * a return value of 0 is not expected from vm_run().
		 */
		ASSERT(error != 0);
		if (error < 0) {
			const struct vm_exit *vme;
			void *outp = entry.exit_data;

			error = 0;
			vme = vm_exitinfo(sc->vmm_vm, vcpu);
			if (ddi_copyout(vme, outp, sizeof (*vme), md)) {
				error = EFAULT;
			}
		}
		break;
	}
	case VM_SUSPEND: {
		struct vm_suspend vmsuspend;

		if (ddi_copyin(datap, &vmsuspend, sizeof (vmsuspend), md)) {
			error = EFAULT;
			break;
		}
		error = vm_suspend(sc->vmm_vm, vmsuspend.how);
		break;
	}
	case VM_REINIT:
		if ((error = vmm_drv_block_hook(sc, B_TRUE)) != 0) {
			/*
			 * The VM instance should be free of driver-attached
			 * hooks during the reinitialization process.
			 */
			break;
		}
		error = vm_reinit(sc->vmm_vm);
		(void) vmm_drv_block_hook(sc, B_FALSE);
		break;
	case VM_STAT_DESC: {
		struct vm_stat_desc statdesc;

		if (ddi_copyin(datap, &statdesc, sizeof (statdesc), md)) {
			error = EFAULT;
			break;
		}
		error = vmm_stat_desc_copy(statdesc.index, statdesc.desc,
		    sizeof (statdesc.desc));
		if (error == 0 &&
		    ddi_copyout(&statdesc, datap, sizeof (statdesc), md)) {
			error = EFAULT;
			break;
		}
		break;
	}
	case VM_STATS_IOC: {
		struct vm_stats vmstats;

		CTASSERT(MAX_VM_STATS >= MAX_VMM_STAT_ELEMS);
		if (ddi_copyin(datap, &vmstats, sizeof (vmstats), md)) {
			error = EFAULT;
			break;
		}
		hrt2tv(gethrtime(), &vmstats.tv);
		error = vmm_stat_copy(sc->vmm_vm, vmstats.cpuid,
		    &vmstats.num_entries, vmstats.statbuf);
		if (error == 0 &&
		    ddi_copyout(&vmstats, datap, sizeof (vmstats), md)) {
			error = EFAULT;
			break;
		}
		break;
	}

	case VM_PPTDEV_MSI: {
		struct vm_pptdev_msi pptmsi;

		if (ddi_copyin(datap, &pptmsi, sizeof (pptmsi), md)) {
			error = EFAULT;
			break;
		}
		error = ppt_setup_msi(sc->vmm_vm, pptmsi.vcpu, pptmsi.pptfd,
		    pptmsi.addr, pptmsi.msg, pptmsi.numvec);
		break;
	}
	case VM_PPTDEV_MSIX: {
		struct vm_pptdev_msix pptmsix;

		if (ddi_copyin(datap, &pptmsix, sizeof (pptmsix), md)) {
			error = EFAULT;
			break;
		}
		error = ppt_setup_msix(sc->vmm_vm, pptmsix.vcpu, pptmsix.pptfd,
		    pptmsix.idx, pptmsix.addr, pptmsix.msg,
		    pptmsix.vector_control);
		break;
	}
	case VM_PPTDEV_DISABLE_MSIX: {
		struct vm_pptdev pptdev;

		if (ddi_copyin(datap, &pptdev, sizeof (pptdev), md)) {
			error = EFAULT;
			break;
		}
		error = ppt_disable_msix(sc->vmm_vm, pptdev.pptfd);
		break;
	}
	case VM_MAP_PPTDEV_MMIO: {
		struct vm_pptdev_mmio pptmmio;

		if (ddi_copyin(datap, &pptmmio, sizeof (pptmmio), md)) {
			error = EFAULT;
			break;
		}
		error = ppt_map_mmio(sc->vmm_vm, pptmmio.pptfd, pptmmio.gpa,
		    pptmmio.len, pptmmio.hpa);
		break;
	}
	case VM_BIND_PPTDEV: {
		struct vm_pptdev pptdev;

		if (ddi_copyin(datap, &pptdev, sizeof (pptdev), md)) {
			error = EFAULT;
			break;
		}
		error = vm_assign_pptdev(sc->vmm_vm, pptdev.pptfd);
		break;
	}
	case VM_UNBIND_PPTDEV: {
		struct vm_pptdev pptdev;

		if (ddi_copyin(datap, &pptdev, sizeof (pptdev), md)) {
			error = EFAULT;
			break;
		}
		error = vm_unassign_pptdev(sc->vmm_vm, pptdev.pptfd);
		break;
	}
	case VM_GET_PPTDEV_LIMITS: {
		struct vm_pptdev_limits pptlimits;

		if (ddi_copyin(datap, &pptlimits, sizeof (pptlimits), md)) {
			error = EFAULT;
			break;
		}
		error = ppt_get_limits(sc->vmm_vm, pptlimits.pptfd,
		    &pptlimits.msi_limit, &pptlimits.msix_limit);
		if (error == 0 &&
		    ddi_copyout(&pptlimits, datap, sizeof (pptlimits), md)) {
			error = EFAULT;
			break;
		}
		break;
	}
	case VM_INJECT_EXCEPTION: {
		struct vm_exception vmexc;
		if (ddi_copyin(datap, &vmexc, sizeof (vmexc), md)) {
			error = EFAULT;
			break;
		}
		error = vm_inject_exception(sc->vmm_vm, vcpu, vmexc.vector,
		    vmexc.error_code_valid, vmexc.error_code,
		    vmexc.restart_instruction);
		break;
	}
	case VM_INJECT_NMI: {
		struct vm_nmi vmnmi;

		if (ddi_copyin(datap, &vmnmi, sizeof (vmnmi), md)) {
			error = EFAULT;
			break;
		}
		error = vm_inject_nmi(sc->vmm_vm, vmnmi.cpuid);
		break;
	}
	case VM_LAPIC_IRQ: {
		struct vm_lapic_irq vmirq;

		if (ddi_copyin(datap, &vmirq, sizeof (vmirq), md)) {
			error = EFAULT;
			break;
		}
		error = lapic_intr_edge(sc->vmm_vm, vmirq.cpuid, vmirq.vector);
		break;
	}
	case VM_LAPIC_LOCAL_IRQ: {
		struct vm_lapic_irq vmirq;

		if (ddi_copyin(datap, &vmirq, sizeof (vmirq), md)) {
			error = EFAULT;
			break;
		}
		error = lapic_set_local_intr(sc->vmm_vm, vmirq.cpuid,
		    vmirq.vector);
		break;
	}
	case VM_LAPIC_MSI: {
		struct vm_lapic_msi vmmsi;

		if (ddi_copyin(datap, &vmmsi, sizeof (vmmsi), md)) {
			error = EFAULT;
			break;
		}
		error = lapic_intr_msi(sc->vmm_vm, vmmsi.addr, vmmsi.msg);
		break;
	}

	case VM_IOAPIC_ASSERT_IRQ: {
		struct vm_ioapic_irq ioapic_irq;

		if (ddi_copyin(datap, &ioapic_irq, sizeof (ioapic_irq), md)) {
			error = EFAULT;
			break;
		}
		error = vioapic_assert_irq(sc->vmm_vm, ioapic_irq.irq);
		break;
	}
	case VM_IOAPIC_DEASSERT_IRQ: {
		struct vm_ioapic_irq ioapic_irq;

		if (ddi_copyin(datap, &ioapic_irq, sizeof (ioapic_irq), md)) {
			error = EFAULT;
			break;
		}
		error = vioapic_deassert_irq(sc->vmm_vm, ioapic_irq.irq);
		break;
	}
	case VM_IOAPIC_PULSE_IRQ: {
		struct vm_ioapic_irq ioapic_irq;

		if (ddi_copyin(datap, &ioapic_irq, sizeof (ioapic_irq), md)) {
			error = EFAULT;
			break;
		}
		error = vioapic_pulse_irq(sc->vmm_vm, ioapic_irq.irq);
		break;
	}
	case VM_IOAPIC_PINCOUNT: {
		int pincount;

		pincount = vioapic_pincount(sc->vmm_vm);
		if (ddi_copyout(&pincount, datap, sizeof (int), md)) {
			error = EFAULT;
			break;
		}
		break;
	}

	case VM_ISA_ASSERT_IRQ: {
		struct vm_isa_irq isa_irq;

		if (ddi_copyin(datap, &isa_irq, sizeof (isa_irq), md)) {
			error = EFAULT;
			break;
		}
		error = vatpic_assert_irq(sc->vmm_vm, isa_irq.atpic_irq);
		if (error == 0 && isa_irq.ioapic_irq != -1) {
			error = vioapic_assert_irq(sc->vmm_vm,
			    isa_irq.ioapic_irq);
		}
		break;
	}
	case VM_ISA_DEASSERT_IRQ: {
		struct vm_isa_irq isa_irq;

		if (ddi_copyin(datap, &isa_irq, sizeof (isa_irq), md)) {
			error = EFAULT;
			break;
		}
		error = vatpic_deassert_irq(sc->vmm_vm, isa_irq.atpic_irq);
		if (error == 0 && isa_irq.ioapic_irq != -1) {
			error = vioapic_deassert_irq(sc->vmm_vm,
			    isa_irq.ioapic_irq);
		}
		break;
	}
	case VM_ISA_PULSE_IRQ: {
		struct vm_isa_irq isa_irq;

		if (ddi_copyin(datap, &isa_irq, sizeof (isa_irq), md)) {
			error = EFAULT;
			break;
		}
		error = vatpic_pulse_irq(sc->vmm_vm, isa_irq.atpic_irq);
		if (error == 0 && isa_irq.ioapic_irq != -1) {
			error = vioapic_pulse_irq(sc->vmm_vm,
			    isa_irq.ioapic_irq);
		}
		break;
	}
	case VM_ISA_SET_IRQ_TRIGGER: {
		struct vm_isa_irq_trigger isa_irq_trigger;

		if (ddi_copyin(datap, &isa_irq_trigger,
		    sizeof (isa_irq_trigger), md)) {
			error = EFAULT;
			break;
		}
		error = vatpic_set_irq_trigger(sc->vmm_vm,
		    isa_irq_trigger.atpic_irq, isa_irq_trigger.trigger);
		break;
	}

	case VM_MMAP_GETNEXT: {
		struct vm_memmap mm;

		if (ddi_copyin(datap, &mm, sizeof (mm), md)) {
			error = EFAULT;
			break;
		}
		error = vm_mmap_getnext(sc->vmm_vm, &mm.gpa, &mm.segid,
		    &mm.segoff, &mm.len, &mm.prot, &mm.flags);
		if (error == 0 && ddi_copyout(&mm, datap, sizeof (mm), md)) {
			error = EFAULT;
			break;
		}
		break;
	}
	case VM_MMAP_MEMSEG: {
		struct vm_memmap mm;

		if (ddi_copyin(datap, &mm, sizeof (mm), md)) {
			error = EFAULT;
			break;
		}
		error = vm_mmap_memseg(sc->vmm_vm, mm.gpa, mm.segid, mm.segoff,
		    mm.len, mm.prot, mm.flags);
		break;
	}
	case VM_ALLOC_MEMSEG: {
		struct vm_memseg vmseg;

		if (ddi_copyin(datap, &vmseg, sizeof (vmseg), md)) {
			error = EFAULT;
			break;
		}
		error = vmmdev_alloc_memseg(sc, &vmseg);
		break;
	}
	case VM_GET_MEMSEG: {
		struct vm_memseg vmseg;

		if (ddi_copyin(datap, &vmseg, sizeof (vmseg), md)) {
			error = EFAULT;
			break;
		}
		error = vmmdev_get_memseg(sc, &vmseg);
		if (error == 0 &&
		    ddi_copyout(&vmseg, datap, sizeof (vmseg), md)) {
			error = EFAULT;
			break;
		}
		break;
	}
	case VM_GET_REGISTER: {
		struct vm_register vmreg;

		if (ddi_copyin(datap, &vmreg, sizeof (vmreg), md)) {
			error = EFAULT;
			break;
		}
		error = vm_get_register(sc->vmm_vm, vcpu, vmreg.regnum,
		    &vmreg.regval);
		if (error == 0 &&
		    ddi_copyout(&vmreg, datap, sizeof (vmreg), md)) {
			error = EFAULT;
			break;
		}
		break;
	}
	case VM_SET_REGISTER: {
		struct vm_register vmreg;

		if (ddi_copyin(datap, &vmreg, sizeof (vmreg), md)) {
			error = EFAULT;
			break;
		}
		error = vm_set_register(sc->vmm_vm, vcpu, vmreg.regnum,
		    vmreg.regval);
		break;
	}
	case VM_SET_SEGMENT_DESCRIPTOR: {
		struct vm_seg_desc vmsegd;

		if (ddi_copyin(datap, &vmsegd, sizeof (vmsegd), md)) {
			error = EFAULT;
			break;
		}
		error = vm_set_seg_desc(sc->vmm_vm, vcpu, vmsegd.regnum,
		    &vmsegd.desc);
		break;
	}
	case VM_GET_SEGMENT_DESCRIPTOR: {
		struct vm_seg_desc vmsegd;

		if (ddi_copyin(datap, &vmsegd, sizeof (vmsegd), md)) {
			error = EFAULT;
			break;
		}
		error = vm_get_seg_desc(sc->vmm_vm, vcpu, vmsegd.regnum,
		    &vmsegd.desc);
		if (error == 0 &&
		    ddi_copyout(&vmsegd, datap, sizeof (vmsegd), md)) {
			error = EFAULT;
			break;
		}
		break;
	}
	case VM_GET_REGISTER_SET: {
		struct vm_register_set vrs;
		int regnums[VM_REG_LAST];
		uint64_t regvals[VM_REG_LAST];

		if (ddi_copyin(datap, &vrs, sizeof (vrs), md)) {
			error = EFAULT;
			break;
		}
		if (vrs.count > VM_REG_LAST || vrs.count == 0) {
			error = EINVAL;
			break;
		}
		if (ddi_copyin(vrs.regnums, regnums,
		    sizeof (int) * vrs.count, md)) {
			error = EFAULT;
			break;
		}

		error = 0;
		for (uint_t i = 0; i < vrs.count && error == 0; i++) {
			if (regnums[i] < 0) {
				error = EINVAL;
				break;
			}
			error = vm_get_register(sc->vmm_vm, vcpu, regnums[i],
			    &regvals[i]);
		}
		if (error == 0 && ddi_copyout(regvals, vrs.regvals,
		    sizeof (uint64_t) * vrs.count, md)) {
			error = EFAULT;
		}
		break;
	}
	case VM_SET_REGISTER_SET: {
		struct vm_register_set vrs;
		int regnums[VM_REG_LAST];
		uint64_t regvals[VM_REG_LAST];

		if (ddi_copyin(datap, &vrs, sizeof (vrs), md)) {
			error = EFAULT;
			break;
		}
		if (vrs.count > VM_REG_LAST || vrs.count == 0) {
			error = EINVAL;
			break;
		}
		if (ddi_copyin(vrs.regnums, regnums,
		    sizeof (int) * vrs.count, md)) {
			error = EFAULT;
			break;
		}
		if (ddi_copyin(vrs.regvals, regvals,
		    sizeof (uint64_t) * vrs.count, md)) {
			error = EFAULT;
			break;
		}

		error = 0;
		for (uint_t i = 0; i < vrs.count && error == 0; i++) {
			/*
			 * Setting registers in a set is not atomic, since a
			 * failure in the middle of the set will cause a
			 * bail-out and inconsistent register state.  Callers
			 * should be wary of this.
			 */
			if (regnums[i] < 0) {
				error = EINVAL;
				break;
			}
			error = vm_set_register(sc->vmm_vm, vcpu, regnums[i],
			    regvals[i]);
		}
		break;
	}
	case VM_RESET_CPU: {
		struct vm_vcpu_reset vvr;

		if (ddi_copyin(datap, &vvr, sizeof (vvr), md)) {
			error = EFAULT;
			break;
		}
		if (vvr.kind != VRK_RESET && vvr.kind != VRK_INIT) {
			error = EINVAL;
		}

		error = vcpu_arch_reset(sc->vmm_vm, vcpu, vvr.kind == VRK_INIT);
		break;
	}
	case VM_GET_RUN_STATE: {
		struct vm_run_state vrs;

		bzero(&vrs, sizeof (vrs));
		error = vm_get_run_state(sc->vmm_vm, vcpu, &vrs.state,
		    &vrs.sipi_vector);
		if (error == 0) {
			if (ddi_copyout(&vrs, datap, sizeof (vrs), md)) {
				error = EFAULT;
				break;
			}
		}
		break;
	}
	case VM_SET_RUN_STATE: {
		struct vm_run_state vrs;

		if (ddi_copyin(datap, &vrs, sizeof (vrs), md)) {
			error = EFAULT;
			break;
		}
		error = vm_set_run_state(sc->vmm_vm, vcpu, vrs.state,
		    vrs.sipi_vector);
		break;
	}

	case VM_SET_KERNEMU_DEV:
	case VM_GET_KERNEMU_DEV: {
		struct vm_readwrite_kernemu_device kemu;
		size_t size = 0;

		if (ddi_copyin(datap, &kemu, sizeof (kemu), md)) {
			error = EFAULT;
			break;
		}

		if (kemu.access_width > 3) {
			error = EINVAL;
			break;
		}
		size = (1 << kemu.access_width);
		ASSERT(size >= 1 && size <= 8);

		if (cmd == VM_SET_KERNEMU_DEV) {
			error = vm_service_mmio_write(sc->vmm_vm, vcpu,
			    kemu.gpa, kemu.value, size);
		} else {
			error = vm_service_mmio_read(sc->vmm_vm, vcpu,
			    kemu.gpa, &kemu.value, size);
		}

		if (error == 0) {
			if (ddi_copyout(&kemu, datap, sizeof (kemu), md)) {
				error = EFAULT;
				break;
			}
		}
		break;
	}

	case VM_GET_CAPABILITY: {
		struct vm_capability vmcap;

		if (ddi_copyin(datap, &vmcap, sizeof (vmcap), md)) {
			error = EFAULT;
			break;
		}
		error = vm_get_capability(sc->vmm_vm, vcpu, vmcap.captype,
		    &vmcap.capval);
		if (error == 0 &&
		    ddi_copyout(&vmcap, datap, sizeof (vmcap), md)) {
			error = EFAULT;
			break;
		}
		break;
	}
	case VM_SET_CAPABILITY: {
		struct vm_capability vmcap;

		if (ddi_copyin(datap, &vmcap, sizeof (vmcap), md)) {
			error = EFAULT;
			break;
		}
		error = vm_set_capability(sc->vmm_vm, vcpu, vmcap.captype,
		    vmcap.capval);
		break;
	}
	case VM_SET_X2APIC_STATE: {
		struct vm_x2apic x2apic;

		if (ddi_copyin(datap, &x2apic, sizeof (x2apic), md)) {
			error = EFAULT;
			break;
		}
		error = vm_set_x2apic_state(sc->vmm_vm, vcpu, x2apic.state);
		break;
	}
	case VM_GET_X2APIC_STATE: {
		struct vm_x2apic x2apic;

		if (ddi_copyin(datap, &x2apic, sizeof (x2apic), md)) {
			error = EFAULT;
			break;
		}
		error = vm_get_x2apic_state(sc->vmm_vm, x2apic.cpuid,
		    &x2apic.state);
		if (error == 0 &&
		    ddi_copyout(&x2apic, datap, sizeof (x2apic), md)) {
			error = EFAULT;
			break;
		}
		break;
	}
	case VM_GET_GPA_PMAP: {
		struct vm_gpa_pte gpapte;

		if (ddi_copyin(datap, &gpapte, sizeof (gpapte), md)) {
			error = EFAULT;
			break;
		}
#ifdef __FreeBSD__
		/* XXXJOY: add function? */
		pmap_get_mapping(vmspace_pmap(vm_get_vmspace(sc->vmm_vm)),
		    gpapte.gpa, gpapte.pte, &gpapte.ptenum);
#endif
		error = 0;
		break;
	}
	case VM_GET_HPET_CAPABILITIES: {
		struct vm_hpet_cap hpetcap;

		error = vhpet_getcap(&hpetcap);
		if (error == 0 &&
		    ddi_copyout(&hpetcap, datap, sizeof (hpetcap), md)) {
			error = EFAULT;
			break;
		}
		break;
	}
	case VM_GLA2GPA: {
		struct vm_gla2gpa gg;

		CTASSERT(PROT_READ == VM_PROT_READ);
		CTASSERT(PROT_WRITE == VM_PROT_WRITE);
		CTASSERT(PROT_EXEC == VM_PROT_EXECUTE);

		if (ddi_copyin(datap, &gg, sizeof (gg), md)) {
			error = EFAULT;
			break;
		}
		gg.vcpuid = vcpu;
		error = vm_gla2gpa(sc->vmm_vm, vcpu, &gg.paging, gg.gla,
		    gg.prot, &gg.gpa, &gg.fault);
		if (error == 0 && ddi_copyout(&gg, datap, sizeof (gg), md)) {
			error = EFAULT;
			break;
		}
		break;
	}
	case VM_GLA2GPA_NOFAULT: {
		struct vm_gla2gpa gg;

		CTASSERT(PROT_READ == VM_PROT_READ);
		CTASSERT(PROT_WRITE == VM_PROT_WRITE);
		CTASSERT(PROT_EXEC == VM_PROT_EXECUTE);

		if (ddi_copyin(datap, &gg, sizeof (gg), md)) {
			error = EFAULT;
			break;
		}
		gg.vcpuid = vcpu;
		error = vm_gla2gpa_nofault(sc->vmm_vm, vcpu, &gg.paging,
		    gg.gla, gg.prot, &gg.gpa, &gg.fault);
		if (error == 0 && ddi_copyout(&gg, datap, sizeof (gg), md)) {
			error = EFAULT;
			break;
		}
		break;
	}

	case VM_ACTIVATE_CPU:
		error = vm_activate_cpu(sc->vmm_vm, vcpu);
		break;

	case VM_SUSPEND_CPU:
		if (ddi_copyin(datap, &vcpu, sizeof (vcpu), md)) {
			error = EFAULT;
		} else {
			error = vm_suspend_cpu(sc->vmm_vm, vcpu);
		}
		break;

	case VM_RESUME_CPU:
		if (ddi_copyin(datap, &vcpu, sizeof (vcpu), md)) {
			error = EFAULT;
		} else {
			error = vm_resume_cpu(sc->vmm_vm, vcpu);
		}
		break;

	case VM_GET_CPUS: {
		struct vm_cpuset vm_cpuset;
		cpuset_t tempset;
		void *srcp = &tempset;
		int size;

		if (ddi_copyin(datap, &vm_cpuset, sizeof (vm_cpuset), md)) {
			error = EFAULT;
			break;
		}

		/* Be more generous about sizing since our cpuset_t is large. */
		size = vm_cpuset.cpusetsize;
		if (size <= 0 || size > sizeof (cpuset_t)) {
			error = ERANGE;
		}
		/*
		 * If they want a ulong_t or less, make sure they receive the
		 * low bits with all the useful information.
		 */
		if (size <= sizeof (tempset.cpub[0])) {
			srcp = &tempset.cpub[0];
		}

		if (vm_cpuset.which == VM_ACTIVE_CPUS) {
			tempset = vm_active_cpus(sc->vmm_vm);
		} else if (vm_cpuset.which == VM_SUSPENDED_CPUS) {
			tempset = vm_suspended_cpus(sc->vmm_vm);
		} else if (vm_cpuset.which == VM_DEBUG_CPUS) {
			tempset = vm_debug_cpus(sc->vmm_vm);
		} else {
			error = EINVAL;
		}

		ASSERT(size > 0 && size <= sizeof (tempset));
		if (error == 0 &&
		    ddi_copyout(srcp, vm_cpuset.cpus, size, md)) {
			error = EFAULT;
			break;
		}
		break;
	}
	case VM_SET_INTINFO: {
		struct vm_intinfo vmii;

		if (ddi_copyin(datap, &vmii, sizeof (vmii), md)) {
			error = EFAULT;
			break;
		}
		error = vm_exit_intinfo(sc->vmm_vm, vcpu, vmii.info1);
		break;
	}
	case VM_GET_INTINFO: {
		struct vm_intinfo vmii;

		vmii.vcpuid = vcpu;
		error = vm_get_intinfo(sc->vmm_vm, vcpu, &vmii.info1,
		    &vmii.info2);
		if (error == 0 &&
		    ddi_copyout(&vmii, datap, sizeof (vmii), md)) {
			error = EFAULT;
			break;
		}
		break;
	}
	case VM_RTC_WRITE: {
		struct vm_rtc_data rtcdata;

		if (ddi_copyin(datap, &rtcdata, sizeof (rtcdata), md)) {
			error = EFAULT;
			break;
		}
		error = vrtc_nvram_write(sc->vmm_vm, rtcdata.offset,
		    rtcdata.value);
		break;
	}
	case VM_RTC_READ: {
		struct vm_rtc_data rtcdata;

		if (ddi_copyin(datap, &rtcdata, sizeof (rtcdata), md)) {
			error = EFAULT;
			break;
		}
		error = vrtc_nvram_read(sc->vmm_vm, rtcdata.offset,
		    &rtcdata.value);
		if (error == 0 &&
		    ddi_copyout(&rtcdata, datap, sizeof (rtcdata), md)) {
			error = EFAULT;
			break;
		}
		break;
	}
	case VM_RTC_SETTIME: {
		struct vm_rtc_time rtctime;

		if (ddi_copyin(datap, &rtctime, sizeof (rtctime), md)) {
			error = EFAULT;
			break;
		}
		error = vrtc_set_time(sc->vmm_vm, rtctime.secs);
		break;
	}
	case VM_RTC_GETTIME: {
		struct vm_rtc_time rtctime;

		rtctime.secs = vrtc_get_time(sc->vmm_vm);
		if (ddi_copyout(&rtctime, datap, sizeof (rtctime), md)) {
			error = EFAULT;
			break;
		}
		break;
	}

	case VM_PMTMR_LOCATE: {
		uint16_t port = arg;
		error = vpmtmr_set_location(sc->vmm_vm, port);
		break;
	}

	case VM_RESTART_INSTRUCTION:
		error = vm_restart_instruction(sc->vmm_vm, vcpu);
		break;

	case VM_SET_TOPOLOGY: {
		struct vm_cpu_topology topo;

		if (ddi_copyin(datap, &topo, sizeof (topo), md) != 0) {
			error = EFAULT;
			break;
		}
		error = vm_set_topology(sc->vmm_vm, topo.sockets, topo.cores,
		    topo.threads, topo.maxcpus);
		break;
	}
	case VM_GET_TOPOLOGY: {
		struct vm_cpu_topology topo;

		vm_get_topology(sc->vmm_vm, &topo.sockets, &topo.cores,
		    &topo.threads, &topo.maxcpus);
		if (ddi_copyout(&topo, datap, sizeof (topo), md) != 0) {
			error = EFAULT;
			break;
		}
		break;
	}

#ifndef __FreeBSD__
	case VM_DEVMEM_GETOFFSET: {
		struct vm_devmem_offset vdo;
		list_t *dl = &sc->vmm_devmem_list;
		vmm_devmem_entry_t *de = NULL;

		if (ddi_copyin(datap, &vdo, sizeof (vdo), md) != 0) {
			error = EFAULT;
			break;
		}

		for (de = list_head(dl); de != NULL; de = list_next(dl, de)) {
			if (de->vde_segid == vdo.segid) {
				break;
			}
		}
		if (de != NULL) {
			vdo.offset = de->vde_off;
			if (ddi_copyout(&vdo, datap, sizeof (vdo), md) != 0) {
				error = EFAULT;
			}
		} else {
			error = ENOENT;
		}
		break;
	}
	case VM_WRLOCK_CYCLE: {
		/*
		 * Present a test mechanism to acquire/release the write lock
		 * on the VM without any other effects.
		 */
		break;
	}
	case VM_ARC_RESV:
		error = vm_arc_resv(sc->vmm_vm, (uint64_t)arg);
		break;
#endif
	default:
		error = ENOTTY;
		break;
	}

	/* Release exclusion resources */
	switch (lock_type) {
	case LOCK_NONE:
		break;
	case LOCK_VCPU:
		vcpu_unlock_one(sc, vcpu);
		break;
	case LOCK_READ_HOLD:
		vmm_read_unlock(sc);
		break;
	case LOCK_WRITE_HOLD:
		vmm_write_unlock(sc);
		break;
	default:
		panic("unexpected lock type");
		break;
	}

	return (error);
}

static vmm_softc_t *
vmm_lookup(const char *name)
{
	list_t *vml = &vmm_list;
	vmm_softc_t *sc;

	ASSERT(MUTEX_HELD(&vmm_mtx));

	for (sc = list_head(vml); sc != NULL; sc = list_next(vml, sc)) {
		if (strcmp(sc->vmm_name, name) == 0) {
			break;
		}
	}

	return (sc);
}

/*
 * Acquire an HMA registration if not already held.
 */
static boolean_t
vmm_hma_acquire(void)
{
	ASSERT(MUTEX_NOT_HELD(&vmm_mtx));

	mutex_enter(&vmmdev_mtx);

	if (vmmdev_hma_reg == NULL) {
		VERIFY3U(vmmdev_hma_ref, ==, 0);
		vmmdev_hma_reg = hma_register(vmmdev_hvm_name);
		if (vmmdev_hma_reg == NULL) {
			cmn_err(CE_WARN, "%s HMA registration failed.",
			    vmmdev_hvm_name);
			mutex_exit(&vmmdev_mtx);
			return (B_FALSE);
		}
	}

	vmmdev_hma_ref++;

	mutex_exit(&vmmdev_mtx);

	return (B_TRUE);
}

/*
 * Release the HMA registration if held and there are no remaining VMs.
 */
static void
vmm_hma_release(void)
{
	ASSERT(MUTEX_NOT_HELD(&vmm_mtx));

	mutex_enter(&vmmdev_mtx);

	VERIFY3U(vmmdev_hma_ref, !=, 0);

	vmmdev_hma_ref--;

	if (vmmdev_hma_ref == 0) {
		VERIFY(vmmdev_hma_reg != NULL);
		hma_unregister(vmmdev_hma_reg);
		vmmdev_hma_reg = NULL;
	}
	mutex_exit(&vmmdev_mtx);
}

static int
vmmdev_do_vm_create(char *name, cred_t *cr)
{
	vmm_softc_t	*sc = NULL;
	minor_t		minor;
	int		error = ENOMEM;

	if (strnlen(name, VM_MAX_NAMELEN) >= VM_MAX_NAMELEN) {
		return (EINVAL);
	}

	if (!vmm_hma_acquire())
		return (ENXIO);

	mutex_enter(&vmm_mtx);

	/* Look for duplicate names */
	if (vmm_lookup(name) != NULL) {
		mutex_exit(&vmm_mtx);
		vmm_hma_release();
		return (EEXIST);
	}

	/* Allow only one instance per non-global zone. */
	if (!INGLOBALZONE(curproc)) {
		for (sc = list_head(&vmm_list); sc != NULL;
		    sc = list_next(&vmm_list, sc)) {
			if (sc->vmm_zone == curzone) {
				mutex_exit(&vmm_mtx);
				vmm_hma_release();
				return (EINVAL);
			}
		}
	}

	minor = id_alloc(vmm_minors);
	if (ddi_soft_state_zalloc(vmm_statep, minor) != DDI_SUCCESS) {
		goto fail;
	} else if ((sc = ddi_get_soft_state(vmm_statep, minor)) == NULL) {
		ddi_soft_state_free(vmm_statep, minor);
		goto fail;
	} else if (ddi_create_minor_node(vmmdev_dip, name, S_IFCHR, minor,
	    DDI_PSEUDO, 0) != DDI_SUCCESS) {
		goto fail;
	}

	error = vm_create(name, &sc->vmm_vm);
	if (error == 0) {
		/* Complete VM intialization and report success. */
		(void) strlcpy(sc->vmm_name, name, sizeof (sc->vmm_name));
		sc->vmm_minor = minor;
		list_create(&sc->vmm_devmem_list, sizeof (vmm_devmem_entry_t),
		    offsetof(vmm_devmem_entry_t, vde_node));

		list_create(&sc->vmm_holds, sizeof (vmm_hold_t),
		    offsetof(vmm_hold_t, vmh_node));
		cv_init(&sc->vmm_cv, NULL, CV_DEFAULT, NULL);

		mutex_init(&sc->vmm_lease_lock, NULL, MUTEX_DEFAULT, NULL);
		list_create(&sc->vmm_lease_list, sizeof (vmm_lease_t),
		    offsetof(vmm_lease_t, vml_node));
		cv_init(&sc->vmm_lease_cv, NULL, CV_DEFAULT, NULL);
		rw_init(&sc->vmm_rwlock, NULL, RW_DEFAULT, NULL);

		sc->vmm_zone = crgetzone(cr);
		zone_hold(sc->vmm_zone);
		vmm_zsd_add_vm(sc);

		list_insert_tail(&vmm_list, sc);
		mutex_exit(&vmm_mtx);
		return (0);
	}

	ddi_remove_minor_node(vmmdev_dip, name);
fail:
	id_free(vmm_minors, minor);
	if (sc != NULL) {
		ddi_soft_state_free(vmm_statep, minor);
	}
	mutex_exit(&vmm_mtx);
	vmm_hma_release();

	return (error);
}

/*
 * Bhyve 'Driver' Interface
 *
 * While many devices are emulated in the bhyve userspace process, there are
 * others with performance constraints which require that they run mostly or
 * entirely in-kernel.  For those not integrated directly into bhyve, an API is
 * needed so they can query/manipulate the portions of VM state needed to
 * fulfill their purpose.
 *
 * This includes:
 * - Translating guest-physical addresses to host-virtual pointers
 * - Injecting MSIs
 * - Hooking IO port addresses
 *
 * The vmm_drv interface exists to provide that functionality to its consumers.
 * (At this time, 'viona' is the only user)
 */
int
vmm_drv_hold(file_t *fp, cred_t *cr, vmm_hold_t **holdp)
{
	vnode_t *vp = fp->f_vnode;
	const dev_t dev = vp->v_rdev;
	vmm_softc_t *sc;
	vmm_hold_t *hold;
	int err = 0;

	if (vp->v_type != VCHR) {
		return (ENXIO);
	}
	const major_t major = getmajor(dev);
	const minor_t minor = getminor(dev);

	mutex_enter(&vmmdev_mtx);
	if (vmmdev_dip == NULL || major != ddi_driver_major(vmmdev_dip)) {
		mutex_exit(&vmmdev_mtx);
		return (ENOENT);
	}
	mutex_enter(&vmm_mtx);
	mutex_exit(&vmmdev_mtx);

	if ((sc = ddi_get_soft_state(vmm_statep, minor)) == NULL) {
		err = ENOENT;
		goto out;
	}
	/* XXXJOY: check cred permissions against instance */

	if ((sc->vmm_flags & (VMM_CLEANUP|VMM_PURGED|VMM_DESTROY)) != 0) {
		err = EBUSY;
		goto out;
	}

	hold = kmem_zalloc(sizeof (*hold), KM_SLEEP);
	hold->vmh_sc = sc;
	hold->vmh_release_req = B_FALSE;

	list_insert_tail(&sc->vmm_holds, hold);
	sc->vmm_flags |= VMM_HELD;
	*holdp = hold;

out:
	mutex_exit(&vmm_mtx);
	return (err);
}

void
vmm_drv_rele(vmm_hold_t *hold)
{
	vmm_softc_t *sc;

	ASSERT(hold != NULL);
	ASSERT(hold->vmh_sc != NULL);
	VERIFY(hold->vmh_ioport_hook_cnt == 0);

	mutex_enter(&vmm_mtx);
	sc = hold->vmh_sc;
	list_remove(&sc->vmm_holds, hold);
	if (list_is_empty(&sc->vmm_holds)) {
		sc->vmm_flags &= ~VMM_HELD;
		cv_broadcast(&sc->vmm_cv);
	}
	mutex_exit(&vmm_mtx);
	kmem_free(hold, sizeof (*hold));
}

boolean_t
vmm_drv_release_reqd(vmm_hold_t *hold)
{
	ASSERT(hold != NULL);

	return (hold->vmh_release_req);
}

vmm_lease_t *
vmm_drv_lease_sign(vmm_hold_t *hold, boolean_t (*expiref)(void *), void *arg)
{
	vmm_softc_t *sc = hold->vmh_sc;
	vmm_lease_t *lease;

	ASSERT3P(expiref, !=, NULL);

	if (hold->vmh_release_req) {
		return (NULL);
	}

	lease = kmem_alloc(sizeof (*lease), KM_SLEEP);
	list_link_init(&lease->vml_node);
	lease->vml_expire_func = expiref;
	lease->vml_expire_arg = arg;
	lease->vml_expired = B_FALSE;
	lease->vml_hold = hold;
	/* cache the VM pointer for one less pointer chase */
	lease->vml_vm = sc->vmm_vm;

	mutex_enter(&sc->vmm_lease_lock);
	while (sc->vmm_lease_blocker != 0) {
		cv_wait(&sc->vmm_lease_cv, &sc->vmm_lease_lock);
	}
	list_insert_tail(&sc->vmm_lease_list, lease);
	vmm_read_lock(sc);
	mutex_exit(&sc->vmm_lease_lock);

	return (lease);
}

static void
vmm_lease_break_locked(vmm_softc_t *sc, vmm_lease_t *lease)
{
	ASSERT(MUTEX_HELD(&sc->vmm_lease_lock));

	list_remove(&sc->vmm_lease_list, lease);
	vmm_read_unlock(sc);
	kmem_free(lease, sizeof (*lease));
}

void
vmm_drv_lease_break(vmm_hold_t *hold, vmm_lease_t *lease)
{
	vmm_softc_t *sc = hold->vmh_sc;

	VERIFY3P(hold, ==, lease->vml_hold);

	mutex_enter(&sc->vmm_lease_lock);
	vmm_lease_break_locked(sc, lease);
	mutex_exit(&sc->vmm_lease_lock);
}

boolean_t
vmm_drv_lease_expired(vmm_lease_t *lease)
{
	return (lease->vml_expired);
}

void *
vmm_drv_gpa2kva(vmm_lease_t *lease, uintptr_t gpa, size_t sz)
{
	ASSERT(lease != NULL);

	return (vmspace_find_kva(vm_get_vmspace(lease->vml_vm), gpa, sz));
}

int
vmm_drv_msi(vmm_lease_t *lease, uint64_t addr, uint64_t msg)
{
	ASSERT(lease != NULL);

	return (lapic_intr_msi(lease->vml_vm, addr, msg));
}

int
vmm_drv_ioport_hook(vmm_hold_t *hold, uint16_t ioport, vmm_drv_iop_cb_t func,
    void *arg, void **cookie)
{
	vmm_softc_t *sc;
	int err;

	ASSERT(hold != NULL);
	ASSERT(cookie != NULL);

	sc = hold->vmh_sc;
	mutex_enter(&vmm_mtx);
	/* Confirm that hook installation is not blocked */
	if ((sc->vmm_flags & VMM_BLOCK_HOOK) != 0) {
		mutex_exit(&vmm_mtx);
		return (EBUSY);
	}
	/*
	 * Optimistically record an installed hook which will prevent a block
	 * from being asserted while the mutex is dropped.
	 */
	hold->vmh_ioport_hook_cnt++;
	mutex_exit(&vmm_mtx);

	vmm_write_lock(sc);
	err = vm_ioport_hook(sc->vmm_vm, ioport, (ioport_handler_t)func,
	    arg, cookie);
	vmm_write_unlock(sc);

	if (err != 0) {
		mutex_enter(&vmm_mtx);
		/* Walk back optimism about the hook installation */
		hold->vmh_ioport_hook_cnt--;
		mutex_exit(&vmm_mtx);
	}
	return (err);
}

void
vmm_drv_ioport_unhook(vmm_hold_t *hold, void **cookie)
{
	vmm_softc_t *sc;

	ASSERT(hold != NULL);
	ASSERT(cookie != NULL);
	ASSERT(hold->vmh_ioport_hook_cnt != 0);

	sc = hold->vmh_sc;
	vmm_write_lock(sc);
	vm_ioport_unhook(sc->vmm_vm, cookie);
	vmm_write_unlock(sc);

	mutex_enter(&vmm_mtx);
	hold->vmh_ioport_hook_cnt--;
	mutex_exit(&vmm_mtx);
}

static int
vmm_drv_purge(vmm_softc_t *sc)
{
	ASSERT(MUTEX_HELD(&vmm_mtx));

	if ((sc->vmm_flags & VMM_HELD) != 0) {
		vmm_hold_t *hold;

		sc->vmm_flags |= VMM_CLEANUP;
		for (hold = list_head(&sc->vmm_holds); hold != NULL;
		    hold = list_next(&sc->vmm_holds, hold)) {
			hold->vmh_release_req = B_TRUE;
		}
		while ((sc->vmm_flags & VMM_HELD) != 0) {
			if (cv_wait_sig(&sc->vmm_cv, &vmm_mtx) <= 0) {
				return (EINTR);
			}
		}
		sc->vmm_flags &= ~VMM_CLEANUP;
	}

	VERIFY(list_is_empty(&sc->vmm_holds));
	sc->vmm_flags |= VMM_PURGED;
	return (0);
}

static int
vmm_drv_block_hook(vmm_softc_t *sc, boolean_t enable_block)
{
	int err = 0;

	mutex_enter(&vmm_mtx);
	if (!enable_block) {
		VERIFY((sc->vmm_flags & VMM_BLOCK_HOOK) != 0);

		sc->vmm_flags &= ~VMM_BLOCK_HOOK;
		goto done;
	}

	/* If any holds have hooks installed, the block is a failure */
	if (!list_is_empty(&sc->vmm_holds)) {
		vmm_hold_t *hold;

		for (hold = list_head(&sc->vmm_holds); hold != NULL;
		    hold = list_next(&sc->vmm_holds, hold)) {
			if (hold->vmh_ioport_hook_cnt != 0) {
				err = EBUSY;
				goto done;
			}
		}
	}
	sc->vmm_flags |= VMM_BLOCK_HOOK;

done:
	mutex_exit(&vmm_mtx);
	return (err);
}

static int
vmm_do_vm_destroy_locked(vmm_softc_t *sc, boolean_t clean_zsd,
    boolean_t *hma_release)
{
	dev_info_t	*pdip = ddi_get_parent(vmmdev_dip);
	minor_t		minor;

	ASSERT(MUTEX_HELD(&vmm_mtx));

	*hma_release = B_FALSE;

	if (vmm_drv_purge(sc) != 0) {
		return (EINTR);
	}

	if (clean_zsd) {
		vmm_zsd_rem_vm(sc);
	}

	/* Clean up devmem entries */
	vmmdev_devmem_purge(sc);

	list_remove(&vmm_list, sc);
	ddi_remove_minor_node(vmmdev_dip, sc->vmm_name);
	minor = sc->vmm_minor;
	zone_rele(sc->vmm_zone);
	if (sc->vmm_is_open) {
		list_insert_tail(&vmm_destroy_list, sc);
		sc->vmm_flags |= VMM_DESTROY;
	} else {
		vm_destroy(sc->vmm_vm);
		ddi_soft_state_free(vmm_statep, minor);
		id_free(vmm_minors, minor);
		*hma_release = B_TRUE;
	}
	(void) devfs_clean(pdip, NULL, DV_CLEAN_FORCE);

	return (0);
}

int
vmm_do_vm_destroy(vmm_softc_t *sc, boolean_t clean_zsd)
{
	boolean_t	hma_release = B_FALSE;
	int		err;

	mutex_enter(&vmm_mtx);
	err = vmm_do_vm_destroy_locked(sc, clean_zsd, &hma_release);
	mutex_exit(&vmm_mtx);

	if (hma_release)
		vmm_hma_release();

	return (err);
}

/* ARGSUSED */
static int
vmmdev_do_vm_destroy(const char *name, cred_t *cr)
{
	boolean_t	hma_release = B_FALSE;
	vmm_softc_t	*sc;
	int		err;

	if (crgetuid(cr) != 0)
		return (EPERM);

	mutex_enter(&vmm_mtx);

	if ((sc = vmm_lookup(name)) == NULL) {
		mutex_exit(&vmm_mtx);
		return (ENOENT);
	}
	/*
	 * We don't check this in vmm_lookup() since that function is also used
	 * for validation during create and currently vmm names must be unique.
	 */
	if (!INGLOBALZONE(curproc) && sc->vmm_zone != curzone) {
		mutex_exit(&vmm_mtx);
		return (EPERM);
	}
	err = vmm_do_vm_destroy_locked(sc, B_TRUE, &hma_release);

	mutex_exit(&vmm_mtx);

	if (hma_release)
		vmm_hma_release();

	return (err);
}

static int
vmm_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	minor_t		minor;
	vmm_softc_t	*sc;

	minor = getminor(*devp);
	if (minor == VMM_CTL_MINOR) {
		/*
		 * Master control device must be opened exclusively.
		 */
		if ((flag & FEXCL) != FEXCL || otyp != OTYP_CHR) {
			return (EINVAL);
		}

		return (0);
	}

	mutex_enter(&vmm_mtx);
	sc = ddi_get_soft_state(vmm_statep, minor);
	if (sc == NULL) {
		mutex_exit(&vmm_mtx);
		return (ENXIO);
	}

	sc->vmm_is_open = B_TRUE;
	mutex_exit(&vmm_mtx);

	return (0);
}

static int
vmm_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	minor_t		minor;
	vmm_softc_t	*sc;
	boolean_t	hma_release = B_FALSE;

	minor = getminor(dev);
	if (minor == VMM_CTL_MINOR)
		return (0);

	mutex_enter(&vmm_mtx);
	sc = ddi_get_soft_state(vmm_statep, minor);
	if (sc == NULL) {
		mutex_exit(&vmm_mtx);
		return (ENXIO);
	}

	VERIFY(sc->vmm_is_open);
	sc->vmm_is_open = B_FALSE;

	/*
	 * If this VM was destroyed while the vmm device was open, then
	 * clean it up now that it is closed.
	 */
	if (sc->vmm_flags & VMM_DESTROY) {
		list_remove(&vmm_destroy_list, sc);
		vm_destroy(sc->vmm_vm);
		ddi_soft_state_free(vmm_statep, minor);
		id_free(vmm_minors, minor);
		hma_release = B_TRUE;
	}
	mutex_exit(&vmm_mtx);

	if (hma_release)
		vmm_hma_release();

	return (0);
}

static int
vmm_is_supported(intptr_t arg)
{
	int r;
	const char *msg;

	if (vmm_is_intel()) {
		r = vmx_x86_supported(&msg);
	} else if (vmm_is_svm()) {
		/*
		 * HMA already ensured that the features necessary for SVM
		 * operation were present and online during vmm_attach().
		 */
		r = 0;
	} else {
		r = ENXIO;
		msg = "Unsupported CPU vendor";
	}

	if (r != 0 && arg != (intptr_t)NULL) {
		if (copyoutstr(msg, (char *)arg, strlen(msg) + 1, NULL) != 0)
			return (EFAULT);
	}
	return (r);
}

static int
vmm_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	vmm_softc_t	*sc;
	minor_t		minor;

	/* The structs in bhyve ioctls assume a 64-bit datamodel */
	if (ddi_model_convert_from(mode & FMODELS) != DDI_MODEL_NONE) {
		return (ENOTSUP);
	}

	minor = getminor(dev);

	if (minor == VMM_CTL_MINOR) {
		void *argp = (void *)arg;
		char name[VM_MAX_NAMELEN] = { 0 };
		size_t len = 0;

		if ((mode & FKIOCTL) != 0) {
			len = strlcpy(name, argp, sizeof (name));
		} else {
			if (copyinstr(argp, name, sizeof (name), &len) != 0) {
				return (EFAULT);
			}
		}
		if (len >= VM_MAX_NAMELEN) {
			return (ENAMETOOLONG);
		}

		switch (cmd) {
		case VMM_CREATE_VM:
			if ((mode & FWRITE) == 0)
				return (EPERM);
			return (vmmdev_do_vm_create(name, credp));
		case VMM_DESTROY_VM:
			if ((mode & FWRITE) == 0)
				return (EPERM);
			return (vmmdev_do_vm_destroy(name, credp));
		case VMM_VM_SUPPORTED:
			return (vmm_is_supported(arg));
		default:
			/* No other actions are legal on ctl device */
			return (ENOTTY);
		}
	}

	sc = ddi_get_soft_state(vmm_statep, minor);
	ASSERT(sc);

	if (sc->vmm_flags & VMM_DESTROY)
		return (ENXIO);

	return (vmmdev_do_ioctl(sc, cmd, arg, mode, credp, rvalp));
}

static int
vmm_segmap(dev_t dev, off_t off, struct as *as, caddr_t *addrp, off_t len,
    unsigned int prot, unsigned int maxprot, unsigned int flags, cred_t *credp)
{
	vmm_softc_t *sc;
	const minor_t minor = getminor(dev);
	struct vm *vm;
	int err;
	vm_object_t vmo = NULL;
	struct vmspace *vms;

	if (minor == VMM_CTL_MINOR) {
		return (ENODEV);
	}
	if (off < 0 || (off + len) <= 0) {
		return (EINVAL);
	}
	if ((prot & PROT_USER) == 0) {
		return (EACCES);
	}

	sc = ddi_get_soft_state(vmm_statep, minor);
	ASSERT(sc);

	if (sc->vmm_flags & VMM_DESTROY)
		return (ENXIO);

	/* Grab read lock on the VM to prevent any changes to the memory map */
	vmm_read_lock(sc);

	vm = sc->vmm_vm;
	vms = vm_get_vmspace(vm);
	if (off >= VM_DEVMEM_START) {
		int segid;
		off_t map_off = 0;

		/* Mapping a devmem "device" */
		if (!vmmdev_devmem_segid(sc, off, len, &segid, &map_off)) {
			err = ENODEV;
			goto out;
		}
		err = vm_get_memseg(vm, segid, NULL, NULL, &vmo);
		if (err != 0) {
			goto out;
		}
		err = vm_segmap_obj(vmo, map_off, len, as, addrp, prot, maxprot,
		    flags);
	} else {
		/* Mapping a part of the guest physical space */
		err = vm_segmap_space(vms, off, as, addrp, len, prot, maxprot,
		    flags);
	}


out:
	vmm_read_unlock(sc);
	return (err);
}

static sdev_plugin_validate_t
vmm_sdev_validate(sdev_ctx_t ctx)
{
	const char *name = sdev_ctx_name(ctx);
	vmm_softc_t *sc;
	sdev_plugin_validate_t ret;
	minor_t minor;

	if (sdev_ctx_vtype(ctx) != VCHR)
		return (SDEV_VTOR_INVALID);

	VERIFY3S(sdev_ctx_minor(ctx, &minor), ==, 0);

	mutex_enter(&vmm_mtx);
	if ((sc = vmm_lookup(name)) == NULL)
		ret = SDEV_VTOR_INVALID;
	else if (sc->vmm_minor != minor)
		ret = SDEV_VTOR_STALE;
	else
		ret = SDEV_VTOR_VALID;
	mutex_exit(&vmm_mtx);

	return (ret);
}

static int
vmm_sdev_filldir(sdev_ctx_t ctx)
{
	vmm_softc_t *sc;
	int ret;

	if (strcmp(sdev_ctx_path(ctx), VMM_SDEV_ROOT) != 0) {
		cmn_err(CE_WARN, "%s: bad path '%s' != '%s'\n", __func__,
		    sdev_ctx_path(ctx), VMM_SDEV_ROOT);
		return (EINVAL);
	}

	mutex_enter(&vmm_mtx);
	ASSERT(vmmdev_dip != NULL);
	for (sc = list_head(&vmm_list); sc != NULL;
	    sc = list_next(&vmm_list, sc)) {
		if (INGLOBALZONE(curproc) || sc->vmm_zone == curzone) {
			ret = sdev_plugin_mknod(ctx, sc->vmm_name,
			    S_IFCHR | 0600,
			    makedevice(ddi_driver_major(vmmdev_dip),
			    sc->vmm_minor));
		} else {
			continue;
		}
		if (ret != 0 && ret != EEXIST)
			goto out;
	}

	ret = 0;

out:
	mutex_exit(&vmm_mtx);
	return (ret);
}

/* ARGSUSED */
static void
vmm_sdev_inactive(sdev_ctx_t ctx)
{
}

static sdev_plugin_ops_t vmm_sdev_ops = {
	.spo_version = SDEV_PLUGIN_VERSION,
	.spo_flags = SDEV_PLUGIN_SUBDIR,
	.spo_validate = vmm_sdev_validate,
	.spo_filldir = vmm_sdev_filldir,
	.spo_inactive = vmm_sdev_inactive
};

/* ARGSUSED */
static int
vmm_info(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	int error;

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = (void *)vmmdev_dip;
		error = DDI_SUCCESS;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
		break;
	}
	return (error);
}

static int
vmm_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	sdev_plugin_hdl_t sph;
	hma_reg_t *reg = NULL;
	boolean_t vmm_loaded = B_FALSE;

	if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	mutex_enter(&vmmdev_mtx);
	/* Ensure we are not already attached. */
	if (vmmdev_dip != NULL) {
		mutex_exit(&vmmdev_mtx);
		return (DDI_FAILURE);
	}

	vmm_sol_glue_init();
	vmm_arena_init();

	/*
	 * Perform temporary HMA registration to determine if the system
	 * is capable.
	 */
	if ((reg = hma_register(vmmdev_hvm_name)) == NULL) {
		goto fail;
	} else if (vmm_mod_load() != 0) {
		goto fail;
	}
	vmm_loaded = B_TRUE;
	hma_unregister(reg);
	reg = NULL;

	/* Create control node.  Other nodes will be created on demand. */
	if (ddi_create_minor_node(dip, "ctl", S_IFCHR,
	    VMM_CTL_MINOR, DDI_PSEUDO, 0) != 0) {
		goto fail;
	}

	if ((sph = sdev_plugin_register("vmm", &vmm_sdev_ops, NULL)) ==
	    (sdev_plugin_hdl_t)NULL) {
		ddi_remove_minor_node(dip, NULL);
		goto fail;
	}

	ddi_report_dev(dip);
	vmmdev_sdev_hdl = sph;
	vmmdev_dip = dip;
	mutex_exit(&vmmdev_mtx);
	return (DDI_SUCCESS);

fail:
	if (vmm_loaded) {
		VERIFY0(vmm_mod_unload());
	}
	if (reg != NULL) {
		hma_unregister(reg);
	}
	vmm_arena_fini();
	vmm_sol_glue_cleanup();
	mutex_exit(&vmmdev_mtx);
	return (DDI_FAILURE);
}

static int
vmm_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}

	/*
	 * Ensure that all resources have been cleaned up.
	 *
	 * To prevent a deadlock with iommu_cleanup() we'll fail the detach if
	 * vmmdev_mtx is already held. We can't wait for vmmdev_mtx with our
	 * devinfo locked as iommu_cleanup() tries to recursively lock each
	 * devinfo, including our own, while holding vmmdev_mtx.
	 */
	if (mutex_tryenter(&vmmdev_mtx) == 0)
		return (DDI_FAILURE);

	mutex_enter(&vmm_mtx);
	if (!list_is_empty(&vmm_list) || !list_is_empty(&vmm_destroy_list)) {
		mutex_exit(&vmm_mtx);
		mutex_exit(&vmmdev_mtx);
		return (DDI_FAILURE);
	}
	mutex_exit(&vmm_mtx);

	VERIFY(vmmdev_sdev_hdl != (sdev_plugin_hdl_t)NULL);
	if (sdev_plugin_unregister(vmmdev_sdev_hdl) != 0) {
		mutex_exit(&vmmdev_mtx);
		return (DDI_FAILURE);
	}
	vmmdev_sdev_hdl = (sdev_plugin_hdl_t)NULL;

	/* Remove the control node. */
	ddi_remove_minor_node(dip, "ctl");
	vmmdev_dip = NULL;

	VERIFY0(vmm_mod_unload());
	VERIFY3U(vmmdev_hma_reg, ==, NULL);
	vmm_arena_fini();
	vmm_sol_glue_cleanup();

	mutex_exit(&vmmdev_mtx);

	return (DDI_SUCCESS);
}

static struct cb_ops vmm_cb_ops = {
	vmm_open,
	vmm_close,
	nodev,		/* strategy */
	nodev,		/* print */
	nodev,		/* dump */
	nodev,		/* read */
	nodev,		/* write */
	vmm_ioctl,
	nodev,		/* devmap */
	nodev,		/* mmap */
	vmm_segmap,
	nochpoll,	/* poll */
	ddi_prop_op,
	NULL,
	D_NEW | D_MP | D_DEVMAP
};

static struct dev_ops vmm_ops = {
	DEVO_REV,
	0,
	vmm_info,
	nulldev,	/* identify */
	nulldev,	/* probe */
	vmm_attach,
	vmm_detach,
	nodev,		/* reset */
	&vmm_cb_ops,
	(struct bus_ops *)NULL
};

static struct modldrv modldrv = {
	&mod_driverops,
	"bhyve vmm",
	&vmm_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

int
_init(void)
{
	int	error;

	sysinit();

	mutex_init(&vmmdev_mtx, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&vmm_mtx, NULL, MUTEX_DRIVER, NULL);
	list_create(&vmm_list, sizeof (vmm_softc_t),
	    offsetof(vmm_softc_t, vmm_node));
	list_create(&vmm_destroy_list, sizeof (vmm_softc_t),
	    offsetof(vmm_softc_t, vmm_node));
	vmm_minors = id_space_create("vmm_minors", VMM_CTL_MINOR + 1, MAXMIN32);

	error = ddi_soft_state_init(&vmm_statep, sizeof (vmm_softc_t), 0);
	if (error) {
		return (error);
	}

	vmm_zsd_init();

	error = mod_install(&modlinkage);
	if (error) {
		ddi_soft_state_fini(&vmm_statep);
		vmm_zsd_fini();
	}

	return (error);
}

int
_fini(void)
{
	int	error;

	error = mod_remove(&modlinkage);
	if (error) {
		return (error);
	}

	vmm_zsd_fini();

	ddi_soft_state_fini(&vmm_statep);

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
