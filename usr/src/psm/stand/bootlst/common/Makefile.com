#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# psm/stand/bootlst/common/Makefile.com
#

TOPDIR	=	../../../../..

include $(TOPDIR)/Makefile.master
include $(TOPDIR)/Makefile.psm
include $(TOPDIR)/psm/stand/lib/Makefile.lib

SYSDIR	=	$(TOPDIR)/uts
COMDIR	=	../../common
STANDDIR =	$(TOPDIR)/stand

SALIBDIR =	$(STANDDIR)/lib/sa
SALIB =		$(SALIBDIR)/libsa.a
PROMLIBDIR=	$(PROMIFDIR)/$(ARCH_PROMDIR)
PROMLIB	=	$(PROMLIBDIR)/libprom.a

SALIBS +=	$(SALIB) $(PROMLIB)
LDLIBS =	-L$(SALIBDIR) -lsa -L$(PROMLIBDIR) -lprom $(LDPLATLIBS)
LDFLAGS =	-Wl,-dn -Wl,-M$(MAPFILE) $(MAP_FLAG)

BOOTLSTOBJ +=	 bootlst.o sasubr.o

CPPDEFS =	-D$(ARCH) -D__$(ARCH) -D$(TARG_MACH) -D__$(TARG_MACH)
CPPDEFS +=	-D_KERNEL -D_MACHDEP -D__ELF

CPPINCS	=	-I$(SYSDIR)/common -I$(SYSDIR)/sun
CPPINCS +=	-I$(SYSDIR)/$(MACH) -I$(PLATDIR)
CPPINCS +=	-I$(STANDDIR)/lib/sa

CPPFLAGS =	$(CPPDEFS) $(CPPINCS)
CPPFLAGS	+= $(CCYFLAG)$(STANDDIR)

CSTD =	$(CSTD_GNU99)
CFLAGS =	$(CCVERBOSE) -O $(CSTD)

ASFLAGS =	-P -D_ASM $(CPPDEFS) -DLOCORE -D_LOCORE -D__STDC__
AS_CPPFLAGS =	$(CPPINCS) $(CPPFLAGS.master)

# install values
LSTFILES=	$(ALL:%=$(ROOT_PSM_DIR)/$(ARCH)/%)
FILEMODE=	644

# install rule
$(ROOT_PSM_DIR)/$(ARCH)/%: %
	$(INS.file)


all:	$(ALL)

install: all $(LSTFILES)

# build rules

%.o: $(COMDIR)/%.c
	$(COMPILE.c) -o $@ $<

.KEEP_STATE:

.PARALLEL:	$(BOOTLSTOBJ)

bootlst: $(MAPFILE) $(BOOTLSTOBJ) $(SALIBS)
	$(LD) $(LDFLAGS) -o $@ $(BOOTLSTOBJ) $(LDLIBS)
	$(POST_PROCESS)

$(SALIBS): FRC
	@cd $(@D); $(MAKE) $(MFLAGS)

$(ROOTDIR):
	$(INS.dir)

clean:
	$(RM) *.o *.ln

clobber:
	$(RM) *.o *.ln $(ALL)

FRC:
