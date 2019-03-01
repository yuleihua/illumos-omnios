#
# CDDL HEADER START
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source. A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#
# CDDL HEADER END
#

#
# Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
#

PROG=		in.cdpd
SRCS=		cdp.c dlenum.c dlpi.c ipc.c yuka.c
OBJS=		$(SRCS:.c=.o)
MANIFEST=	cdpd.xml

include ../../../Makefile.cmd
include ../../../Makefile.cmd.64

include ../Makefile.lib

ROOTMANIFESTDIR=	$(ROOTSVCNETWORK)

CSTD=		$(CSTD_GNU99)

LDLIBS += -lsocket -ldladm -ldlpi

#
# Instrument with CTF data to ease debugging.
#
CTFCONVERT_HOOK = && $(CTFCONVERT_O)
CTFMERGE_HOOK = && $(CTFMERGE) -L VERSION -o $@ $(OBJS)
$(OBJS) := CFLAGS64 += $(CTF_FLAGS)

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS) $(CTFMERGE_HOOK)
	$(POST_PROCESS)

install: all $(ROOTMANIFEST) $(ROOTLIBINETPROG)

check:	$(CHKMANIFEST)

clean:
	$(RM) $(OBJS)

include ../../../Makefile.targ
