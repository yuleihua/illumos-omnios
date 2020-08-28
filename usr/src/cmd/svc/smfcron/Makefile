#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source. A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.

# Copyright 2020 OmniOS Community Edition (OmniOSce) Association.

PROG= smfcron

SRCS= $(PROG:%=%.sh)

ROOTLIBSVCBINPROG = $(ROOT)/lib/svc/bin/$(PROG)

include ../../Makefile.cmd

FILEMODE= 0555

.KEEP_STATE:

all: $(PROG)

install: all $(ROOTLIBSVCBINPROG)

$(ROOTLIBSVCBIN)/%: %
	$(INS.file)

clean:

include ../../Makefile.targ
