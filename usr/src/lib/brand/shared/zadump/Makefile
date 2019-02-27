#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
#

PROG =		zadump

include ../../../../cmd/Makefile.cmd
include ../../../../cmd/Makefile.cmd.64
include ../../Makefile.brand

SRCS =		zadump.c
OBJS =		$(SRCS:.c=.o)

SHARED =	$(PROG)
CLEANFILES =	$(PROG)

.KEEP_STATE:

LDLIBS +=	-L$(ROOT)/lib
LDLIBS +=	-ldladm

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDFLAGS) $(LDLIBS)
	$(POST_PROCESS)

%.o: %.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

$(ROOTSHARED) :=        FILEMODE = 755
install: all $(ROOTSHARED)

CLOBBERFILES += $(ROOTSHARED)

clean:
	$(RM) $(OBJS) $(CLEANFILES)

clobber: clean
	$(RM) $(CLOBBERFILES)

