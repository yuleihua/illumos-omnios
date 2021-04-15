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
#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
# Copyright 2020 Joyent, Inc.
#

LX_CMN  =	$(SRC)/common/brand/lx

LIBRARY =	lx_brand.a
VERS	=	.1
COBJS	=	capabilities.o		\
		clock.o			\
		clone.o			\
		debug.o			\
		dir.o			\
		file.o			\
		fork.o			\
		lx_brand.o		\
		misc.o			\
		module.o		\
		mount.o			\
		mount_nfs.o		\
		ptrace.o		\
		sendfile.o		\
		signal.o		\
		stack.o			\
		statfs.o		\
		sysctl.o		\
		sysv_ipc.o		\
		time.o			\
		truncate.o

CMNOBJS =	lx_auxv.o	\
		lx_errno.o	\
		lx_signum.o
ASOBJS	=	lx_handler.o lx_crt.o
OBJECTS	=	$(CMNOBJS) $(COBJS) $(ASOBJS)

USDT_PROVIDERS =	lx_provider.d

include ../../Makefile.lx
include ../../../../Makefile.lib

CSRCS   =	$(COBJS:%o=../common/%c) $(CMNOBJS:%o=$(LX_CMN)/%c)
ASSRCS  =	$(ASOBJS:%o=$(ISASRCDIR)/%s)
SRCS    =	$(CSRCS) $(ASSRCS)

SRCDIR =	../common
UTSBASE	=	../../../../../uts

LIBS =		$(DYNLIB)
LDLIBS +=	-lmapmalloc -lsocket -lrpcsvc -lnsl -lc
DYNFLAGS +=	$(DYNFLAGS_$(CLASS))
DYNFLAGS +=	$(BLOCAL) $(ZNOVERSION) -Wl,-e_start
CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-D_REENTRANT -I. -I../ -I$(UTSBASE)/common/brand/lx -I$(LX_CMN)
ASFLAGS =	-P $(ASFLAGS_$(CURTYPE)) -D_ASM -I../	\
			-I$(UTSBASE)/common/brand/lx

ZGUIDANCE =	-Wl,-zguidance=nounused

# not linted
SMATCH=off

C99MODE=	-xc99=%all
C99LMODE=	-Xc99=%all

.KEEP_STATE:

all: $(LIBS)

lint: lintcheck

include ../../../../Makefile.targ
include ../../../../Makefile.usdt

pics/%.o: $(ISASRCDIR)/%.s
	$(COMPILE.s) -o $@ $<
	$(POST_PROCESS_S_O)

pics/%.o: $(LX_CMN)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
