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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright 2020 Tintri by DDN, Inc. All rights reserved.
#

LIBRARY =	libmlrpc.a
VERS =		.2

OBJS_COMMON =			\
	mlrpc_clh.o		\
	ndr_auth.o		\
	ndr_client.o		\
	ndr_heap.o		\
	ndr_marshal.o		\
	ndr_ops.o		\
	ndr_process.o		\
	ndr_server.o		\
	ndr_svc.o		\
	ndr_wchar.o

NDLLIST = rpcpdu

OBJECTS=	$(OBJS_COMMON) $(NDLLIST:%=%_ndr.o)
CLEANFILES += $(NDLLIST:%=%_ndr.c)

include ../../Makefile.lib

LIBS=		$(DYNLIB)

LDLIBS +=	-lsmbfs -luuid -lc

SRCDIR=		../common
SRCS=   $(OBJS_COMMON:%.o=$(SRCDIR)/%.c)

NDLDIR =	$(SRCDIR)

CFLAGS +=	$(CCVERBOSE)
INCS = -I. -I$(SRCDIR)
CPPFLAGS += $(INCS) -D_REENTRANT

all:	$(LIBS)


include ../../Makefile.targ

objs/%_ndr.o pics/%_ndr.o : %_ndr.c

%_ndr.c : $(NDLDIR)/%.ndl
	$(NDRGEN) -Y $(ANSI_CPP) $(CPPFLAGS) $<

.KEEP_STATE:
