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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
# Copyright 2016 Toomas Soome <tsoome@me.com>
#
# Copyright (c) 2018, Joyent, Inc.

LIBRARY =	libdns_sd.a
VERS =		.1
OBJECTS =	dnssd_clientlib.o dnssd_clientstub.o dnssd_ipc.o

include ../../Makefile.lib

MAPFILEDIR=	../common
SRCDIR=		$(SRC)/contrib/mDNSResponder/mDNSShared
LIBS =		$(DYNLIB)

LDLIBS +=	-lsocket -lnsl -lc

CSTD =	$(CSTD_GNU99)
CPPFLAGS +=	-I$(SRCDIR) -DNOT_HAVE_SA_LEN -D_XPG4_2 -D__EXTENSIONS__
CPPFLAGS +=	-DMDNS_VERSIONSTR_NODTS -DmDNSResponderVersion=1310.80.1

pics/dnssd_clientstub.o := CERRWARN +=	-_gcc=-Wno-unused-but-set-variable

# not linted
SMATCH=off

.PARALLEL =     $(OBJECTS)
.KEEP_STATE:

all: $(LIBS)

pics/%.o:	$(SRCDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

include ../../Makefile.targ
