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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

.KEEP_STATE:

PROG = ctfstabs
SRCS = \
	ctfstabs.c \
	forth.c \
	fth_enum.c \
	fth_struct.c \
	genassym.c \
	memory.c \
	utils.c

include ../../Makefile.ctf
include ../../Makefile.ctf.post

LDLIBS += -lctf
NATIVE_LIBS += libctf.so

OBJS = $(SRCS:%.c=%.o) list.o

CERRWARN += $(CNOWARN_UNINIT)
CERRWARN += -_gcc=-Wno-unused

.NO_PARALLEL:
.PARALLEL: $(OBJS)

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

%.o: ../common/%.c
	$(COMPILE.c) $<

%.o: $(SRC)/common/list/%.c
	$(COMPILE.c) $<

$(ROOTONBLDMACHPROG): $(PROG)

install: $(ROOTONBLDMACHPROG)

clean:
	$(RM) $(OBJS)

include ../../Makefile.ctf.targ
