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
# Copyright (c) 1998, 2010, Oracle and/or its affiliates. All rights reserved.
#
# Copyright (c) 2018, Joyent, Inc.

PROG= savecore
SRCS= ../savecore.c ../../../uts/common/os/compress.c
OBJS= savecore.o compress.o

include ../../Makefile.cmd

CSTD = $(CSTD_GNU99)

CFLAGS += $(CCVERBOSE)
CFLAGS64 += $(CCVERBOSE)
CPPFLAGS += -D_LARGEFILE64_SOURCE=1 -DBZ_NO_STDIO -I$(SRC)/uts/common

# not linted
SMATCH=off

#
# savecore is compiled with bits from $(SRC)/common/bzip2 and some function
# symbols there are defined as weak; if you leave them out of
# savecore.c it will compile, but trying to call that function
# will jump to 0.  So we use -ztext to avoid that.
#
LDFLAGS += $(ZTEXT)

BZIP2OBJS =	bz2blocksort.o	\
		bz2compress.o	\
		bz2decompress.o	\
		bz2randtable.o	\
		bz2bzlib.o	\
		bz2crctable.o	\
		bz2huffman.o

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS) $(BZIP2OBJS)
	$(LINK.c) -o $(PROG) $(OBJS) $(BZIP2OBJS) $(LDLIBS)
	$(POST_PROCESS)

clean:
	$(RM) $(OBJS) $(BZIP2OBJS)

include ../../Makefile.targ

%.o: ../%.c
	$(COMPILE.c) -I$(SRC)/common $<
	$(POST_PROCESS_O)

%.o: ../../../uts/common/os/%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

bz2%.o: ../../../common/bzip2/%.c
	$(COMPILE.c) -o $@ -I$(SRC)/common -I$(SRC)/common/bzip2 $<
	$(POST_PROCESS_O)
