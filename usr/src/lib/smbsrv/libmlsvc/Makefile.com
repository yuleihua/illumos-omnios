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
# Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2020 Tintri by DDN, Inc. All rights reserved.
#
# Copyright (c) 2018, Joyent, Inc.

LIBRARY =	libmlsvc.a
VERS =		.1

OBJS_COMMON =		\
	dfs.o		\
	dssetup_clnt.o	\
	dssetup_svc.o	\
	eventlog_svc.o	\
	eventlog_log.o	\
	lsalib.o	\
	lsar_clnt.o	\
	lsar_svc.o	\
	mlsvc_client.o	\
	mlsvc_domain.o	\
	mlsvc_init.o	\
	mlsvc_netr.o	\
	mlsvc_util.o	\
	msgsvc_svc.o	\
	netdfs.o	\
	netr_auth.o	\
	netr_logon.o	\
	netr_ssp.o	\
	samlib.o	\
	samr_clnt.o	\
	samr_svc.o	\
	smb_autohome.o	\
	smb_logon.o	\
	smb_share.o	\
	smb_quota.o	\
	smbrdr_glue.o	\
	spoolss_svc.o	\
	srvsvc_clnt.o	\
	srvsvc_sd.o	\
	srvsvc_svc.o	\
	svcctl_scm.o	\
	svcctl_svc.o	\
	winreg_svc.o	\
	wkssvc_svc.o

# Automatically generated from .ndl files
NDLLIST =		\
	dssetup		\
	eventlog	\
	lsarpc		\
	msgsvc		\
	netdfs		\
	netlogon	\
	samrpc		\
	spoolss		\
	srvsvc		\
	svcctl		\
	winreg

OBJECTS=        $(OBJS_COMMON) $(NDLLIST:%=%_ndr.o)

include ../../../Makefile.lib
include ../../Makefile.lib

INCS += -I$(SRC)/common/smbsrv
INCS += -I$(SRC)/uts/common/smbsrv/ndl

LDLIBS +=	$(MACH_LDLIBS)
LDLIBS += -lmlrpc -lsmb -lsmbns -lshare -lsmbfs -lnsl -lpkcs11 -lmd5	 \
	-lscf -lcmdutils -lsec -lavl -lnvpair -luutil -luuid -lgen -lzfs \
	-lresolv -lc

CPPFLAGS += $(INCS) -D_REENTRANT
CPPFLAGS += -Dsyslog=smb_syslog
$(ENABLE_SMB_PRINTING) CPPFLAGS += -DHAVE_CUPS

CERRWARN += -_gcc=-Wno-unused-function
CERRWARN += $(CNOWARN_UNINIT)

# not linted
SMATCH=off


SRCS=   $(OBJS_COMMON:%.o=$(SRCDIR)/%.c)

include ../../Makefile.targ
include ../../../Makefile.targ
