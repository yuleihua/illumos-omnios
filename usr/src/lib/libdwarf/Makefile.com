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
# Copyright 2015 Joyent, Inc.
#

LIBRARY=	libdwarf.a
VERS=		.1

OBJECTS=dwarf_abbrev.o		\
	dwarf_alloc.o		\
	dwarf_arange.o		\
	dwarf_debuglink.o	\
	dwarf_die_deliv.o	\
	dwarf_dnames.o		\
	dwarf_dsc.o		\
	dwarf_elf_access.o	\
	dwarf_elf_load_headers.o \
	dwarf_elf_rel_detector.o \
	dwarf_elfread.o		\
	dwarf_error.o		\
	dwarf_form.o		\
	dwarf_frame.o		\
	dwarf_frame2.o		\
	dwarf_funcs.o		\
	dwarf_gdbindex.o	\
	dwarf_generic_init.o	\
	dwarf_global.o		\
	dwarf_groups.o		\
	dwarf_harmless.o	\
	dwarf_init_finish.o	\
	dwarf_leb.o		\
	dwarf_line.o		\
	dwarf_loc.o		\
	dwarf_locationop_read.o \
	dwarf_loclists.o	\
	dwarf_machoread.o	\
	dwarf_macro.o		\
	dwarf_macro5.o		\
	dwarf_names.o		\
	dwarf_object_detector.o	\
	dwarf_object_read_common.o \
	dwarf_original_elf_init.o	\
	dwarf_peread.o		\
	dwarf_print_lines.o	\
	dwarf_pubtypes.o	\
	dwarf_query.o		\
	dwarf_ranges.o		\
	dwarf_rnglists.o	\
	dwarf_str_offsets.o	\
	dwarf_stringsection.o	\
	dwarf_stubs.o		\
	dwarf_tied.o		\
	dwarf_tsearchhash.o	\
	dwarf_types.o		\
	dwarf_util.o		\
	dwarf_vars.o		\
	dwarf_weaks.o		\
	dwarf_xu_index.o	\
	dwarfstring.o		\
	dwgetopt.o		\
	gennames.o		\
	malloc_check.o		\
	pro_alloc.o		\
	pro_arange.o		\
	pro_die.o		\
	pro_dnames.o		\
	pro_encode_nm.o		\
	pro_error.o		\
	pro_expr.o		\
	pro_finish.o		\
	pro_forms.o		\
	pro_frame.o		\
	pro_funcs.o		\
	pro_init.o		\
	pro_line.o		\
	pro_log_extra_flag_strings.o \
	pro_macinfo.o		\
	pro_pubnames.o		\
	pro_reloc_stream.o	\
	pro_reloc_symbolic.o	\
	pro_reloc.o		\
	pro_section.o		\
	pro_types.o		\
	pro_vars.o		\
	pro_weaks.o

include ../../Makefile.lib
include ../../Makefile.rootfs

LIBS =		$(DYNLIB)
LDLIBS +=	-lelf -lc -lz
NATIVE_LIBS +=	libz.so

SRCDIR =	../common
CFLAGS64 +=	$(C_BIGPICFLAGS)
CPPFLAGS +=	-I$(SRCDIR) -DELF_TARGET_ALL=1
CERRWARN +=	-_gcc=-Wno-unused
CERRWARN +=	-_gcc=-Wno-implicit-function-declaration

SMATCH =	off

.KEEP_STATE:

all:	$(LIBS)


include ../../Makefile.targ
