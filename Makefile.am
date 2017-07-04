# Copyright © 2017 Collabora Ltd

# This file is part of libcapsule.

# libcapsule is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.

# libcapsule is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public
# License along with libcapsule.  If not, see <http://www.gnu.org/licenses/>.

V                     ?= 0
AUTOMAKE_OPTIONS       = subdir-objects
ACLOCAL_AMFLAGS        = -I m4
AM_CFLAGS              = --std=c99 -D_GNU_SOURCE -Wall -Werror

bin_PROGRAMS           = elf-dump print-libstubs
lib_LTLIBRARIES        = libcapsule.la

lib_LTLIBRARIES       += libz.la
lib_LTLIBRARIES       += libGL.la

include_HEADERS        = capsule/capsule.h
nodist_include_HEADERS = utils/utils.h utils/dump.h utils/process-pt-dynamic.h

elf_dump_SOURCES       = utils/elf-dump.c
elf_dump_LDFLAGS       = -ldl

print_libstubs_SOURCES = utils/print-libstubs.c \
                         utils/utils.c          \
                         utils/ld-cache.c       \
                         utils/ld-libs.c
print_libstubs_LDFLAGS = -ldl -lelf
print_libstubs_CFLAGS  = $(AM_CFLAGS)

libcapsule_la_SOURCES  = capsule/capsule-dlmopen.c  \
                         capsule/capsule-relocate.c \
                         capsule/capsule-init.c     \
                         utils/utils.c utils/dump.c \
                         utils/process-pt-dynamic.c \
                         utils/mmap-info.c          \
                         utils/ld-cache.c           \
                         utils/ld-libs.c

libcapsule_la_LDFLAGS  = -lelf
############################################################################
# shim libraries:

# libz to match version 1.2.8 and have the same symbol versioning:
libz_la_SOURCES        = shim/libz.so.c
libz_la_LDFLAGS        = -lcapsule -version-number 1:2:8 \
                         -Wl,--version-script=shim/libz.so.map

# libGL is always 1.2.0, and doesn't use symbol versioning:
libGL_la_SOURCES       = shim/libGL.so.c
libGL_la_LDFLAGS       = -lcapsule -version-number 1:2

############################################################################
shims      = $(patsubst shim/lib%.so.c,%,$(filter shim/lib%.so.c,$(SOURCES)))
shim_srcs  = $(foreach l,$(shims),shim/lib$l.so.c)
shim_base  = $(basename $(shim_srcs))
shim_files = $(foreach y,map symbols,$(foreach x,$(shim_base),$x.$y))

GENSTUB_V1 = 
GENSTUB_V0 = @echo "  GENSTUB " $(subst $(word 1, $(basename $(filter shim/lib%,$^))),,$(filter shim/lib%,$^)) : $@;
GENSTUB    = $(GENSTUB_V$(V))

CLEANFILES    = $(shim_files) $(shim_srcs)
BUILT_SOURCES = $(shim_srcs)

include disabled.mk

# explicitly depend on the generators and .excluded and .shared metafiles
# depend on the .dlopen file IFF it exists
shim/lib%.so.c: generate-stublib.sh print-libstubs capsule-shim.h shim/lib%.so.c.*
	$(GENSTUB)$(top_srcdir)/$< $$(basename $@ .c) $@.excluded $@.shared $@ 	"$(lib$(*)_la_LDFLAGS)";

debug:
	@echo srcs : $(shim_srcs)
	@echo files: $(shim_files)

