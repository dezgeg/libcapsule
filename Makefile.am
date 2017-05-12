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
AUTOMAKE_OPTIONS 	   = subdir-objects
ACLOCAL_AMFLAGS        = -I m4
AM_CFLAGS 			   = --std=c99 -D_GNU_SOURCE -Og -ggdb -Wall 

bin_PROGRAMS 		   = elf-dump print-libstubs
lib_LTLIBRARIES 	   = libcapsule.la libz.la libGL.la
include_HEADERS        = capsule/capsule.h
nodist_include_HEADERS = utils/utils.h utils/dump.h utils/process-pt-dynamic.h

elf_dump_SOURCES       = utils/elf-dump.c
elf_dump_LDFLAGS       = -ldl

print_libstubs_SOURCES = utils/print-libstubs.c
print_libstubs_LDFLAGS = -ldl

libcapsule_la_SOURCES  = capsule/capsule-dlmopen.c  \
                         capsule/capsule-relocate.c \
                         utils/utils.c utils/dump.c \
                         utils/process-pt-dynamic.c \
                         utils/mmap-info.c

libcapsule_la_LDFLAGS  = -lelf

libz_la_SOURCES        = shim/libz.so.c
libz_la_LDFLAGS        = -lcapsule -version-info 1:1:0 \
                         -Wl,--version-script=shim/libz.so.c.map

libGL_la_SOURCES       = shim/libGL.so.c
libGL_la_LDFLAGS       = -lcapsule -version-info 1:1:0

shims      = z GL
shim_srcs  = $(foreach l,$(shims),shim/lib$l.so.c)
shim_files = $(foreach y,map symbols,$(foreach x,$(shim_srcs),$x.$y))

GENSTUB_V1 = 
GENSTUB_V0 = @echo "  GENSTUB " $@.excluded $@.shared $@;
GENSTUB    = $(GENSTUB_V$(V))

CLEANFILES 			   = $(shim_files) $(shim_srcs)
BUILT_SOURCES 		   = $(shim_srcs)

shim/lib%.so.c: generate-stublib.sh print-libstubs capsule-shim.h shim/lib%.so.c.excluded shim/lib%.so.c.shared
	$(GENSTUB)$(top_srcdir)/$< $$(basename $@ .c) $@.excluded $@.shared $@

debug:
	@echo srcs : $(shim_srcs)
	@echo files: $(shim_files)

