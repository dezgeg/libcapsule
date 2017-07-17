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

AUTOMAKE_OPTIONS        = subdir-objects
ACLOCAL_AMFLAGS         = -I m4
AM_CFLAGS               = --std=c99 -D_GNU_SOURCE -Wall -Werror

# installable items:
libexec_PROGRAMS        = capsule-symbols capsule-version
libexec_SCRIPTS         = data/capsule-mkstublib data/capsule-init-project
lib_LTLIBRARIES         = libcapsule.la
pkgconfigdir            = $(libdir)/pkgconfig
pkgconfig_DATA          = data/capsule.pc
include_HEADERS         = capsule/capsule.h

# demo program - keep this hanging around as it's a useful PoC
noinst_PROGRAMS         = elf-dump

elf_dump_SOURCES        = utils/elf-dump.c
elf_dump_LDFLAGS        = -ldl
elf_dump_SOURCES       += utils/utils.h

# now the rules for building our installables:
capsule_symbols_SOURCES = utils/print-libstubs.c \
                          utils/utils.c          \
                          utils/ld-cache.c       \
                          utils/ld-libs.c
capsule_symbols_SOURCES += \
                          utils/utils.h          \
                          utils/ld-cache.h       \
                          utils/ld-libs.h
capsule_symbols_LDFLAGS = -ldl -lelf
# this looks like a no-op but it gives capsule_symbols its own target
# so that libtool doesn't get bent out of shape about using an object
# (ld-cache.o, ld-libs.o) as both part of a library and a standalone
# executable:
capsule_symbols_CFLAGS  = $(AM_CFLAGS)

capsule_version_SOURCES = utils/print-version.c  \
                          utils/utils.c          \
                          utils/ld-cache.c       \
                          utils/ld-libs.c
capsule_version_SOURCES += \
                          utils/utils.h          \
                          utils/ld-cache.h       \
                          utils/ld-libs.h
capsule_version_LDFLAGS = -ldl -lelf
capsule_version_CFLAGS  = $(AM_CFLAGS)


libcapsule_la_SOURCES   = capsule/capsule-dlmopen.c  \
                          capsule/capsule-relocate.c \
                          capsule/capsule-init.c     \
                          utils/utils.c              \
                          utils/dump.c               \
                          utils/process-pt-dynamic.c \
                          utils/mmap-info.c          \
                          utils/ld-cache.c           \
                          utils/ld-libs.c
libcapsule_la_LDFLAGS   = -lelf -version-number 0:1  \
libcapsule_la_SOURCES  += utils/utils.h              \
                          utils/dump.h               \
                          utils/process-pt-dynamic.h \
                          utils/mmap-info.h          \
                          utils/ld-cache.h           \
                          utils/ld-libs.h

dist_pkgdata_DATA       = data/capsule-shim.h     \
                          data/capsule-shim.mk.in \
                          disabled.mk

CLEANFILES    = $(shim_files) $(shim_srcs)
BUILT_SOURCES = $(shim_srcs)

include disabled.mk
