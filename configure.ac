dnl Copyright © 2017 Collabora Ltd

dnl This file is part of libcapsule.

dnl libcapsule is free software: you can redistribute it and/or modify
dnl it under the terms of the GNU Lesser General Public License as
dnl published by the Free Software Foundation, either version 3 of the
dnl License, or (at your option) any later version.

dnl libcapsule is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU Lesser General Public License for more details.

dnl You should have received a copy of the GNU Lesser General Public
dnl License along with libcapsule.  If not, see <http://www.gnu.org/licenses/>.

AC_INIT(libcapsule, 0.1)
AC_CONFIG_MACRO_DIR([m4])

dnl don't kvetch about gnu makefile syntax
dnl and don't require ChangeLog &co if they don't exist
AM_INIT_AUTOMAKE([-Wno-portability foreign])
AM_SILENT_RULES([yes])

LT_INIT

dnl make sure we've got the _right_ libelf (doesn't ship a .pc)
AC_CHECK_TYPE([Elf_Cmd], [], [], [#include <libelf.h>])
AC_MSG_CHECKING([Elf_Cmd ELF_C_READ_MMAP])
AC_RUN_IFELSE([AC_LANG_PROGRAM([#include <libelf.h>],
                               [Elf_Cmd x = ELF_C_READ_MMAP;])],
              [AC_MSG_RESULT([yes])],
              [AC_MSG_RESULT([no])]
              [AC_MSG_ERROR([ELF_C_READ_MMAP missing: libelfg vs libelf0?])])

AC_SEARCH_LIBS([dlmopen], [dl])
AC_PATH_PROG([XSLTPROC], [xsltproc])

AC_OUTPUT([Makefile data/capsule.pc data/dirconf.txt])
