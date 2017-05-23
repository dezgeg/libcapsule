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

LT_INIT

dnl ////////////////////////////////////////////////////////////////
dnl Remove when the shim libraries move out into their own packages?
dnl zlib demo:
PKG_CHECK_MODULES([ZLIB], [zlib])
dnl libGL demo:
PKG_CHECK_MODULES([GL],   [gl])
PKG_CHECK_MODULES([XCB2], [xcb-dri2])
PKG_CHECK_MODULES([XCB3], [xcb-dri3])
dnl ////////////////////////////////////////////////////////////////

AC_SEARCH_LIBS([dlmopen], [dl])
AC_OUTPUT([Makefile])
