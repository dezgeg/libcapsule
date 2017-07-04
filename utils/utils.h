// Copyright © 2017 Collabora Ltd

// This file is part of libcapsule.

// libcapsule is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.

// libcapsule is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.

// You should have received a copy of the GNU Lesser General Public
// License along with libcapsule.  If not, see <http://www.gnu.org/licenses/>.

#pragma once

#include <link.h> // for __ELF_NATIVE_CLASS
#include "debug.h"

#if __ELF_NATIVE_CLASS == 64
#define FMT_OFF   "lu"
#define FMT_SWORD "lu"
#define FMT_WORD  "ld"
#define FMT_SIZE  "lu"
#define FMT_ADDR  "ld"
#define FMT_XADDR "lx"
#define FMT_XU64  "lx"
#else
#define FMT_OFF   "u"
#define FMT_SWORD "u"
#define FMT_WORD  "d"
#define FMT_SIZE  "u"
#define FMT_ADDR  "d"
#define FMT_XADDR "x"
#define FMT_XU64  "llx"
#endif

char *safe_strncpy (char *dest, const char *src, size_t n);
int   resolve_link (const char *prefix, char *path, char *dir);
