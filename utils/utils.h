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

enum
{
    DEBUG_NONE       = 0,
    DEBUG_PATH       = 0x1,
    DEBUG_SEARCH     = 0x1 << 1,
    DEBUG_LDCACHE    = 0x1 << 2,
    DEBUG_CAPSULE    = 0x1 << 3,
    DEBUG_MPROTECT   = 0x1 << 4,
    DEBUG_WRAPPERS   = 0x1 << 5,
    DEBUG_RELOCS     = 0x1 << 6,
    DEBUG_ALL        = 0xffff,
};

#ifdef DEBUG
#define debug(fmt, args...) \
    fprintf( stderr, "%s:" fmt "\n", __PRETTY_FUNCTION__, ##args )
#else
#define debug(fmt, args...) \

#endif

extern unsigned long debug_context;
extern unsigned long debug_flags;

char *safe_strncpy (char *dest, const char *src, size_t n);
int   resolve_link (const char *prefix, char *path, char *dir);
void  set_debug_flags (const char *control);
