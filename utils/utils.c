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

#include <sys/param.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include "debug.h"

unsigned long debug_flags;

// like strncpy except it guarantees the final byte is NUL in
// case we truncated the string. does not yet warn you in any
// way about truncation though, should probably fix that:
char *safe_strncpy (char *dest, const char *src, size_t n)
{
    char *rv = strncpy( dest, src, n );
    dest[ n - 1 ] = '\0';
    return rv;
}

// prefix is the root of the external tree we're patching in
// with libcapsule, path is what we're trying to resolve if
// it is a symlink. dir is a scratch space we're going to use.
// all three must have at least PATH_MAX chars allocated.
//
// Designed to be called repeatedly, starting with an ABSOLUTE
// path the first time. Will write the resolved link back into
// path each time and return true, until fed a path which is
// not a symlink, at which point it will leave path alone and
// return false:
int resolve_link(const char *prefix, char *path, char *dir)
{
    int dfd;
    char rl[PATH_MAX];
    char *end = NULL;
    int rv = 0;

    safe_strncpy( dir, path, PATH_MAX );
    end = strrchr( dir, '/' );

    if( end )
        *end = '\0';
    else
        strcpy( dir, "." ); // not sure this is right, FIXME?
                            // but as long as the first call to us
                            // in any sequence was an absolute path
                            // this will never come up
    dfd = open( dir, O_RDONLY );

    if( dfd < 0 )
        return 0;

    rv = readlinkat( dfd, path, rl, sizeof(rl) );

    if( rv >= 0 )
    {
        rl[ rv ] = '\0';

        if( rl[0] == '/' )
        {
            const int pl = strlen( prefix );

            safe_strncpy( path, prefix, PATH_MAX );
            safe_strncpy( path + pl, rl, PATH_MAX - pl );
        }
        else
        {
            const int pl = strlen( dir );

            safe_strncpy( path, dir, PATH_MAX );
            path[ pl ] = '/';
            safe_strncpy( path + pl + 1, rl, PATH_MAX - pl - 1 );
        }
    }

    close( dfd );

    return rv != -1;
}

// todo - check this properly for actual word boundaries and
// make it warn about unknown debug keywords:
void set_debug_flags (const char *control)
{
    debug_flags = DEBUG_NONE;

    if ( !control )
        return;

    if( strstr( control, "path"     ) ) debug_flags |= DEBUG_PATH;
    if( strstr( control, "search"   ) ) debug_flags |= DEBUG_SEARCH;
    if( strstr( control, "ldcache"  ) ) debug_flags |= DEBUG_LDCACHE;
    if( strstr( control, "capsule"  ) ) debug_flags |= DEBUG_CAPSULE;
    if( strstr( control, "mprotect" ) ) debug_flags |= DEBUG_MPROTECT;
    if( strstr( control, "wrappers" ) ) debug_flags |= DEBUG_WRAPPERS;
    if( strstr( control, "reloc"    ) ) debug_flags |= DEBUG_RELOCS;
    if( strstr( control, "elf"      ) ) debug_flags |= DEBUG_ELF;
    if( strstr( control, "all"      ) ) debug_flags |= DEBUG_ALL;

    fprintf(stderr, "capsule debug flags: \n"
            "  path    : %c # path manipulation and translation"           "\n"
            "  search  : %c # searching for DSOs"                          "\n"
            "  ldcache : %c # loading/processing the ld cache"             "\n"
            "  capsule : %c # setting up the proxy capsule"                "\n"
            "  mprotect: %c # handling mprotect (for RELRO)"               "\n"
            "  wrappers: %c # function wrappers installed in the capsule"  "\n"
            "  reloc   : %c # patching capsule symbols into external DSOs" "\n"
            "  elf     : %c # detailed ELF introspection logging"          "\n",
            (debug_flags & DEBUG_PATH    ) ? 'Y' : 'n' ,
            (debug_flags & DEBUG_SEARCH  ) ? 'Y' : 'n' ,
            (debug_flags & DEBUG_LDCACHE ) ? 'Y' : 'n' ,
            (debug_flags & DEBUG_CAPSULE ) ? 'Y' : 'n' ,
            (debug_flags & DEBUG_MPROTECT) ? 'Y' : 'n' ,
            (debug_flags & DEBUG_WRAPPERS) ? 'Y' : 'n' ,
            (debug_flags & DEBUG_RELOCS  ) ? 'Y' : 'n' ,
            (debug_flags & DEBUG_ELF     ) ? 'Y' : 'n' );
}
