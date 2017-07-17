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
#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "ld-cache.h"
#include "ld-libs.h"

int main (int argc, char **argv)
{
    const char *libname;
    const char *prefix = NULL;
    ld_libs_t ldlibs = {};
    int error = 0;
    int e = 0;

    if( argc < 2 )
    {
        fprintf( stderr, "usage: %s <ELF-DSO> [/path/prefix]\n", argv[0] );
        exit( 1 );
    }

    if( argc > 2 )
        prefix = argv[2];

    if( ld_libs_init( &ldlibs, NULL, prefix, 0, &error ) &&
        ld_libs_set_target( &ldlibs, argv[1] )           )
    {
        const char *path;
        const char *buf;

        if( (libname = strrchr( argv[1], '/' )) )
            libname = libname + 1;
        else
            libname = argv[1];

        path = &ldlibs.needed[0].path[0];

        while( (buf = strstr( path + 1, libname )) )
            path = buf;

        if( path )
            path = strstr( path, ".so." );

        if( path )
            path += 4;

        if( !path || !*path )
            if( (path = strstr( libname, ".so." )) )
                path += 4;

        fprintf( stdout, "%s %s %s %s\n",
                 prefix, libname,
                 (path && *path) ?  path : "1", // wild guess if we failed
                 &ldlibs.needed[0].path[0] );
    }
    else
    {
        e = (error == 0) ? errno : error;
        fprintf( stderr, "%s: failed to open [%s]%s (%d: %s)\n",
                 argv[0], argv[2], argv[1],
                 e ? e : ENOENT,
                 ldlibs.error ? ldlibs.error : "unspecified error" );
        if( !e )
            e = ENOENT;
    }

    ld_libs_finish( &ldlibs );
    exit(e);
}
