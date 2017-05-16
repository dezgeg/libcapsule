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

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <link.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "mmap-info.h"

typedef enum
{
    MAPS_START  ,
    MAPS_END    ,
    MAPS_DATA   ,
    MAPS_PROT_R ,
    MAPS_PROT_W ,
    MAPS_PROT_X ,
    MAPS_PROT_P ,
    MAPS_SKIP   ,
    MAPS_PATH   ,
} map_parse_state;

#define PROC_FILE "/proc/self/maps"
#define ERROR(s) \
    ({ if(err   ) *err    = errno; \
       if(errstr) *errstr = s;    \
       return NULL; })

void
free_mmap_info(mmapinfo_t *ptr)
{
    if( ptr )
        free( ptr );
}

mmapinfo_t *
find_mmap_info(mmapinfo_t *maps, void *addr)
{
    if( !maps )
        return NULL;

    for( int i = 0; maps[i].start != MAP_FAILED; i++ )
    {
        if( (ElfW(Addr)) maps[i].start > (ElfW(Addr)) addr )
            continue;

        if( (ElfW(Addr)) maps[i].end < (ElfW(Addr)) addr )
            continue;

        return &maps[i];
    }

    return NULL;
}

int
add_mmap_protection(mmapinfo_t *mmap_info, unsigned int flags)
{
    ElfW(Addr)   start = (ElfW(Addr)) mmap_info->start;
    ElfW(Addr)   end   = (ElfW(Addr)) mmap_info->end;
    size_t       size  = end - start;
    unsigned int prot  = mmap_info->protect | flags;

    return mprotect( (void *)start, size, prot );
}

int
reset_mmap_protection(mmapinfo_t *mmap_info)
{
    ElfW(Addr)    start = (ElfW(Addr)) mmap_info->start;
    ElfW(Addr)    end   = (ElfW(Addr)) mmap_info->end;
    size_t        size  = end - start;

    return mprotect( (void *)start, size, mmap_info->protect );
}

mmapinfo_t *
load_mmap_info (int *err, char **errstr)
{
    FILE *maps = fopen( PROC_FILE, "r" );
    char map_line[80 + PATH_MAX];
    int map_entries = 0;
    mmapinfo_t *entries = NULL;

    if( maps <= 0 )
        ERROR("Warning: could not open " PROC_FILE);

    while( fgets(&map_line[0], sizeof(map_line), maps) )
        map_entries++;

    if( fseek(maps, 0, SEEK_SET) < 0 )
        ERROR("Warning: Unable to seek to start of " PROC_FILE);

    if( map_entries > 0 )
        entries = calloc( map_entries + 1, sizeof(mmapinfo_t) );
    else
        ERROR("Warning: no mmap entries found in " PROC_FILE);

    int l = 0;

    while( fgets(&map_line[0], sizeof(map_line), maps) )
    {
        int offs;
        char *s = NULL;
        int skip = 0;
        map_parse_state p = MAPS_START;
        map_parse_state item = MAPS_START;
        int last_blank = 0;
        char *path = NULL;

        for( offs = 0; offs < sizeof(map_line) && l < map_entries; offs++ )
        {
            char *c = map_line + offs;

            // we've hit the end of the line: prematurely or not, clean up:
            if( *c == '\n' )
            {
                *c = '\0';
                if( path )
                    strncpy( &entries[l].path[0], path, PATH_MAX );
                entries[l].path[PATH_MAX - 1] = '\0';
                l++;
                break;
            }

            switch (p)
            {
              case MAPS_START:
              case MAPS_END:
                if( isxdigit(*c) )
                {
                    s = c;
                    item = p;
                    p = MAPS_DATA;
                }
                break;

              case MAPS_DATA:
                if( !isxdigit(*c) )
                {
                    char **addr = ( item == MAPS_START ?
                                    &entries[l].start  :
                                    &entries[l].end    );
                    *c = '\0';
                    *addr = (char *)strtoul( s, NULL, 16 );
                    p = item == MAPS_START ? MAPS_END : MAPS_PROT_R;
                }
                break;

              case MAPS_PROT_R:
                if( *c != 'r' && *c != '-' )
                    continue;

                entries[l].protect  = PROT_NONE;

                entries[l].protect |= (*c == 'r' ? PROT_READ : PROT_NONE);
                p = MAPS_PROT_W;
                break;

              case MAPS_PROT_W:
                entries[l].protect |= (*c == 'w' ? PROT_WRITE : PROT_NONE);
                p = MAPS_PROT_X;
                break;

              case MAPS_PROT_X:
                entries[l].protect |= (*c == 'x' ? PROT_EXEC : PROT_NONE);
                p = MAPS_PROT_P;
                break;

              case MAPS_PROT_P:
                last_blank = isblank(*c);
                skip = 7;
                p = MAPS_SKIP;
                break;

              case MAPS_SKIP:
                if( isblank(*c) )
                {
                    if( last_blank == 0 )
                        skip--;
                }
                else if( !isblank(*c) )
                {
                    if( last_blank == 1 )
                        skip--;
                }

                last_blank = isblank(*c);

                if( skip <= 0 )
                    p = MAPS_PATH;
                break;

              case MAPS_PATH:
                if( !path && !isblank(*c) )
                    path = c;
                break;
            }
        }
    }

    entries[map_entries].start   = MAP_FAILED;
    entries[map_entries].end     = MAP_FAILED;
    entries[map_entries].protect = PROT_NONE;
    entries[map_entries].path[0] = '\0';

    fclose( maps );

    return entries;
}

int
mmap_entry_should_be_writable (mmapinfo_t *mmap_info)
{
    // already has write permissions, don't care:
    if( mmap_info->protect & PROT_WRITE )
        return 0;

    // or not a 'real' DSO, leave the hell alone:
    if( strchr( mmap_info->path, '[' ) )
        return 0;

    return 1;
}

