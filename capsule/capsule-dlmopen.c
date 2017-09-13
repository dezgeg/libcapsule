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
#include <unistd.h>
#include <limits.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <string.h>
#include <fcntl.h>

#include <libelf.h>
#include <gelf.h>
#include <dlfcn.h>

#include "capsule.h"
#include "utils/utils.h"
#include "utils/dump.h"
#include "utils/mmap-info.h"
#include "utils/process-pt-dynamic.h"
#include "utils/ld-cache.h"
#include "utils/ld-libs.h"

// map the ld.so.cache for the system into memory so that we can search it
// for DSOs in the same way as the dynamic linker.
//
// returns true on success, false otherwise.
//
// this function respects any path prefix specified in ldlibs
static int
load_ld_cache (ld_libs_t *libs, const char *path)
{
    int rv;

    if( libs->prefix.len == 0 )
    {
        libs->ldcache.fd = open( path, O_RDONLY );
    }
    else
    {
        safe_strncpy( libs->prefix.path + libs->prefix.len,
                      path, PATH_MAX - libs->prefix.len );
        libs->ldcache.fd = open( libs->prefix.path, O_RDONLY );
    }

    rv = ld_cache_open( &libs->ldcache, libs->prefix.path );

    return rv;
}

// ==========================================================================
// some pretty printers for debugging:

// dump out the contents of the ld cache to stderr:
static void
dump_ld_cache (ld_libs_t *ldlibs)
{
    ld_cache_foreach( &ldlibs->ldcache, ld_entry_dump, stderr );
}

static void
wrap (const char *name,
      ElfW(Addr) base,
      ElfW(Dyn) *dyn,
      capsule_item *wrappers)
{
    int mmap_errno = 0;
    char *mmap_error = NULL;
    ElfW(Addr) start = (ElfW(Addr)) dyn - base;
    // we don't know the size so we'll have to rely on the linker putting
    // well formed entries into the mmap()ed DSO region.
    // (tbf if the linker is putting duff entries here we're boned anyway)
    //
    // dyn is the address of the dynamic section
    // base is the start of the program header in memory
    // start should be the offset from the program header to its dyn section
    //
    // the utility functions expect an upper bound though so set that to
    // something suitably large:
    relocation_data_t rdata = { 0 };

    rdata.target    = name;
    rdata.debug     = debug_flags;
    rdata.error     = NULL;
    rdata.relocs    = wrappers;

    // if RELRO linking has happened we'll need to tweak the mprotect flags
    // before monkeypatching the symbol tables, for which we will need the
    // sizes, locations and current protections of any mmap()ed regions:
    rdata.mmap_info = load_mmap_info( &mmap_errno, &mmap_error );

    if( mmap_errno || mmap_error )
    {
        DEBUG( DEBUG_MPROTECT,
               "mmap/mprotect flags information load error (errno: %d): %s",
               mmap_errno, mmap_error );
        DEBUG( DEBUG_MPROTECT,
               "relocation will be unable to handle RELRO linked libraries" );
    }

    // make all the mmap()s writable:
    for( int i = 0; rdata.mmap_info[i].start != MAP_FAILED; i++ )
        if( mmap_entry_should_be_writable( &rdata.mmap_info[i] ) )
            add_mmap_protection( &rdata.mmap_info[i], PROT_WRITE );

    // if we're debugging wrapper installation in detail we
    // will end up in a path that's normally only DEBUG_ELF
    // debugged:
    if( debug_flags & DEBUG_WRAPPERS )
        debug_flags = debug_flags | DEBUG_ELF;

    // install any required wrappers inside the capsule:
    process_pt_dynamic( (void *)start, // offset from phdr to dyn section
                        0,      //  fake size value
                        base,   //  address of phdr in memory
                        process_dt_rela,
                        process_dt_rel,
                        &rdata );

    // put the debug flags back in case we changed them
    debug_flags = rdata.debug;

    // put the mmap()/mprotect() permissions back the way they were:
    for( int i = 0; rdata.mmap_info[i].start != MAP_FAILED; i++ )
        if( mmap_entry_should_be_writable( &rdata.mmap_info[i] ) )
            reset_mmap_protection( &rdata.mmap_info[i] );

    free_mmap_info( rdata.mmap_info );
    rdata.mmap_info = NULL;
}

static inline int
excluded_from_wrap (const char *name, char **exclude)
{
    const char *dso = strrchr(name, '/');

    // we can't ever subvert the runtime linker itself:
    if( strncmp( "/ld-", dso, 4 ) == 0 )
        return 1;

    for( char **x = exclude; x && *x; x++ )
        if( strcmp ( *x, dso + 1 ) == 0 )
            return 1;

    return 0;
}

// replace calls out to dlopen in the encapsulated DSO with a wrapper
// which should take care of preserving the /path-prefix and namespace
// wrapping of the original capsule_dlmopen() call.
//
// strictly speaking we can wrap things other than dlopen(),
// but that's currently all we use this for:
static int install_wrappers ( void *dl_handle,
                              capsule_item *wrappers,
                              const char **exclude,
                              int *errcode,
                              char **error)
{
    int replacements = 0;
    struct link_map *map;

    if( dlinfo( dl_handle, RTLD_DI_LINKMAP, &map ) != 0 )
    {
        if( error )
            *error = dlerror();

        if( errcode )
            *errcode = EINVAL;

        DEBUG( DEBUG_WRAPPERS, "mangling capsule symbols: %s", *error );

        return -1;
    }

    DEBUG( DEBUG_WRAPPERS, "link_map: %p <- %p -> %p",
               map ? map->l_next : NULL ,
               map ? map         : NULL ,
               map ? map->l_prev : NULL );

    // no guarantee that we're at either end of the link map:
    while( map->l_prev )
        map = map->l_prev;

    if (map->l_next)
        for( struct link_map *m = map; m; m = m->l_next )
            if( !excluded_from_wrap(m->l_name, (char **)exclude) )
                wrap( m->l_name, m->l_addr, m->l_ld, wrappers );

    return replacements;
}

// dump the link map info for the given dl handle (NULL = default)
static void
dump_link_map( void *dl_handle )
{
    struct link_map *map;
    void *handle;

    if( !dl_handle )
        handle = dlopen( NULL, RTLD_LAZY|RTLD_NOLOAD );
    else
        handle = dl_handle;

    if( dlinfo( handle, RTLD_DI_LINKMAP, &map ) != 0 )
    {
        DEBUG( DEBUG_CAPSULE, "failed to access link_map for handle %p-%p: %s",
               dl_handle, handle, dlerror() );
        return;
    }

    // be kind, rewind the link map:
    while( map->l_prev )
        map = map->l_prev;

    fprintf( stderr, "(dl-handle %s", dl_handle ? "CAPSULE" : "DEFAULT" );
    for( struct link_map *m = map; m; m = m->l_next )
        fprintf( stderr, "\n  [%p] %s [%p]\n",
                 m->l_prev, m->l_name, m->l_next );
    fprintf( stderr, ")\n" );
}

// ==========================================================================
void *
capsule_dlmopen (const char *dso,
                 const char *prefix,
                 Lmid_t *namespace,
                 capsule_item *wrappers,
                 unsigned long dbg,
                 const char **exclude,
                 int *errcode,
                 char **error)
{
    void *ret = NULL;
    ld_libs_t ldlibs = {};

    if( dbg == 0 )
        dbg = debug_flags;

    ld_libs_init( &ldlibs, exclude, prefix, dbg, errcode );

    if( errcode && *errcode )
        return NULL;

    // ==================================================================
    // read in the ldo.so.cache - this will contain all architectures
    // currently installed (x86_64, i386, x32) in no particular order
    if( load_ld_cache( &ldlibs, "/etc/ld.so.cache" ) )
    {
        if( debug_flags & DEBUG_LDCACHE )
            dump_ld_cache( &ldlibs );
    }
    else
    {
        int rv = (errno == 0) ? EINVAL : errno;

        if( error )
            *error = strdup( "capsule_dlmopen: failed to read ld.so.cache" );

        if( errcode )
            *errcode = rv;

        return NULL;
    }

    // ==================================================================
    // find the starting point of our capsule
    if( !ld_libs_set_target( &ldlibs, dso ) )
    {
        if( error )
        {
            *error = ldlibs.error;
            ldlibs.error = NULL;
        }
        else
        {
            free( ldlibs.error );
        }

        if( errcode )
            *errcode = ENOENT;

        goto cleanup;
    }

    // ==================================================================
    // once we have the starting point recursively find all its DT_NEEDED
    // entries, except for the linker itself and libc, which must not
    // be different between the capsule and the "real" DSO environment:
    ld_libs_find_dependencies( &ldlibs );

    if( ldlibs.error )
    {
        if( error )
        {
            *error = ldlibs.error;
            ldlibs.error = NULL;
        }

        if( errcode )
            *errcode = EINVAL;

        goto cleanup;
    }

    // ==================================================================
    // load the stack of DSOs we need:
    ret = ld_libs_load( &ldlibs, namespace, 0, errcode );

    if( debug_flags & DEBUG_CAPSULE )
    {
        dump_link_map( ret  );
        dump_link_map( NULL );
    }

    if( !ret )
        goto cleanup;

    // TODO: failure in the dlopen fixup phase should probably be fatal:
    if( ret      != NULL && // no errors so far
        wrappers != NULL )  // have a dlopen fixup function
        install_wrappers( ret, wrappers, exclude, errcode, error );

cleanup:
    ld_libs_finish( &ldlibs );
    return ret;
}

void *
capsule_shim_dlopen(Lmid_t ns,
                    const char *prefix,
                    const char **exclude,
                    const char *file,
                    int flag)
{
    void *res = NULL;
    int code = 0;
    char *errors = NULL;
    ld_libs_t ldlibs = {};

    DEBUG( DEBUG_WRAPPERS,
           "dlopen(%s, %x) wrapper: LMID: %ld; prefix: %s;",
           file, flag, ns, prefix );

    if( prefix && strcmp(prefix, "/") )
    {
        ld_libs_init( &ldlibs, exclude, prefix, debug_flags, &code );

        if( !load_ld_cache( &ldlibs, "/etc/ld.so.cache" ) )
        {
            int rv = (errno == 0) ? EINVAL : errno;

            DEBUG( DEBUG_LDCACHE|DEBUG_WRAPPERS,
                   "Loading ld.so.cache from %s (error: %d)", prefix, rv );
            goto cleanup;
        }

        // find the initial DSO (ie what the caller actually asked for):
        if( !ld_libs_set_target( &ldlibs, file ) )
        {
            int rv = (errno == 0) ? EINVAL : errno;

            DEBUG( DEBUG_SEARCH|DEBUG_WRAPPERS,
                           "Not found: %s under %s (error: %d)",
                           file, prefix, rv );
            goto cleanup;
        }

        // harvest all the requested DSO's dependencies:
        ld_libs_find_dependencies( &ldlibs );

        if( ldlibs.error )
        {
            DEBUG( DEBUG_WRAPPERS, "capsule dlopen error: %s", ldlibs.error );
            goto cleanup;
        }

        // load them up in reverse dependency order:
        res = ld_libs_load( &ldlibs, &ns, flag, &code );

        if( !res )
            DEBUG( DEBUG_WRAPPERS,
                   "capsule dlopen error %d: %s", code, errors );

        goto cleanup;
    }
    else // no prefix: straightforward dlmopen into our capsule namespace:
    {
        res = dlmopen( ns, file, flag );

        if( !res )
            DEBUG( DEBUG_WRAPPERS,
                   "capsule dlopen error %s: %s", file, dlerror() );
    }

    return res;

cleanup:
    ld_libs_finish( &ldlibs );
    return res;
}

static int
dso_is_exported (const char *dsopath, const char **exported)
{
    for( const char **ex = exported; ex && *ex; ex++ )
        if( soname_matches_path( *ex, dsopath ) )
            return 1;

    return 0;
}

void *
capsule_shim_dlsym (void *capsule,
                    void *handle,
                    const char *symbol,
                    const char **exported)
{
    void *addr = NULL;

    if( (addr = dlsym( capsule, symbol )) )
    {
        Dl_info dso = { 0 };

        // only keep addr from the capsule if it's from an exported DSO:
        // or if we are unable to determine where it came from (what?)
        if( dladdr( addr, &dso ) )
            if( !dso_is_exported( dso.dli_fname, exported ) )
                addr = NULL;
    }

    if( addr == NULL )
        addr = dlsym( handle, symbol );

    return addr;
}
