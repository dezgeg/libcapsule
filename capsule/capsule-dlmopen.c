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

// ==========================================================================
// this is stolen from the ld.so config (dl-cache.h) since we need
// to use a slightly re-brained version of the linker to do our
// filthy, filthy business (and these details are not in a shipped header)

#define FLAG_ANY                -1
#define FLAG_TYPE_MASK          0x00ff
#define FLAG_LIBC4              0x0000
#define FLAG_ELF                0x0001
#define FLAG_ELF_LIBC5          0x0002
#define FLAG_ELF_LIBC6          0x0003
#define FLAG_REQUIRED_MASK      0xff00
#define FLAG_SPARC_LIB64        0x0100
#define FLAG_IA64_LIB64         0x0200
#define FLAG_X8664_LIB64        0x0300
#define FLAG_S390_LIB64         0x0400
#define FLAG_POWERPC_LIB64      0x0500
#define FLAG_MIPS64_LIBN32      0x0600
#define FLAG_MIPS64_LIBN64      0x0700
#define FLAG_X8664_LIBX32       0x0800
#define FLAG_ARM_LIBHF          0x0900
#define FLAG_AARCH64_LIB64      0x0a00
#define FLAG_ARM_LIBSF          0x0b00
#define FLAG_MIPS_LIB32_NAN2008     0x0c00
#define FLAG_MIPS64_LIBN32_NAN2008  0x0d00
#define FLAG_MIPS64_LIBN64_NAN2008  0x0e00

static const char *flag_descr[] = { "libc4", "ELF", "libc5", "libc6"};

static const char *const abi_tag_os[] =
{
    [0] = "Linux",
    [1] = "Hurd",
    [2] = "Solaris",
    [3] = "FreeBSD",
    [4] = "kNetBSD",
    [5] = "Syllable",
    [6] = "Unknown OS"
};
#define MAXTAG (sizeof abi_tag_os / sizeof abi_tag_os[0] - 1)

#define CACHEMAGIC "ld.so-1.7.0"

#define CACHEMAGIC_NEW "glibc-ld.so.cache"
#define CACHE_VERSION "1.1"
#define CACHEMAGIC_VERSION_NEW CACHEMAGIC_NEW CACHE_VERSION

struct file_entry_new
{
    int32_t flags;        /* This is 1 for an ELF library.  */
    uint32_t key, value;  /* String table indices.  */
    uint32_t osversion;   /* Required OS version.  */
    uint64_t hwcap;       /* Hwcap entry.  */
};

struct cache_file_new
{
    char magic[sizeof CACHEMAGIC_NEW - 1];
    char version[sizeof CACHE_VERSION - 1];
    uint32_t nlibs;                /* Number of entries.  */
    uint32_t len_strings;          /* Size of string table. */
    uint32_t unused[5];            /* Leave space for future extensions
                                      and align to 8 byte boundary.  */
    struct file_entry_new libs[0]; /* Entries describing libraries.  */
    /* After this the string table of size len_strings is found.  */
};

struct file_entry
{
    int flags;               /* This is 1 for an ELF library.  */
    unsigned int key, value; /* String table indices.  */
};

struct cache_file
{
    char magic[sizeof CACHEMAGIC - 1];
    unsigned int nlibs;
    struct file_entry libs[0];
};

/* Used to align cache_file_new.  */
#define ALIGN_CACHE(addr)                               \
    (((addr) + __alignof__ (struct cache_file_new) -1)	\
     & (~(__alignof__ (struct cache_file_new) - 1)))

// end of stolen header structures

// ==========================================================================
// And now some definitions related to us handling the ld.so.cache ourselves:

// we only handle up to this many library dependencies -
// yes, hardwired limits are bad but there's already enough complexity
// here - can revisit this decision if it ever becomes close to being
// an issue (shouldn't affect the api or abi):
#define DSO_LIMIT 256

struct dso_cache_search
{
    int idx;
    const char *name;
};

typedef enum
{
    CACHE_NONE,
    CACHE_NEW ,
    CACHE_OLD ,
} cache_type;

typedef struct
{
    int   fd;
    char *name;
    char  path[PATH_MAX];
    int   requestors[DSO_LIMIT];
    int   depcount;
    Elf  *dso;
} dso_needed_t;

typedef struct
{
    int    cache_fd;
    size_t cache_map_size;
    struct cache_file *cache_mmap;
    const char *cache_data;
    union { struct cache_file *old; struct cache_file_new *new; } cache;
    cache_type ctype;
    int last_idx;
    int elf_class;
    Elf64_Half elf_machine;
    struct { char path[PATH_MAX]; size_t len; } prefix;
    const char **exclude;
    dso_needed_t needed[DSO_LIMIT];
    char *not_found[DSO_LIMIT];
    char *error;
    int last_not_found;
    unsigned long debug;
} ldlibs_t;

typedef int (*ldcache_entry_cb) (ldlibs_t *ldlibs,
                                 const char *name,
                                 int flag,
                                 unsigned int osv,
                                 uint64_t hwcap,
                                 const char *path,
                                 void *data);

// ==========================================================================
static void clear_needed (dso_needed_t *needed)
{
    elf_end( needed->dso );
    needed->dso = NULL;

    if( needed->fd >= 0 )
        close( needed->fd );
    needed->fd = -1;

    free( needed->name );
    needed->name = NULL;

    needed->depcount = 0;

    memset( needed->path, 0, PATH_MAX );
    memset( needed->requestors, 0, sizeof(int) * DSO_LIMIT );
}

// set the ldlibs elf class and machine based on the link map entry
// passed to us if possible: if we found values for these, return 1,
// otherwise return 0:
static int
find_elf_constraints(ldlibs_t *ldlibs, struct link_map *m)
{
    int fd = -1;
    Elf *dso = NULL;
    GElf_Ehdr ehdr = { };

    // absolute path or it's a "fake" link map entry which we can't use
    // as there's no actual file to open and inspect:
    if( !m || !m->l_name || (m->l_name[0] != '/'))
        return 0;

    // if we can't open the DSO pointed to by the link map, bail:
    fd = open( m->l_name, O_RDONLY );

    if( fd < 0 )
        return 0;

    dso = elf_begin( fd, ELF_C_READ_MMAP, NULL );

    if( dso && gelf_getehdr( dso, &ehdr ) )
    {
        ldlibs->elf_class   = gelf_getclass( dso );
        ldlibs->elf_machine = ehdr.e_machine;
        DEBUG( DEBUG_SEARCH|DEBUG_CAPSULE,
               "elf class: %d; elf machine: %d; set from: %s",
               ldlibs->elf_class, ldlibs->elf_machine, m->l_name );
    }

    if( dso != NULL )
        elf_end( dso );

    if( fd >= 0 )
        close( fd );

    return ( ldlibs->elf_class != ELFCLASSNONE );
}


// record the class & machine of the start of the link chain
// so that we can only consider matching libraries later
// this matters on multi-arch systems so we don't pick an
// i386 or x32 DSO to statisfy a DT_NEEDED from an x86-64 one.
// return true if we found a valid DSO, false (can't happen?) otherwise
static int
set_elf_constraints (ldlibs_t *ldlibs)
{
    void *handle;
    struct link_map *map;
    struct link_map *m;

    if( (handle = dlopen( NULL, RTLD_LAZY|RTLD_NOLOAD )) &&
        (dlinfo( handle, RTLD_DI_LINKMAP, &map ) == 0)   )
    {
        // we're not guaranteed to be at the start of the link map chain:
        while( map->l_prev )
            map = map->l_prev;

        // check link maps until we find one we can fill in
        // our constraints from:
        for( m = map; m; m = m->l_next )
            if( find_elf_constraints(ldlibs, m) )
                break;
    }
    else
    {
        // this would be frankly beyond bizarre:
        fprintf(stderr, "dlopen/dlinfo on self failed: %s\n", dlerror() );
    }

    return ( ( ldlibs->elf_class   != ELFCLASSNONE ) &&
             ( ldlibs->elf_machine |= EM_NONE      ) );
}

// check that the currently opened DSO at offset idx in the needed array
// matches the class & architecture of the DSO we started with:
// return true on a match, false otherwise
static int
check_elf_constraints (ldlibs_t *ldlibs, int idx)
{
    GElf_Ehdr ehdr = {};
    int eclass;

    // bogus ELF DSO - no ehdr available?
    if( !gelf_getehdr( ldlibs->needed[ idx ].dso, &ehdr ) )
        return 0;

    eclass = gelf_getclass( ldlibs->needed[ idx ].dso );

    // check class (32 vs 64 bit)
    if( ldlibs->elf_class != eclass )
        return 0;

    // check target architecture (i386, x86-64)
    // x32 ABI is class 32 but machine x86-64
    if( ldlibs->elf_machine != ehdr.e_machine )
        return 0;

    DEBUG( DEBUG_ELF, "constraints: class %d; machine: %d;",
           ldlibs->elf_class, ldlibs->elf_machine );
    DEBUG( DEBUG_ELF, "results    : class %d; machine: %d;",
           eclass, ehdr.e_machine );

    // both the class (word size) and machine (architecture) match
    return 1;
}

// make sure all the string buffers are zeroed out
static inline void sanitise_ldlibs(ldlibs_t *ldlibs)
{
    ldlibs->prefix.path[ ldlibs->prefix.len ] = '\0';
}

// as we are pulling in files from a non '/' prefix ('/host' by default)
// we need to compensate for this when resolving symlinks.
// this will keep following the path at entry i in ldlibs until
// it finds something that is not a symlink.
void resolve_symlink_prefixed (ldlibs_t *ldlibs, int i)
{
    int count = 0;
    char resolved[PATH_MAX];
    char link_dir[PATH_MAX];

    sanitise_ldlibs(ldlibs);
    // prefix is unset or is /, nothing to do here (we can rely on
    // libc's built-in symlink following if there's no prefix):
    if( ldlibs->prefix.len == 0 ||
        (ldlibs->prefix.path[0] == '/' && ldlibs->prefix.path[1] == '\0') )
        return;

    LDLIB_DEBUG( ldlibs, DEBUG_PATH,
                 "resolving (un)prefixed link in %s", ldlibs->needed[i].path );

    // set the resolved path to the current needed path as a starting point:
    safe_strncpy( resolved, ldlibs->needed[i].path, PATH_MAX );

    // now keep poking resolve_link (resolved will be updated each time)
    // until it returns false:
    while( resolve_link(ldlibs->prefix.path, resolved, link_dir) )
    {
        LDLIB_DEBUG( ldlibs, DEBUG_PATH, "  resolved to: %s", resolved );

        if( ++count > MAXSYMLINKS )
        {
            fprintf( stderr, "%s: MAXSYMLINKS (%d) exceeded resolving %s\n",
                     __PRETTY_FUNCTION__, MAXSYMLINKS,
                     ldlibs->needed[i].path );
            break;
        }
    }

    // if the path changed, copy `resolved' back into needed[].path:
    if( count )
        safe_strncpy( ldlibs->needed[i].path, resolved, PATH_MAX );
}

// open the dso at offset i in the needed array, but only accept it
// if it matches the class & architecture of the starting DSO:
// return a true value only if we finish with a valid fd for the DSO
//
// will set up the needed entry at offset i correctly if we are
// successful, and clear it if we are not:
//
// designed to be called on a populated ldlib needed entry, 'name'
// is the original requested name (typically an absolute path to
// a DSO or a standard DT_NEEDED style specifier following 'libfoo.so.X')
//
// note that this expects the prefix to have already been prepended
// to the DSO path in the ldlibs->needed[i].path buffer if necessary
// this is to allow both prefixed and unprefixed DSOs to be handled
// here:
static int
ldlib_open (ldlibs_t *ldlibs, const char *name, int i)
{

    LDLIB_DEBUG( ldlibs, DEBUG_SEARCH,
                 "ldlib_open: target -: %s", ldlibs->needed[i].path );

    // resolve the symlink manually if there's a prefix:
    resolve_symlink_prefixed( ldlibs, i );

    LDLIB_DEBUG( ldlibs, DEBUG_SEARCH,
                 "ldlib_open: target +: %s", ldlibs->needed[i].path );

    ldlibs->needed[i].fd = open( ldlibs->needed[i].path, O_RDONLY );

    if( ldlibs->needed[i].fd >= 0 )
    {
        int acceptable = 0;

        ldlibs->needed[i].name = NULL;
        ldlibs->needed[i].dso  =
          elf_begin( ldlibs->needed[i].fd, ELF_C_READ_MMAP, NULL );

        acceptable = check_elf_constraints( ldlibs, i );

        LDLIB_DEBUG( ldlibs, DEBUG_SEARCH,
                     "[%03d] %s on fd #%d; elf: %p; acceptable: %d",
                     i,
                     ldlibs->needed[i].path,
                     ldlibs->needed[i].fd  ,
                     ldlibs->needed[i].dso ,
                     acceptable );

        // either clean up the current entry so we can find a better DSO
        // or (for a valid candidate) copy the original requested name in:
        if( !acceptable )
            clear_needed( &ldlibs->needed[i] );
        else
            ldlibs->needed[i].name = strdup( name );
    }

    // the fd will only be valid if everything worked out:
    return ldlibs->needed[i].fd >= 0;
}

// iterate over the ld.so.cache loaded into the ldlibs structure,
// calling cb for each entry, until cb returns true or we run out
// of entries. will return true as soon as cb returns true, or
// false if we get to the end of the cache without cb returning true:
static int
iterate_ldcache (ldlibs_t *ldlibs, ldcache_entry_cb cb, void *data)
{
    int rval = 0;
    const char *base = ldlibs->cache_data;

    switch (ldlibs->ctype)
    {
      case CACHE_OLD:
        for (int i = 0; !rval && (i < ldlibs->cache.old->nlibs); i++)
        {
            struct file_entry *f = &ldlibs->cache.old->libs[i];
            rval = cb( ldlibs, base + f->key, f->flags,
                       0, 0, base + f->value, data );
        }
        break;

      case CACHE_NEW:
        for (int i = 0; !rval && (i < ldlibs->cache.new->nlibs); i++)
        {
            struct file_entry_new *f = &ldlibs->cache.new->libs[i];
            rval = cb( ldlibs, base + f->key, f->flags,
                       f->osversion, f->hwcap, base + f->value, data );
        }
        break;

      default:
        fprintf( stderr, "Invalid ld cache type %d, cannot parse",
                 ldlibs->ctype );
        exit(22);
    }

    return rval;
}

// search callback for search_ldcache. see search_ldcache and iterate_ldcache:
// returning a true value means we found (and set up) the DSO we wanted:
static int
search_ldcache_cb (ldlibs_t *ldlibs,
                   const char *name, // name of the DSO in the ldcache
                   int flag,         // 1 for an ELF DSO
                   unsigned int osv, // OS version. we don't use this
                   uint64_t hwcap,   // HW caps. Ibid.
                   const char *path, // absolute path to DSO (may be a symlink)
                   struct dso_cache_search *target)
{
    // passed an empty query, just abort the whole search
    if( !target->name || !(*target->name) )
        return 1;

    // what would this even mean? malformed cache entry?
    // skip it and move on
    if( !name || !*name )
        return 0;

    if( strcmp( name, target->name ) == 0 )
    {
        int    idx    = target->idx;
        char  *prefix = ldlibs->prefix.path;
        size_t plen   = ldlibs->prefix.len;
        char  *lpath  = ldlibs->needed[ idx ].path;

        LDLIB_DEBUG( ldlibs, DEBUG_SEARCH|DEBUG_LDCACHE,
                     "checking %s vs %s [%s]",
                     target->name, name, path );
        // copy in the prefix and append the DSO path to it
        safe_strncpy( lpath, prefix, PATH_MAX );
        safe_strncpy( lpath + plen, path, PATH_MAX - plen );

        // try to open the DSO. This will finish setting up the
        // needed[idx] slot if successful, and reset it ready for
        // another attempt if it fails:
        return ldlib_open( ldlibs, name, idx );
    }

    return 0;
}

// search the ld.so.cache loaded into ldlibs for one matching `name'
// name should be unadorned: eg just libfoo.so.X - no path elements
// attached (as the cache lookup is for unadorned library names):
//
// if a match is found, the needed array entry at i will be populated
// and will contain a valid fd for the DSO. (and search_ldcache will
// return true). Otherwise the entry will be empty and we will return false:
//
// this function will respect any path prefix specified in ldlibs
static int
search_ldcache (const char *name, ldlibs_t *ldlibs, int i)
{
    struct dso_cache_search target;

    target.idx   = i;
    target.name  = name;

    iterate_ldcache( ldlibs, (ldcache_entry_cb)search_ldcache_cb, &target );

    return ldlibs->needed[i].fd >= 0;
}

// search a : separated path (such as LD_LIBRARY_PATH from the environment)
// for a DSO matching the bare `name' (eg libfoo.so.X)
//
// if a match is found, the needed array entry at i will be populated
// and will contain a valid fd for the DSO. (and search_ldcache will
// return true). Otherwise the entry will be empty and we will return false:
//
// this function will respect any path prefix specified in ldlibs
static int
search_ldpath (const char *name, const char *ldpath, ldlibs_t *ldlibs, int i)
{
    char  *sp     = (char *)ldpath;
    char  *prefix = ldlibs->prefix.path;
    size_t plen   = ldlibs->prefix.len;

    prefix[plen] = '\0';

    sanitise_ldlibs(ldlibs);

    LDLIB_DEBUG( ldlibs, DEBUG_SEARCH,
                 "searching for %s in %s (prefix: %s)",
                 name, ldpath, plen ? prefix : "-none-" );

    while( sp && *sp )
    {
        size_t len;
        char *end;

        end = strchr( sp, ':' );
        if( end )
            len = MIN((end - sp), PATH_MAX - plen - 1);
        else
            len = MIN(strlen( sp ), PATH_MAX - plen - 1);

        safe_strncpy( prefix + plen, sp, len + 1);
        prefix[plen + len + 1] = '\0';

        LDLIB_DEBUG( ldlibs, DEBUG_SEARCH, "  searchpath element: %s", prefix );
        // append the target name, without overflowing, then resolve
        if( (plen + len + strlen( name ) + 1 < PATH_MAX) )
        {
            prefix[plen + len] = '/';
            safe_strncpy( prefix + plen + len + 1, name,
                          PATH_MAX - plen - len - 1 );

            LDLIB_DEBUG( ldlibs, DEBUG_SEARCH, "examining %s", prefix );
            // if path resolution succeeds _and_ we can open an acceptable
            // DSO at that location, we're good to go (ldlib_open will
            // finish setting up or clearing the needed[] entry for us):
            if( realpath( prefix, ldlibs->needed[i].path ) &&
                ldlib_open( ldlibs, name, i ) )
                return 1;
        }

        // search the next path element if there is one
        if( !end )
            break;

        sp = end + 1;
    }

    return 0;
}

// find a DSO using an algorithm that matches the one used by the
// normal dynamic linker and set up the needed array entry at offset i.
//
// Exceptions:
// we don't support DT_RPATH/DT_RUNPATH
// we don't handle ${ORIGIN} and similar
// we will respect any path prefix specified in ldlibs
//
// if a match is found, the needed array entry at i will be populated
// and will contain a valid fd for the DSO. (and search_ldcache will
// return true). Otherwise the entry will be empty and we will return false:
static int
dso_find (const char *name, ldlibs_t *ldlibs, int i)
{
    int found = 0;
    const char *ldpath = NULL;
    int absolute = (name && (name[0] == '/'));

    // 'name' is an absolute path, or relative to CWD:
    // we may to need to do some path manipulation
    if( strchr( name, '/' ) )
    {
        size_t plen = ldlibs->prefix.len;
        char prefixed[PATH_MAX];
        const char *target;

        // we have a path prefix, so yes, we need to do some path manipulation:
        if( ldlibs->prefix.len )
        {
            sanitise_ldlibs(ldlibs);
            safe_strncpy( prefixed, ldlibs->prefix.path, PATH_MAX );

            if( absolute )
            {
                safe_strncpy( prefixed + plen, name, PATH_MAX - plen );
                LDLIB_DEBUG( ldlibs, DEBUG_SEARCH|DEBUG_PATH,
                             "absolute path to DSO %s", prefixed );
            }
            else
            {   // name is relative... this is probably wrong?
                // I don't think this can ever really happen but
                // worst case is we'll simply not open a DSO whose
                // path we couldn't resolve, and then move on:
                safe_strncpy( prefixed + plen, "/", PATH_MAX - plen );
                safe_strncpy( prefixed + plen + 1, name, PATH_MAX - plen - 1);
                LDLIB_DEBUG( ldlibs, DEBUG_SEARCH|DEBUG_PATH,
                             "relative path to DSO %s", prefixed );
            }

            target = prefixed;
        }
        else
        {   // name is a standard bare 'libfoo.so.X' spec:
            target = name;
        }

        LDLIB_DEBUG( ldlibs, DEBUG_SEARCH|DEBUG_PATH,
                     "resolving path %s", target );
        // this will fail for a non-absolute path, but that's OK
        // if realpath lookup succeeds needed[i].path will be set correctly:
        if( realpath( target, ldlibs->needed[i].path ) )
            return ldlib_open( ldlibs, name, i );
    }

    // path was absolute and we couldn't resolve it. give up:
    if( absolute )
        return 0;

    LDLIB_DEBUG( ldlibs, DEBUG_SEARCH, "target DSO is %s", name );
    // now search LD_LIBRARY_PATH, the ld.so.cache, and the default locations
    // in that order (similar algorithm to the linker, but with the RPATH and
    // ${ORIGIN} support dropped)
    if( (ldpath = getenv( "LD_LIBRARY_PATH" )) )
        if( (found = search_ldpath( name, ldpath, ldlibs, i )) )
            return found;

    if( (found = search_ldcache( name, ldlibs, i )) )
        return found;

    if( (found = search_ldpath( name, "/lib:/usr/lib", ldlibs, i )) )
        return found;

    return 0;
}

// if a DSO has already been requested and found as a result of a DT_NEEDED
// entry we've seen before then it's already in the needed array - check
// for such pre-required entries and simply record the dependency instead
// of reopening the DSO (and return true to indicate that we already have the
// DSO)
//
// we have assumed that the root of the DSO chain can never be already-needed
// as this would indicate a circular dependency.
static int
already_needed (dso_needed_t *needed, int requesting_idx, const char *name)
{
    for( int i = DSO_LIMIT - 1; i > 0; i-- )
    {
        if( needed[i].name && strcmp( needed[i].name, name ) == 0)
        {
            needed[i].requestors[requesting_idx] = 1;
            return i;
        }
    }

    return 0;
}

// we're getting to the meat of it: process a DSO at offset idx in the
// needed array, extract each SHT_DYNAMIC section, then make sure we
// can find a DSO to satisfy every DT_NEEDED sub-entry in the section.
// this function recurses into itself each time it finds a previously
// unseen DT_NEEDED value (but not if the DT_NEEDED value is for a DSO
// it has already found and recorded in the needed array)
//
// NOTE: you must use dso_find to seed the 0th entry in the needed array
// or the elf handle in needed[0].dso will not be set up and hilarity*
// will ensue.
static void
_dso_iterate_sections (ldlibs_t *ldlibs, int idx)
{
    Elf_Scn *scn = NULL;

    //debug(" ldlibs: %p; idx: %d (%s)", ldlibs, idx, ldlibs->needed[idx].name);

    ldlibs->last_idx = idx;

    LDLIB_DEBUG( ldlibs, DEBUG_ELF,
                 "%03d: fd:%d dso:%p ← %s",
                 idx,
                 ldlibs->needed[idx].fd,
                 ldlibs->needed[idx].dso,
                 ldlibs->needed[idx].path );

    while((scn = elf_nextscn( ldlibs->needed[idx].dso, scn )) != NULL)
    {
        GElf_Shdr shdr = {};
        gelf_getshdr( scn, &shdr );

        // SHT_DYNAMIC is the only section type we care about here:
        if( shdr.sh_type == SHT_DYNAMIC )
        {
            int i = 0;
            GElf_Dyn dyn = {};
            Elf_Data *edata = NULL;

            edata = elf_getdata( scn, edata );

            // process eaach DT_* entry in the SHT_DYNAMIC section:
            while( !ldlibs->error                  &&
                   gelf_getdyn( edata, i++, &dyn ) &&
                   (dyn.d_tag != DT_NULL)          )
            {
                int skip = 0;
                int next = ldlibs->last_idx;
                dso_needed_t *needed = ldlibs->needed;
                char *next_dso; // name of the dependency we're going to need

                // we're only gathering DT_NEEDED (dependency) entries here:
                if( dyn.d_tag != DT_NEEDED )
                    continue;

                next_dso =
                  elf_strptr( needed[idx].dso, shdr.sh_link, dyn.d_un.d_val );

                //////////////////////////////////////////////////
                // ignore the linker itself
                if( strstr( next_dso, "ld-" ) == next_dso )
                    continue;

                // ignore any DSOs we've been specifically told to leave out:
                for( char **x = (char **)ldlibs->exclude; x && *x; x++ )
                {
                    if( strcmp( *x, next_dso ) == 0 )
                    {
                        LDLIB_DEBUG( ldlibs, DEBUG_SEARCH|DEBUG_ELF,
                                     "skipping %s / %s", next_dso, *x );
                        skip = 1;
                        break;
                    }
                }

                if( skip )
                    continue;

                //////////////////////////////////////////////////
                // if we got this far, we have another dependency:
                needed[idx].depcount++;

                // already on our list, no need to do anything else here:
                if( already_needed( needed, idx, next_dso ) )
                    continue;

                next++;
                if( next >= DSO_LIMIT )
                {
                    ldlibs->error = strdup( "Too many dependencies: abort" );
                    break;
                }

                if( !dso_find( next_dso, ldlibs, next ) )
                {
                    ldlibs->not_found[ ldlibs->last_not_found++ ] =
                      strdup( next_dso );
                    ldlibs->error = strdup( "Missing dependencies:" );
                }
                else
                {
                    // record which DSO requested the new library we found:
                    needed[next].requestors[idx] = 1;
                    // now find the dependencies of our newest dependency:
                    _dso_iterate_sections( ldlibs, next );
                }
            }
        }
    }
}

static void
_dso_iterator_format_error (ldlibs_t * ldlibs)
{
    size_t extra_space = 0;

    if( ! ldlibs->error )
        return;

    if( ! ldlibs->not_found[0] )
        return;

    for( int i = 0; (i < DSO_LIMIT) && ldlibs->not_found[i]; i++ )
        extra_space += strlen( ldlibs->not_found[i] ) + 1;

    if( extra_space )
    {
        char *append_here;
        char *end;
        size_t prev_space = strlen( ldlibs->error );

        ldlibs->error =
          realloc( ldlibs->error, prev_space + extra_space + 2 );
        append_here = ldlibs->error + prev_space;
        end = ldlibs->error + prev_space + extra_space + 1;
        memset( append_here, 0, extra_space + 2 );

        for( int i = 0; (i < DSO_LIMIT) && ldlibs->not_found[i]; i++ )
        {
            append_here +=
              snprintf( append_here, end - append_here,
                        " %s", ldlibs->not_found[i] );
            free( ldlibs->not_found[i] );
            ldlibs->not_found[i] = NULL;
        }
    }
}

// wrapper to format any accumulated errors and similar after
// invoking the actual dso iterator: returns true if we gathered
// all the needed info witout error, false otherwise:
static int
dso_iterate_sections (ldlibs_t *ldlibs, int idx)
{
    _dso_iterate_sections( ldlibs, idx );
    _dso_iterator_format_error( ldlibs );

    return ldlibs->error == NULL;
}

// map the ld.so.cache for the system into memory so that we can search it
// for DSOs in the same way as the dynamic linker.
//
// returns true on success, false otherwise.
//
// this function respects any path prefix specified in ldlibs
static int
load_ld_cache (ldlibs_t *libs, const char *path)
{
    struct stat ldcache = {};
    const char *cachepath;
    int rv;

    if( libs->prefix.len == 0 )
    {
        cachepath = path;
        libs->cache_fd = open( path, O_RDONLY );
    }
    else
    {
        safe_strncpy( libs->prefix.path + libs->prefix.len,
                      path, PATH_MAX - libs->prefix.len );
        cachepath = libs->prefix.path;
        libs->cache_fd = open( libs->prefix.path, O_RDONLY );
    }

    if( libs->cache_fd < 0 )
    {
        fprintf( stderr, "failed to open ld.so cache file %s: %s\n",
                 cachepath, strerror( errno ) );
        goto no_cache;
    }

    fstat( libs->cache_fd, &ldcache );

    // cache file must be at least this big or it's invalid:
    if( ldcache.st_size < sizeof( struct cache_file ) )
        goto no_cache;

    libs->cache_mmap =
      mmap( NULL, ldcache.st_size, PROT_READ, MAP_PRIVATE, libs->cache_fd, 0 );

    if( libs->cache_mmap == MAP_FAILED )
    {
        fprintf( stderr, "failed to mmap ld.so cache file %s: %s\n",
                 path, strerror( errno ) );
        goto no_cache;
    }

    libs->cache_map_size = ldcache.st_size;

    // plain modern (circa 2016) cache map:
    if( memcmp( libs->cache_mmap->magic, CACHEMAGIC, sizeof(CACHEMAGIC) -1 ) )
    {
        DEBUG( DEBUG_LDCACHE, "New format ld cache" );
        libs->cache.new = (struct cache_file_new *)libs->cache_mmap;

        // if the magic strings don't reside at the expected offsets, bail out:
        if( memcmp( libs->cache.new->magic, CACHEMAGIC_NEW,
                    sizeof(CACHEMAGIC_NEW) - 1 ) ||
            memcmp( libs->cache.new->version, CACHE_VERSION,
                    sizeof(CACHE_VERSION) - 1) )
        {
            fprintf( stderr, "invalid cache, expected %s: %s\n",
                     CACHEMAGIC_NEW, CACHE_VERSION );
            goto no_cache;
        }

        libs->cache_data = (char *)libs->cache.new;
        libs->ctype = CACHE_NEW;
    }
    else
    {
        size_t header = sizeof( struct cache_file );
        size_t entry  = sizeof( struct file_entry );
        size_t block  = header + (libs->cache_mmap->nlibs * entry);
        size_t offset = ALIGN_CACHE( block );
        int nlibs = libs->cache_mmap->nlibs;

        DEBUG( DEBUG_LDCACHE, "Old format ld cache" );

        // it's an old-style cache, unless we successfully probe for a
        // nested new cache inside it:
        libs->ctype = CACHE_OLD;

        /* This is where the strings start.  */
        libs->cache_data = (const char *) &libs->cache_mmap->libs[ nlibs ];

        if( libs->cache_map_size > (offset + sizeof( struct cache_file_new )) )
        {
            libs->cache.new = (void *)libs->cache_mmap + offset;

            // this is the probe: as in the pervious if block, except
            // that if we don't find a new cache it's not an error,
            // it just means we're in an old style cache:
            if( memcmp( libs->cache.new->magic, CACHEMAGIC_NEW,
                        sizeof(CACHEMAGIC_NEW) - 1 ) ||
                memcmp( libs->cache.new->version, CACHE_VERSION,
                        sizeof(CACHE_VERSION) - 1) )
            {
                // nope, no encapsulated new cache:
                libs->cache.old = libs->cache_mmap;
            }
            else
            {
                DEBUG( DEBUG_LDCACHE, "... with a new style cache inside" );
                libs->ctype = CACHE_NEW;
                libs->cache_data = (char *)libs->cache.new;
            }
        }
    }

    if( libs->cache_fd >= 0 )
    {
        DEBUG( DEBUG_LDCACHE, "Opened ld.cache at %s", cachepath );
        rv = 1;
    }
    else
    {
        DEBUG( DEBUG_LDCACHE, "No ld.cache at %s", cachepath );
        rv = 0;
    }

    sanitise_ldlibs( libs );
    return rv;

no_cache:

    if( libs->cache_fd >= 0 )
        close( libs->cache_fd );

    if( libs->cache_mmap != MAP_FAILED && libs->cache_mmap != NULL )
        munmap( libs->cache_mmap, libs->cache_map_size );

    libs->cache_fd       = -1;
    libs->cache_map_size = 0;
    libs->ctype          = CACHE_NONE;
    libs->cache_mmap     = NULL;
    libs->cache_data     = NULL;
    libs->cache.new      = NULL;

    return 0;
}

static void
cleanup_ldlibs (ldlibs_t *ldlibs)
{
    for( int i = 0; i < DSO_LIMIT; i++ )
        clear_needed( &ldlibs->needed[i] );

    for( int i = ldlibs->last_not_found; i >= 0; i-- )
    {
        free( ldlibs->not_found[i] );
        ldlibs->not_found[i] = NULL;
    }

    ldlibs->last_not_found = 0;

    if( ldlibs->cache_mmap )
    {
        munmap( ldlibs->cache_mmap, ldlibs->cache_map_size );
        ldlibs->cache_map_size = 0;
    }
    // these are into the region we just munmap()ed
    ldlibs->cache_data = NULL;
    ldlibs->cache.new  = NULL;
    ldlibs->cache.old  = NULL;

    if( ldlibs->cache_fd >= 0 )
    {
        close( ldlibs->cache_fd );
        ldlibs->cache_fd = -1;
    }

    ldlibs->ctype = CACHE_NONE;
    ldlibs->last_idx = 0;
    ldlibs->elf_class = ELFCLASSNONE;
    ldlibs->elf_machine = EM_NONE;

    ldlibs->prefix.len = 0;
    ldlibs->prefix.path[0] = '\0';

    if( ldlibs->error )
        free( ldlibs->error );

    ldlibs->error = NULL;
}

static const char *
_rtldstr(int flag)
{
    char flags[160] = { 0 };
    char *f = &flags[0];

    if( !flag)
        return "LOCAL";

#define RTLDFLAGSTR(x) \
    if( x & flag ) f += snprintf(f, &flags[80] - f, " %s", & #x [5])

    RTLDFLAGSTR(RTLD_LAZY);
    RTLDFLAGSTR(RTLD_NOW);
    RTLDFLAGSTR(RTLD_NOLOAD);
    RTLDFLAGSTR(RTLD_DEEPBIND);
    RTLDFLAGSTR(RTLD_GLOBAL);
    RTLDFLAGSTR(RTLD_NODELETE);

    return ( flags[0] == ' ' ) ? &flags[1] : &flags[0];
}

// And now we actually open everything we have found, in reverse
// dependency order (which prevents dlmopen from going and finding
// DT_NEEDED values from outside the capsule), which it will do
// if we don't work backwards:
static void *
load_ldlibs (ldlibs_t *ldlibs, Lmid_t *namespace, int flag, int *errcode, char **error)
{
    int go;
    Lmid_t lm = (*namespace > 0) ? *namespace : LM_ID_NEWLM;
    void *ret = NULL;

    if( !flag )
        flag = RTLD_LAZY;

    do
    {
        go = 0;

        for( int j = 0; j < DSO_LIMIT; j++ )
        {
            // reached the end of the list
            if( !ldlibs->needed[j].name )
                continue;

            // library has no further dependencies which have not already
            // been satisfied (except for the libc and linker DSOs),
            // this means we can safely open it without dlmopen accidentally
            // pulling in DSOs from outside the encapsulated tree:
            if( ldlibs->needed[j].depcount == 0 )
            {
                const char *path = ldlibs->needed[j].path;
                go++;

                LDLIB_DEBUG( ldlibs, DEBUG_CAPSULE,
                             "DLMOPEN %p %s %s",
                             (void *)lm, _rtldstr(flag), path );

                // The actual dlmopen. If this was the first one, it may
                // have created a new link map id, wich we record later on:

                // note that since we do the opens in reverse dependency order,
                // the _last_ one we open will be the DSO we actually asked for
                // so if we succeed, ret has to contain the right handle.
                ret = dlmopen( lm, path, flag );

                if( !ret )
                {
                    if( error )
                        *error = dlerror();

                    if( errcode )
                        *errcode = EINVAL;

                    return NULL;
                }

                // If this was the first dlmopen, record the new LM Id
                // for return to our caller:
                if( lm == LM_ID_NEWLM )
                {
                    dlinfo( ret, RTLD_DI_LMID, namespace );
                    lm = *namespace;
                    LDLIB_DEBUG( ldlibs, DEBUG_CAPSULE,
                                 "new Lmid_t handle %p\n", (void *)lm );
                }

                // go through the map of DSOs and reduce the dependency
                // count for any DSOs which had the current DSO as a dep:
                for( int k = 0; k < DSO_LIMIT; k++ )
                    if( ldlibs->needed[j].requestors[k] )
                        ldlibs->needed[k].depcount--;

                clear_needed( &ldlibs->needed[j] );
            }
        }
    } while (go);

    return ret;
}

static void
init_ldlibs (ldlibs_t *ldlibs,
             const char **exclude,
             const char *prefix,
             unsigned long dbg,
             int *errcode,
             char **error)
{
    memset( ldlibs, 0, sizeof(ldlibs_t) );
    ldlibs->cache_fd    = -1;
    ldlibs->ctype       = CACHE_NONE;
    ldlibs->elf_class   = ELFCLASSNONE;
    ldlibs->elf_machine = EM_NONE;
    ldlibs->exclude     = exclude;
    ldlibs->debug       = dbg;

    if( errcode )
        *errcode = 0;

    // super important, 0 is valid but is usually stdin,
    // don't want to go stomping all over that by accident:
    for( int x = 0; x < DSO_LIMIT; x++ )
        ldlibs->needed[x].fd = -1;

    set_elf_constraints(ldlibs);
    // ==================================================================
    // set up the path prefix at which we expect to find the encapsulated
    // library and its ld.so.cache and dependencies and so forth:
    if( prefix )
    {
        size_t prefix_len = strlen( prefix );
        ssize_t space = PATH_MAX - prefix_len;

        // if we don't have at least this much space it's not
        // going to work out:
        if( (space - strlen( "/usr/lib/libx.so.x" )) <= 0 )
        {
            if( error )
                *error = strdup( "capsule_dlmopen: prefix is too large" );

            if( errcode )
                *errcode = ENAMETOOLONG;

            return;
        }

        safe_strncpy( ldlibs->prefix.path, prefix, PATH_MAX );
        ldlibs->prefix.len = prefix_len;
    }
    else
    {
        ldlibs->prefix.path[0] = '\0';
        ldlibs->prefix.len     = 0;
    }
}

// ==========================================================================
// some pretty printers for debugging:
static int
dump_ld_entry (ldlibs_t *ldlibs,
               const char *name,
               int flag,
               unsigned int osv,
               uint64_t hwcap,
               const char *path,
               void *cb_data)
{
    fprintf( stderr, "%s → %s\n", name, path );

    fputs( "  type: ", stderr );
    switch (flag & FLAG_TYPE_MASK)
    {
      case FLAG_LIBC4:
      case FLAG_ELF:
      case FLAG_ELF_LIBC5:
      case FLAG_ELF_LIBC6:
        fputs( flag_descr[flag & FLAG_TYPE_MASK], stderr );
        break;
      default:
        fputs ("???", stdout);
        break;
    }
    fputs( "\n", stderr );

    fputs( "  requires: ", stderr );
    switch (flag & FLAG_REQUIRED_MASK)
    {
      case FLAG_SPARC_LIB64:
        fputs ("Sparc 64bit", stderr);
        break;
      case FLAG_IA64_LIB64:
        fputs ("IA-64", stderr);
        break;
      case FLAG_X8664_LIB64:
        fputs ("x86-64", stderr);
        break;
      case FLAG_S390_LIB64:
        fputs ("s390 64bit", stderr);
        break;
      case FLAG_POWERPC_LIB64:
        fputs ("PPC 64bit", stderr);
        break;
      case FLAG_MIPS64_LIBN32:
        fputs ("MIPS N32", stderr);
        break;
      case FLAG_MIPS64_LIBN64:
        fputs ("MIPS 64bit", stderr);
        break;
      case FLAG_X8664_LIBX32:
        fputs ("x32", stderr);
        break;
      case FLAG_ARM_LIBHF:
        fputs ("Arm hard-float", stderr);
        break;
      case FLAG_AARCH64_LIB64:
        fputs ("AArch64", stderr);
        break;
        /* Uses the ARM soft-float ABI.  */
      case FLAG_ARM_LIBSF:
        fputs ("Arm soft-float", stderr);
        break;
      case FLAG_MIPS_LIB32_NAN2008:
        fputs ("MIPS nan2008", stderr);
      break;
      case FLAG_MIPS64_LIBN32_NAN2008:
        fputs ("MIPS N32 nan2008", stderr);
        break;
      case FLAG_MIPS64_LIBN64_NAN2008:
        fputs ("IPS 64bit nan2008", stderr);
        break;
      case 0:
        break;
      default:
        fprintf (stderr, "%0x", flag & FLAG_REQUIRED_MASK);
        break;
    }
    fputs( "\n", stderr );

    unsigned int os = osv >> 24;

    fprintf( stderr, "  OS ABI: %s %d.%d.%d (%0x)\n",
             abi_tag_os[ os > MAXTAG ? MAXTAG : os ],
             (osv >> 16) & 0xff,
             (osv >> 8 ) & 0xff,
             osv & 0xff,
             osv );

    fprintf( stderr, "  hwcaps: %0"FMT_XU64"\n", hwcap );
    return 0;
}

// dump out the contents of the ld cache to stderr:
static void
dump_ld_cache (ldlibs_t *ldlibs)
{
    iterate_ldcache( ldlibs, dump_ld_entry, NULL );
}

static void
wrap (const char *name,
      ElfW(Addr) base,
      ElfW(Dyn) *dyn,
      capsule_item_t *wrappers)
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
                              capsule_item_t *wrappers,
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
// ==========================================================================
void *
capsule_dlmopen (const char *dso,
                 const char *prefix,
                 Lmid_t *namespace,
                 capsule_item_t *wrappers,
                 unsigned long dbg,
                 const char **exclude,
                 int *errcode,
                 char **error)
{
    void *ret = NULL;
    ldlibs_t ldlibs = { 0 };

    if( dbg == 0 )
        dbg = debug_flags;

    if( elf_version(EV_CURRENT) == EV_NONE )
    {
        if( error )
            *error = strdup( "capsule_dlmopen: incompatible libelf version" );

        if( errcode )
            *errcode = elf_errno();

        return NULL;
    }

    init_ldlibs( &ldlibs, exclude, prefix, dbg, errcode, error );

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
    if( !dso_find( dso, &ldlibs, 0 ) )
    {
        int rv = (errno == 0) ? EINVAL : errno;

        if( error )
        {
            int elf_rv;

            if( ldlibs.error )
            {
                *error = ldlibs.error;
                ldlibs.error = NULL;
            }
            else if( (elf_rv = elf_errno()) )
            {
                *error = strdup( elf_errmsg(elf_rv) );
            }
            else
            {
                *error = strdup( "capsule_dlmopen: could not open dso" );
            }
        }

        if( errcode )
            *errcode = rv;

        goto cleanup;
    }

    // ==================================================================
    // once we have the starting point recursively find all its DT_NEEDED
    // entries, except for the linker itself and libc, which must not
    // be different between the capsule and the "real" DSO environment:
    dso_iterate_sections( &ldlibs, 0 );

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
    ret = load_ldlibs( &ldlibs, namespace, 0, errcode, error );

    if( !ret )
        goto cleanup;

    // TODO: failure in the dlopen fixup phase should probably be fatal:
    if( ret      != NULL && // no errors so far
        wrappers != NULL )  // have a dlopen fixup function
        install_wrappers( ret, wrappers, exclude, errcode, error );

cleanup:
    cleanup_ldlibs( &ldlibs );
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
    ldlibs_t ldlibs = { 0 };

    DEBUG( DEBUG_WRAPPERS,
           "dlopen(%s, %x) wrapper: LMID: %ld; prefix: %s;",
           file, flag, ns, prefix );

    if( prefix && strcmp(prefix, "/") )
    {
        init_ldlibs( &ldlibs, exclude, prefix, debug_flags, &code, &errors );

        if( !load_ld_cache( &ldlibs, "/etc/ld.so.cache" ) )
        {
            int rv = (errno == 0) ? EINVAL : errno;

            DEBUG( DEBUG_LDCACHE|DEBUG_WRAPPERS,
                   "Loading ld.so.cache from %s (error: %d)", prefix, rv );
            goto cleanup;
        }

        // find the initial DSO (ie what the caller actually asked for):
        if( !dso_find( file, &ldlibs, 0 ) )
        {
            int rv = (errno == 0) ? EINVAL : errno;

            DEBUG( DEBUG_SEARCH|DEBUG_WRAPPERS,
                           "Not found: %s under %s (error: %d)",
                           file, prefix, rv );
            goto cleanup;
        }

        // harvest all the requested DSO's dependencies:
        dso_iterate_sections( &ldlibs, 0 );

        if( ldlibs.error )
        {
            DEBUG( DEBUG_WRAPPERS, "capsule dlopen error: %s", ldlibs.error );
            goto cleanup;
        }

        // load them up in reverse dependency order:
        res = load_ldlibs( &ldlibs, &ns, flag, &code, &errors );

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
    cleanup_ldlibs( &ldlibs );
    return res;
}
