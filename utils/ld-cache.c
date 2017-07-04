#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#include "ld-cache.h"
#include "utils.h"

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

/* Used to align cache_file_new.  */
#define ALIGN_CACHE(addr)                               \
    (((addr) + __alignof__ (struct cache_file_new) -1)	\
     & (~(__alignof__ (struct cache_file_new) - 1)))

// end of stolen header structures
////////////////////////////////////////////////////////////////////////////
static void
ld_cache_reset (ldcache_t *cache)
{
    cache->fd       = -1;
    cache->map_size = 0;
    cache->data     = NULL;
    cache->file.old = NULL;
    cache->type     = CACHE_NONE;
    cache->mmap     = MAP_FAILED;
    cache->is_open  = 0;
}

void
ld_cache_close (ldcache_t *cache)
{
    // 0 is a valid fd, but is also the default value of the unset
    // struct member, so we have to check if it's _really_ open:
    if( cache->is_open )
    {
        if( cache->fd >= 0 )
            close( cache->fd );
    }

    if( cache->mmap && cache->map_size )
        munmap( cache->mmap, cache->map_size );

    ld_cache_reset( cache );
}

int
ld_cache_open (ldcache_t *cache, const char *path)
{
    struct stat ldcache = {};

    ld_cache_close( cache );

    cache->fd = open( path, O_RDONLY );

    if( cache->fd < 0 )
        goto cleanup;

    // now we have a real file descriptor tag the
    // cache as successfully opened:
    cache->is_open = 1;

    fstat( cache->fd, &ldcache );

    // cache file must be at least this big or it's invalid:
    if( ldcache.st_size < sizeof( struct cache_file ) )
        goto cleanup;

    cache->mmap =
      mmap( NULL, ldcache.st_size, PROT_READ, MAP_PRIVATE, cache->fd, 0 );

    if( cache->mmap == MAP_FAILED )
        goto cleanup;

    cache->map_size = ldcache.st_size;

    // plain modern (circa 2016) cache map:
    if( memcmp( cache->mmap->magic, CACHEMAGIC, sizeof(CACHEMAGIC) -1 ) )
    {
        DEBUG( DEBUG_LDCACHE, "New format ld cache" );
        cache->file.new = (struct cache_file_new *)cache->mmap;

        // if the magic strings don't reside at the expected offsets, bail out:
        if( memcmp( cache->file.new->magic,
                    CACHEMAGIC_NEW, sizeof(CACHEMAGIC_NEW) - 1 ) ||
            memcmp( cache->file.new->version,
                    CACHE_VERSION, sizeof(CACHE_VERSION) - 1 ) )
        {
            fprintf( stderr, "invalid cache, expected %s: %s\n",
                     CACHEMAGIC_NEW, CACHE_VERSION );
            goto cleanup;
        }

        cache->data = (char *)cache->file.new;
        cache->type = CACHE_NEW;
    }
    else
    {
        size_t header = sizeof( struct cache_file );
        size_t entry  = sizeof( struct file_entry );
        size_t block  = header + (cache->mmap->nlibs * entry);
        size_t offset = ALIGN_CACHE( block );
        int nlibs = cache->mmap->nlibs;

        DEBUG( DEBUG_LDCACHE, "Old format ld cache" );

        // it's an old-style cache, unless we successfully probe for a
        // nested new cache inside it:
        cache->type = CACHE_OLD;

        /* This is where the strings start in an old style cache  */
        cache->data = (const char *) &cache->mmap->libs[ nlibs ];

        if( cache->map_size > (offset + sizeof( struct cache_file_new )) )
        {
            cache->file.new = (void *)cache->mmap + offset;

            // this is the probe: as in the pervious if block, except
            // that if we don't find a new cache it's not an error,
            // it just means we're in an old style cache:
            if( memcmp( cache->file.new->magic, CACHEMAGIC_NEW,
                        sizeof(CACHEMAGIC_NEW) - 1 ) ||
                memcmp( cache->file.new->version, CACHE_VERSION,
                        sizeof(CACHE_VERSION) - 1) )
            {
                // nope, no encapsulated new cache:
                cache->file.old = cache->mmap;
            }
            else
            {
                DEBUG( DEBUG_LDCACHE, "... with a new style cache inside" );
                cache->type = CACHE_NEW;
                cache->data = (char *)cache->file.new;
            }
        }
    }

    DEBUG( DEBUG_LDCACHE, "Opened ld.cache at %s", path );
    return 1;

cleanup:
    DEBUG( DEBUG_LDCACHE, "Failed to open ld.cache at %s", path );
    ld_cache_close( cache );
    return 0;
}

// iterate over the entries in the ld cache, invoking callback cb on each one
// until eithe the callback returns true or we run out of entries.
// if the callback terminates iteration by returning true, return that value,
// otherwise return false:
intptr_t
ld_cache_foreach (ldcache_t *cache, ld_cache_entry_cb cb, void *data)
{
    int rval = 0;
    const char *base = cache->data;

    switch( cache->type )
    {
      case CACHE_OLD:
        for (int i = 0; !rval && (i < cache->file.old->nlibs); i++)
        {
            struct file_entry *f = &cache->file.old->libs[i];
            rval = cb( base + f->key, f->flags, 0, 0, base + f->value, data );
        }
        break;

      case CACHE_NEW:
        for (int i = 0; !rval && (i < cache->file.new->nlibs); i++)
        {
            struct file_entry_new *f = &cache->file.new->libs[i];
            rval = cb( base + f->key, f->flags,
                       f->osversion, f->hwcap, base + f->value, data );
        }
        break;

      default:
        fprintf( stderr, "Invalid ld cache type %d", cache->type );
        break;
    }

    return rval;
}

intptr_t
ld_entry_dump (const char *name,
               int flag,
               unsigned int osv,
               uint64_t hwcap,
               const char *path,
               void *data)
{
    FILE *stream = (FILE *)data;
    fprintf( stream, "%s → %s\n", name, path );

    fputs( "  type: ", stream );
    switch (flag & FLAG_TYPE_MASK)
    {
      case FLAG_LIBC4:
      case FLAG_ELF:
      case FLAG_ELF_LIBC5:
      case FLAG_ELF_LIBC6:
        fputs( flag_descr[flag & FLAG_TYPE_MASK], stream );
        break;
      default:
        fputs( "???", stdout );
        break;
    }
    fputs( "\n", stream );

    fputs( "  requires: ", stream );
    switch (flag & FLAG_REQUIRED_MASK)
    {
      case FLAG_SPARC_LIB64:
        fputs( "Sparc 64bit", stream );
        break;
      case FLAG_IA64_LIB64:
        fputs( "IA-64", stream );
        break;
      case FLAG_X8664_LIB64:
        fputs( "x86-64", stream );
        break;
      case FLAG_S390_LIB64:
        fputs( "s390 64bit", stream );
        break;
      case FLAG_POWERPC_LIB64:
        fputs( "PPC 64bit", stream );
        break;
      case FLAG_MIPS64_LIBN32:
        fputs( "MIPS N32", stream );
        break;
      case FLAG_MIPS64_LIBN64:
        fputs( "MIPS 64bit", stream );
        break;
      case FLAG_X8664_LIBX32:
        fputs( "x32", stream );
        break;
      case FLAG_ARM_LIBHF:
        fputs( "Arm hard-float", stream );
        break;
      case FLAG_AARCH64_LIB64:
        fputs( "AArch64", stream );
        break;
        /* Uses the ARM soft-float ABI.  */
      case FLAG_ARM_LIBSF:
        fputs( "Arm soft-float", stream );
        break;
      case FLAG_MIPS_LIB32_NAN2008:
        fputs( "MIPS nan2008", stream );
      break;
      case FLAG_MIPS64_LIBN32_NAN2008:
        fputs( "MIPS N32 nan2008", stream );
        break;
      case FLAG_MIPS64_LIBN64_NAN2008:
        fputs( "IPS 64bit nan2008", stream );
        break;
      case 0:
        break;
      default:
        fprintf (stream, "%0x", flag & FLAG_REQUIRED_MASK);
        break;
    }
    fputs( "\n", stream );

    unsigned int os = osv >> 24;

    fprintf( stream, "  OS ABI: %s %d.%d.%d (%0x)\n",
             abi_tag_os[ os > MAXTAG ? MAXTAG : os ],
             (osv >> 16) & 0xff,
             (osv >> 8 ) & 0xff,
             osv & 0xff,
             osv );

    fprintf( stream, "  hwcaps: %0"FMT_XU64"\n", hwcap );
    return 0;
}
