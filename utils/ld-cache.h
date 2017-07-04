#pragma once

#include <sys/types.h>
#include <stdint.h>

typedef enum
{
    CACHE_NONE,
    CACHE_NEW ,
    CACHE_OLD ,
} cache_type;


// ==========================================================================
// this is stolen from the ld.so config (dl-cache.h) since we need
// to use a slightly re-brained version of the linker to do our
// filthy, filthy business (and these details are not in a shipped header)
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

typedef struct
{
    int fd;
    size_t map_size;
    struct cache_file *mmap;
    const char *data;
    union { struct cache_file *old; struct cache_file_new *new; } file;
    cache_type type;
    int is_open;
} ldcache_t;

// ==========================================================================

typedef intptr_t (*ld_cache_entry_cb) (const char *name,
                                       int flag,
                                       unsigned int osv,
                                       uint64_t hwcap,
                                       const char *path,
                                       void *data);

int      ld_cache_open    (ldcache_t *cache, const char *path);
void     ld_cache_close   (ldcache_t *cache);
intptr_t ld_cache_foreach (ldcache_t *cache, ld_cache_entry_cb cb, void *data);

intptr_t ld_entry_dump (const char *name, int flag, unsigned int osv,
                        uint64_t hwcap, const char *path, void *data);
