#pragma once

#include <limits.h>
#include <libelf.h>
#include <gelf.h>

#include "ld-cache.h"

// we only handle up to this many library dependencies -
// yes, hardwired limits are bad but there's already enough complexity
// here - can revisit this decision if it ever becomes close to being
// an issue (shouldn't affect the api or abi):
#define DSO_LIMIT 256

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
    ldcache_t ldcache;
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
} ld_libs_t;

int   ld_libs_init (ld_libs_t *ldlibs,
                    const char **exclude,
                    const char *prefix,
                    unsigned long dbg,
                    int *error);

int   ld_libs_set_target        (ld_libs_t *ldlibs, const char *target);
int   ld_libs_find_dependencies (ld_libs_t *ldlibs);
void  ld_libs_finish            (ld_libs_t *ldlibs);

void *ld_libs_load (ld_libs_t *ldlibs, Lmid_t *namespace, int flag, int *error);
