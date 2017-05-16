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

#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <link.h>
#include "mmap-info.h"

// these macros are secretly the same for elf32 & elf64:
#define ELFW_ST_TYPE(a)       ELF32_ST_TYPE(a)
#define ELFW_ST_BIND(a)       ELF32_ST_BIND(a)
#define ELFW_ST_VISIBILITY(a) ELF32_ST_VISIBILITY(a)

typedef struct
{
    const char *target; // name of shim DSO to have its symbols relocated
    capsule_item_t *relocs;
    struct { int success; int failure; } count;
    int debug;
    char *error;
    mmapinfo_t *mmap_info;
} relocation_data_t;

typedef int (*relocate_cb_t)(const void *start,
                             const int relasz,
                             const char *strtab,
                             const void *symtab,
                             ElfW(Addr)  base,
                             void *data);

int process_dt_rela (const void *start,
                     const int relasz,
                     const char *strtab,
                     const void *symtab,
                     ElfW(Addr)  base,
                     void *data);

int process_dt_rel  (const void *start,
                     const int relasz,
                     const char *strtab,
                     const void *symtab,
                     ElfW(Addr)  base,
                     void *data);

int process_pt_dynamic (void *start,
                        size_t size,
                        ElfW(Addr) base,
                        relocate_cb_t process_rela,
                        relocate_cb_t process_rel,
                        void *data);
