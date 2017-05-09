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

#include <link.h>

typedef struct
{
    const char *name;
    ElfW(Addr) shim;
    ElfW(Addr) real;
} capsule_item_t;

int capsule_relocate (const char *target,
                      void *source,
                      int debug,
                      capsule_item_t *relocations,
                      char **error);

void *capsule_dlmopen (const char *dso,
                       const char *prefix,
                       Lmid_t *namespace,
                       capsule_item_t *wrappers,
                       int debug,
                       const char **exclude,
                       int *errcode,
                       char **error);

void *capsule_shim_dlopen(void *handle,
                          Lmid_t ns,
                          const char *prefix,
                          const char **exclude,
                          const char *file,
                          int flag);
