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

/**
 * capsule_init:
 *
 * Does any initialisation necessary to use libcapsule's functions.
 * Currently just initialises the debug flags from the CAPSULE_DEBUG
 * environment variable.
 */
void capsule_init (void);

int capsule_relocate (const char *target,
                      void *source,
                      unsigned long debug,
                      capsule_item_t *relocations,
                      char **error);

/**
 * capsule_dlmopen:
 * @dso: The name of the DSO to open (cf dlopen()) - eg libGL.so.1
 * @prefix: The location of the foreign tree in which @dso should be found
 * @namespace: Address of an #Lmid_t value (usually %LM_ID_NEWLM)
 * @wrappers: Array of #capsule_item_t used to replace symbols in the namespace
 * @debug: Internal debug flags. Pass 0 here.
 * @exclude: an array of char *, each specfying a DSO not to load
 * @errcode: location in which to store the error code on failure
 * @error: location in which to store an error message on failure
 *
 * Opens @dso (a library) from a filesystem mounted at @prefix into a
 * symbol namespace specified by @namespace, using dlmopen().
 *
 * Any symbols specified in @wrappers will be replaced with the
 * corresponding address from @wrappers (allowing you to replace
 * function definitions inside the namespace with your own).
 * This is normally used to replace calls from inside the namespace to
 * dlopen() (which would cause a segfault) with calls to dlmopen().
 *
 * The #Lmid_t valu addressed by @namespace should normally include
 * %LM_ID_NEWLM to create a new namespace. The actual namespace used
 * will be stored in @namespace after a successful call.
 *
 * If a value other than %LM_ID_NEWLM was passed in via @namespace it
 * is not expected to change (and a change would indicate a bug or
 * undefined behaviour).
 *
 * In addition to a bare libFOO.so.X style name, @dso may be an
 * absolute path (or even a relative one) and in those cases should
 * have the same effect as passing those values to dlopen(). This is
 * not a normal use case though, and has not been heavily tested.
 *
 * An empty ("") or void (%NULL) @prefix is equivalent to "/".
 */
void *capsule_dlmopen (const char *dso,
                       const char *prefix,
                       Lmid_t *namespace,
                       capsule_item_t *wrappers,
                       unsigned long debug,
                       const char **exclude,
                       int *errcode,
                       char **error);

void *capsule_shim_dlopen(Lmid_t ns,
                          const char *prefix,
                          const char **exclude,
                          const char *file,
                          int flag);
