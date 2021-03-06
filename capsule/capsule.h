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

/**
 * capsule_addr:
 *
 * Identical to an ElfW(Addr) from libelf. You may treat this as
 * equivalent to a void * when assigning to it.
 */
typedef ElfW(Addr) capsule_addr;

/**
 * capsule_item:
 * @name: The name of the symbol to be relocated
 * @shim: address of the ‘fake’ symbol in the proxy library
 * @real: address of the ‘real’ symbol in the target library
 *
 * @shim may typically be left empty in calls to capsule_dlmopen()
 * and capsule_relocate().
 *
 * @real may also be left empty in calls to capsule_relocate()
 *
 * Both slots will typically hold the correct values after a successful
 * capsule… call. While this is sometimes important internally it is
 * not usually of interest to the caller (except maybe for debugging)
 */
typedef struct _capsule_item capsule_item;

struct _capsule_item
{
    const char *name;
    capsule_addr real;
    capsule_addr shim;

    /*< private >*/
    void *unused0;
    void *unused1;
    void *unused2;
    void *unused3;
};

/**
 * capsule_init:
 *
 * Does any initialisation necessary to use libcapsule's functions.
 * Currently just initialises the debug flags from the CAPSULE_DEBUG
 * environment variable.
 */
void capsule_init (void);

/**
 * capsule_relocate:
 * @target: The DSO from which to export symbols (currently unused)
 * @source: The dl handle from which to export symbols
 * @debug: Internal debug flag. Pass 0 here.
 * @relocations: Array of capsule_item specifying which symbols to export
 * @error: location in which to store an error string on failure
 *
 * Returns: 0 on success, non-zero on failure.
 *
 * @source is typically the value returned by a successful capsule_dlmopen()
 * call (although a handle returned by dlmopen() would also be reasonable).
 *
 * The #capsule_item entries in @relocations need only specify the symbol
 * name: The shim and real fields will be populated automatically if they
 * are not pre-filled (this is the normal use case, as it would be unusual
 * to know these value in advance).
 *
 * In the unlikely event that an error message is returned in @error it is the
 * caller's responsibility to free() it.
 */
int capsule_relocate (const char *target,
                      void *source,
                      unsigned long debug,
                      capsule_item *relocations,
                      char **error);

/**
 * capsule_dlmopen:
 * @dso: The name of the DSO to open (cf dlopen()) - eg libGL.so.1
 * @prefix: The location of the foreign tree in which @dso should be found
 * @namespace: Address of an #Lmid_t value (usually %LM_ID_NEWLM)
 * @wrappers: Array of #capsule_item used to replace symbols in the namespace
 * @debug: Internal debug flags. Pass 0 here.
 * @exclude: an array of char *, each specfying a DSO not to load
 * @errcode: location in which to store the error code on failure
 * @error: location in which to store an error message on failure
 *
 * Returns: A (void *) DSO handle, as per dlopen(3), or %NULL on error
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
                       capsule_item *wrappers,
                       unsigned long debug,
                       const char **exclude,
                       int *errcode,
                       char **error);

/**
 * capsule_shim_dlopen:
 * @ns: An #Lmid_t value giving the namespace in which to operate
 * @prefix: the mount point of the foreign tree in wich to find DSOs
 * @exclude: Array of DSO names to ignore
 * @file: base name of the target DSO (eg libz.so.1)
 * @flag: dlopen() flags to pass to the real dlmopen() call
 *
 * Returns: a void * dl handle (cf dlopen())
 *
 * This helper function exists because dlopen() cannot safely be called
 * by a DSO opened into a private namespace. It takes @file and @flag
 * arguments (cf dlopen()) and @prefix, @exclude, and @namespace arguments
 * (cf capsule_dlmopen(), although namespace is an #Lmid_t and not a pointer
 * to one as in capsule_dlmopen()) and performs a safe dlmopen() call instead,
 *  respecting the same restrictions as capsule_dlmopen().
 *
 * Typically this function is used to implement a safe wrapper for dlopen()
 * which is passed via the wrappers argument to capsule_dlmopen(). This
 * replaces calls to dlopen() by all DSOs in the capsule produced by
 * capsule_dlmopen(), allowing libraries which use dlopen() to work inside
 * the capsule.
 *
 * Limitations: RTLD_GLOBAL is not supported in @flag. This is a glibc
 * limitation in the dlmopen() implementation.
 */
void *capsule_shim_dlopen(Lmid_t ns,
                          const char *prefix,
                          const char **exclude,
                          const char *file,
                          int flag);

/**
 * capsule_shim_dlsym:
 * @capsule: A dl handle as returned by capsule_dlmopen()
 * @handle: A dl handle, as passed to dlsym()
 * @symbol: A symbol name, as passed to dlsym()
 * @exported: An array of DSO names considered to ba valid symbol sources
 *
 * Returns: a void * symbol address (cf dlsym())
 *
 * Some libraries have a use pattern in which their caller/user
 * uses dlsym() to obtain symbols rather than using those symbols
 * directly in its own code (libGL is an example of this).
 *
 * Since the target library may have a different symbol set than the
 * one the libcapsule proxy shim was generated from we can't rely on
 * dlsym() finding those symbols in the shim's symbol table.
 *
 * Instead we must intercept dlsym() calls made outside the capsule
 * and attempt to look for the required symbol in the namespace defined
 * by @capsule first - If the required symbol is found there AND is
 * from one of the DSO names present in @exported then that symbol is
 * returned. If either of those conditions is not met then a normal
 * dlsym call with the passed handle is made.
 *
 * This function provides the functionality described above, and is
 * intended for use in a suitable wrapper implemented in the the shim
 * library.
 */
void *
capsule_shim_dlsym (void *capsule,
                    void *handle,
                    const char *symbol,
                    const char **exported);
