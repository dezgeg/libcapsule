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

#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>

#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>

#include <link.h>

// these macros are secretly the same for elf32 & elf64:
#define ELFW_ST_TYPE(a)       ELF32_ST_TYPE(a)
#define ELFW_ST_BIND(a)       ELF32_ST_BIND(a)
#define ELFW_ST_VISIBILITY(a) ELF32_ST_VISIBILITY(a)

// given a symbol in DT_SYMTAB at index 𝒊, jump to its
// entry in DT_VERSYM (also at offset 𝒊 for an array of ElfW(Versym))
// and extract its value 𝒗𝒔 (a number). The corresponding DT_VERDEF entry
// (ElfW(Verdef)) is the one whose vd_ndx member == 𝒗𝒔 & 0x7fff
//
// NOTE: if 𝒗𝒔 & 0x8000 then the version is the default or base version
// of the symbol, which should be used if the requestor has not specified
// a version for this symbol
//
// NOTE: in practice the vd_ndx member is the 1-based array position in
// the DT_VERDEF array, but the linker/elfutils code does not rely on
// this, so neither do we.
//
// next we check that the vd_flags member in the DT_VERDEF entry does not
// contain VER_FLG_BASE, as that is the DT_VERDEF entry for the entire DSO
// and must not be used as a symbol version (this should never happen:
// the spec does not allow it, but it's not physically impossible).
//
// if we have a valid DT_VERDEF entry the ElfW(Verdaux) array entry at offset
// vd_aux (from the address of the DT_VERDEF entry itself) will give
// the address of an ElfW(Verdaux) struct whose vda_name entry points
// to (𝑓𝑖𝑛𝑎𝑙𝑙𝑦) an offset into the DT_STRTAB which gives the version name.
//
// And that's how symbol version lookup works, as near as I can tell.
static void
symbol_version ( ElfW(Sym) *symbol,
                 int i,
                 const char *strtab,
                 const ElfW(Versym) *versym,
                 const void *verdef,
                 const int verdefnum,
                 int *default_version,
                 const char **version,
                 ElfW(Versym) *vs)
{
    *default_version = 0;
    *version = NULL;

    if( versym == NULL )
        return;

    switch( symbol->st_shndx )
    {
      case SHN_UNDEF:
      case SHN_ABS:
      case SHN_COMMON:
      case SHN_BEFORE:
      case SHN_AFTER:
      case SHN_XINDEX:
        // none of these are handled (and we're very unlikely to need to)
        break;

      default:
        if( symbol->st_shndx < SHN_LORESERVE )
        {
            const char  *vd = verdef;
            *vs = *(versym + i);

            for( int x = 0; x < verdefnum; x++ )
            {
                ElfW(Verdef) *entry = (ElfW(Verdef) *) vd;

                if( entry->vd_ndx == (*vs & 0x7fff) )
                {
                    const char *au;

                    if( entry->vd_flags & VER_FLG_BASE )
                        break;

                    au = vd + entry->vd_aux;
                    ElfW(Verdaux) *aux = (ElfW(Verdaux) *) au;
                    *version = strtab + aux->vda_name;
                    *default_version = (*vs & 0x8000) ? 0 : 1;
                }

                vd = vd + entry->vd_next;
            }
        }
    }
}


int symbol_excluded (const char *name)
{
    if( !strcmp(name, "_init") ||
        !strcmp(name, "_fini") )
        return 1;

    return 0;
}

static void
parse_symtab (const void *start,
              const char *strtab,
              const ElfW(Versym) *versym,
              const void *verdef,
              const int verdefnum)
{
    int x = 0;
    ElfW(Sym) *entry;

    for( entry = (ElfW(Sym) *)start;
         ( (ELFW_ST_TYPE(entry->st_info) < STT_NUM) &&
           (ELFW_ST_BIND(entry->st_info) < STB_NUM) );
         entry++, x++ )
    {
        int defversym = 0;
        const char *version = NULL;
        ElfW(Versym) vs = 0;

        switch( ELFW_ST_TYPE(entry->st_info) )
        {
          case STT_FUNC:
          case STT_OBJECT:
            symbol_version( entry, x, strtab, versym, verdef, verdefnum,
                            &defversym, &version, &vs );

            if( !vs )
                continue;

            if( symbol_excluded(strtab + entry->st_name) )
                continue;

            fprintf( stdout, "%s %s%s%s\n",
                     strtab + entry->st_name  ,
                     version   ? "@"     : "" ,
                     defversym ? "@"     : "" ,
                     version   ? version : "" );
            break;
        }
    }
}

void *
addr (ElfW(Addr) base, ElfW(Addr) ptr)
{
    if( ptr > base )
        return (void *)ptr;
    else
        return (void *)(base + ptr);
}

static const ElfW(Dyn) *
find_dyn (ElfW(Addr) base, void *start, size_t size, int what)
{
    ElfW(Dyn) *entry = start + base;
    void *limit = start + base + size;

    for( ; (entry->d_tag != DT_NULL) && ((void *)entry < limit); entry++ )
        if( entry->d_tag == what )
            return entry;

    return NULL;
}

int
find_value (ElfW(Addr) base, void *start, size_t size, int what)
{
    const ElfW(Dyn) *entry = find_dyn( base, start, size, what );
    return entry ? entry->d_un.d_val : -1;
}

ElfW(Addr)
find_ptr (ElfW(Addr) base, void *start, size_t size, int what)
{
    const ElfW(Dyn) *entry = find_dyn( base, start, size, what );
    return entry ? entry->d_un.d_ptr : (ElfW(Addr)) NULL;
}


const ElfW(Sym) *
find_symbol (int idx, const ElfW(Sym) *stab, const char *str, char **name)
{
    ElfW(Sym) *entry;
    ElfW(Sym) *target = (ElfW(Sym) *)stab + idx;

    if( idx < 0 )
        return NULL;

    // we could just accept the index as legitimate but then we'd
    // run the risk of popping off into an unknown hyperspace coordinate
    // this way we stop if the target is past the known end of the table:
    for( entry = (ElfW(Sym) *)stab;
         ( (ELFW_ST_TYPE(entry->st_info) < STT_NUM) &&
           (ELFW_ST_BIND(entry->st_info) < STB_NUM) );
         entry++ )
    {
        if( entry == target )
        {
            if( name )
                *name = (char *)str + entry->st_name;
            return target;
        }
    }

    return NULL;
}

const char *
find_strtab (ElfW(Addr) base, void *start, size_t size, int *siz)
{
    ElfW(Dyn) *entry;

    const char *tab = NULL;

    for( entry = start + base;
         (entry->d_tag != DT_NULL) && ((void *)entry < (start + base + size));
         entry++ )
    {
        if( entry->d_tag == DT_STRTAB )
        {
            tab  = (char *)addr(base, entry->d_un.d_ptr);
        }
        else if( entry->d_tag == DT_STRSZ  )
        {
            *siz = entry->d_un.d_val;
        }
    }

    return tab;
}

static void
parse_dynamic (void *start, size_t size, ElfW(Addr) base)
{
    ElfW(Dyn) *entry;

    int strsiz     = -1;
    int verdefnum  = -1;

    const void *symtab = NULL;
    const void *versym = NULL;
    const void *verdef = NULL;
    const char *strtab = find_strtab( base, start, size, &strsiz );

    for( entry = start + base;
         (entry->d_tag != DT_NULL) && ((void *)entry < (start + base + size));
         entry++ )
    {
        switch( entry->d_tag )
        {
          case DT_SYMTAB:
            if( versym == NULL )
                versym = addr( base, find_ptr( base, start, size, DT_VERSYM ) );
            if( verdef == NULL )
                verdef = addr( base, find_ptr( base, start, size, DT_VERDEF ) );
            if( verdefnum == -1 )
                verdefnum = find_value( base, start, size, DT_VERDEFNUM );

            symtab = addr( base, entry->d_un.d_ptr );
            parse_symtab( symtab, strtab, versym, verdef, verdefnum );
            break;

          case DT_VERDEFNUM:
            verdefnum = entry->d_un.d_val;
            break;

          case DT_VERDEF:
            if( verdefnum == -1 )
                verdefnum = find_value( base, start, size, DT_VERDEFNUM );
            verdef = addr( base, entry->d_un.d_ptr );
            // parse_verdef( verdef, strtab, verdefnum );
            break;

          case DT_VERSYM:
            if( versym == NULL )
                versym = addr( base, entry->d_un.d_ptr );
            break;

          default:
            break;
        }
    }

    return;
}

static int
phdr_cb (struct dl_phdr_info *info, size_t size, void *data)
{
    int j;

    if( strstr( info->dlpi_name, (const char *)data ) == NULL )
        return 0;

    for( j = 0; j < info->dlpi_phnum; j++ )
    {
        switch(info->dlpi_phdr[j].p_type)
        {
          case PT_DYNAMIC:
            parse_dynamic((void *) info->dlpi_phdr[j].p_vaddr,
                          info->dlpi_phdr[j].p_memsz,
                          info->dlpi_addr);
            break;

          default:
            break;
        }
    }

    return 0;
}

int main (int argc, char **argv)
{
    void *handle;
    const char *libname;

    if( argc < 2 )
    {
        fprintf( stderr, "usage: %s <ELF-DSO>\n", argv[0] );
        exit( 1 );
    }

    handle = dlopen( argv[1], RTLD_NOW|RTLD_GLOBAL );

    if( !handle )
    {
        int e = errno;
        char *err = dlerror();
        fprintf( stderr, "%s: failed to open %s (%d: %s)\n",
                 argv[0], argv[1], e ? e : ENOENT, err );
        exit(e ? e : ENOENT);
    }

    if( (libname = strrchr( argv[1], '/' )) )
        libname = libname + 1;
    else
        libname = argv[1];

    dl_iterate_phdr( phdr_cb, (void *)libname );

    exit(0);
}
