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

#include "capsule/capsule.h"
#include "utils.h"
#include "process-pt-dynamic.h"
#include "mmap-info.h"

static void *
#if __ELF_NATIVE_CLASS == 32
addr (ElfW(Addr) base, ElfW(Addr) ptr, ElfW(Sword) addend)
#elif __ELF_NATIVE_CLASS == 64
addr (ElfW(Addr) base, ElfW(Addr) ptr, ElfW(Sxword) addend)
#else
#error "Unsupported __ELF_NATIVE_CLASS size (not 32 or 64)"
#endif
{
    if( (ptr + addend) > base )
        return (void *)(ptr + addend);
    else
        return (void *)(base + ptr + addend);
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

// find a sub-entry of a given DT_* type and return its d_val field:
static int
find_value (ElfW(Addr) base, void *start, size_t size, int what)
{
    const ElfW(Dyn) *entry = find_dyn( base, start, size, what );
    return entry ? entry->d_un.d_val : -1;
}

// find a sub-entry of a given DT_* type and return its d_ptr field:
#if 0
static void *
find_ptr (ElfW(Addr) base, void *start, size_t size, int what)
{
    const ElfW(Dyn) *entry = find_dyn( base, start, size, what );
    return entry ? (void *)entry->d_un.d_ptr : NULL;
}
#endif

static const char *
find_strtab (ElfW(Addr) base, void *start, size_t size, int *siz)
{
    ElfW(Dyn) *entry;

    const char *tab = NULL;

    for( entry = start + base;
         (entry->d_tag != DT_NULL) &&
           ((size == 0) || ((void *)entry < (start + base + size)));
         entry++ )
    {
        if( entry->d_tag == DT_STRTAB )
        {
            tab  = (char *)addr(base, entry->d_un.d_ptr, 0);
        }
        else if( entry->d_tag == DT_STRSZ  )
        {
            *siz = entry->d_un.d_val;
        }
    }

    return tab;
}

static const ElfW(Sym) *
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

int
try_relocation (ElfW(Addr) *reloc_addr, const char *name, void *data)
{
    capsule_item *map;
    relocation_data_t *rdata = data;

    if( !name || !*name || !reloc_addr )
        return 0;

    for( map = rdata->relocs; map->name; map++ )
    {
        if( strcmp( name, map->name ) )
            continue;

        DEBUG( DEBUG_RELOCS,
               "relocation for %s (%p->{ %p }, %p, %p)",
               name, reloc_addr, NULL, (void *)map->shim, (void *)map->real );

        // couldn't look up the address of the shim function. buh?
        if( !map->shim )
            return 1;

        // sought after symbols is not available in the private namespace
        if( !map->real )
        {
            rdata->count.failure++;
            DEBUG( DEBUG_RELOCS, "--failed" );

            return 1;
        }

        // our work here is already done, apparently
        if( *reloc_addr == map->real )
            return 0;
        // ======================================================================
        // exegesis:

        // linking goes like this: we start with a PLT entry pointing at the
        // 'trampoline' entry which patches up the relocations. The first
        // time we call a function, we go to the PLT which sends us to the
        // trampoline, which  finds the shim (in the case of our proxy library)
        // or the real address (in the case of a normal library) and pastes that
        // address into the PLT.

        // This function scribbles over the trampoline address with the real
        // address, thus bypassing the trampoline _and_ the shim permanently.

        /// IOW the 0th, 1st and second function calls normally look like this:
        // 0: function-call → PLT → trampoline : (PLT ← address) → address
        // 1: function-call → PLT → address
        // 2: ibid

        // If we are already pointing to the shim instead of the trampoline
        // that indicates we have RELRO linking - the linker has already resolved
        // the address to the shim (as it doesn't know about the real address
        // which is hidden inside the capsule).

        // -1: linker → function-lookup : (PLT ← address)
        //  0: function-call → PLT → address
        //  1: ibid

        // but⁰ RELRO linking also mprotect()s the relevant pages to be read-only
        // which prevents us from overwriting the address.

        // but¹ we are smarter than the average bear, and we tried to harvest
        // the mprotect info: If we did, then we will already have toggled the
        // write permission on everything that didn't have it and can proceed
        // (we're also not savages, so we'll put those permissions back later)

        // however, if we don't have any mprotect into for this relocation entry,
        // then we can't de-shim the RELROd PLT entry, and it's sad 🐼 time.
        // ======================================================================
        if( (*reloc_addr == map->shim) &&
            !find_mmap_info(rdata->mmap_info, reloc_addr) )
        {
            DEBUG( DEBUG_RELOCS|DEBUG_MPROTECT,
                   " ERROR: cannot update relocation record for %s", name );
            return 1; // FIXME - already shimmed, can't seem to override?
        }

        *reloc_addr = map->real;
        rdata->count.success++;
        DEBUG( DEBUG_RELOCS, "--relocated" );
        return 0;
    }

    // nothing to relocate
    return 0;
}

#define DUMP_SLOTINFO(n,x) \
    DEBUG(DEBUG_ELF, "%s has slot type %s (%d)", n, #x, x)

int
process_dt_rela (const void *start,
                 int relasz,
                 const char *strtab,
                 const void *symtab,
                 ElfW(Addr)  base,
                 void *data)
{
    ElfW(Rela) *entry;

    for( entry = (ElfW(Rela) *)start;
         entry < (ElfW(Rela) *)(start + relasz);
         entry++ )
    {
        int sym;
        int chr;
        char *name = NULL;
        const ElfW(Sym) *symbol;

#if __ELF_NATIVE_CLASS == 32
        sym = ELF32_R_SYM (entry->r_info);
        chr = ELF32_R_TYPE(entry->r_info);
#elif __ELF_NATIVE_CLASS == 64
        sym = ELF64_R_SYM (entry->r_info);
        chr = ELF64_R_TYPE(entry->r_info);
#else
        fprintf( stderr, "__ELF_NATIVE_CLASS is neither 32 nor 64" );
        exit( 22 );
#endif

        DEBUG( DEBUG_ELF, "RELA entry at %p", entry );

        symbol = find_symbol( sym, symtab, strtab, &name );

        DEBUG( DEBUG_ELF,
               "symbol %p; name: %p:%s", symbol, name, name ? name : "-" );

        if( !symbol || !name || !*name )
            continue;

        switch( chr )
        {
            void *slot;

       // case R_386_JMP_SLOT:  // these are secretly the same:
          case R_X86_64_JUMP_SLOT:
            slot = addr( base, entry->r_offset, entry->r_addend );
            DEBUG( DEBUG_ELF,
                   "R_X86_64_JUMP_SLOT: %p ← { offset: %"FMT_ADDR"; addend: %"FMT_SIZE" }",
                   slot, entry->r_offset, entry->r_addend );
            try_relocation( slot, name, data );
            break;
          case R_X86_64_NONE:
            DUMP_SLOTINFO(name, R_X86_64_NONE);
            break;
          case R_X86_64_64:
            DUMP_SLOTINFO(name, R_X86_64_64);
            break;
          case R_X86_64_PC32:
            DUMP_SLOTINFO(name, R_X86_64_PC32);
            break;
          case R_X86_64_GOT32:
            DUMP_SLOTINFO(name, R_X86_64_GOT32);
            break;
          case R_X86_64_PLT32:
            DUMP_SLOTINFO(name, R_X86_64_PLT32);
            break;
          case R_X86_64_COPY:
            DUMP_SLOTINFO(name, R_X86_64_COPY);
            break;
          case R_X86_64_GLOB_DAT:
            DUMP_SLOTINFO(name, R_X86_64_GLOB_DAT);
            break;
          case R_X86_64_RELATIVE:
            DUMP_SLOTINFO(name, R_X86_64_RELATIVE);
            break;
          case R_X86_64_GOTPCREL:
            DUMP_SLOTINFO(name, R_X86_64_GOTPCREL);
            break;
          case R_X86_64_32:
            DUMP_SLOTINFO(name, R_X86_64_32);
            break;
          case R_X86_64_32S:
            DUMP_SLOTINFO(name, R_X86_64_32S);
            break;
          case R_X86_64_16:
            DUMP_SLOTINFO(name, R_X86_64_16);
            break;
          case R_X86_64_PC16:
            DUMP_SLOTINFO(name, R_X86_64_PC16);
            break;
          case R_X86_64_8:
            DUMP_SLOTINFO(name, R_X86_64_8);
            break;
          case R_X86_64_PC8:
            DUMP_SLOTINFO(name, R_X86_64_PC8);
            break;
          case R_X86_64_DTPMOD64:
            DUMP_SLOTINFO(name, R_X86_64_DTPMOD64);
            break;
          case R_X86_64_DTPOFF64:
            DUMP_SLOTINFO(name, R_X86_64_DTPOFF64);
            break;
          case R_X86_64_TPOFF64:
            DUMP_SLOTINFO(name, R_X86_64_TPOFF64);
            break;
          case R_X86_64_TLSGD:
            DUMP_SLOTINFO(name, R_X86_64_TLSGD);
            break;
          case R_X86_64_TLSLD:
            DUMP_SLOTINFO(name, R_X86_64_TLSLD);
            break;
          case R_X86_64_DTPOFF32:
            DUMP_SLOTINFO(name, R_X86_64_DTPOFF32);
            break;
          case R_X86_64_GOTTPOFF:
            DUMP_SLOTINFO(name, R_X86_64_GOTTPOFF);
            break;
          case R_X86_64_TPOFF32:
            DUMP_SLOTINFO(name, R_X86_64_TPOFF32);
            break;
          case R_X86_64_PC64:
            DUMP_SLOTINFO(name, R_X86_64_PC64);
            break;
          case R_X86_64_GOTOFF64:
            DUMP_SLOTINFO(name, R_X86_64_GOTOFF64);
            break;
          case R_X86_64_GOTPC32:
            DUMP_SLOTINFO(name, R_X86_64_GOTPC32);
            break;
          case R_X86_64_GOT64:
            DUMP_SLOTINFO(name, R_X86_64_GOT64);
            break;
          case R_X86_64_GOTPCREL64:
            DUMP_SLOTINFO(name, R_X86_64_GOTPCREL64);
            break;
          case R_X86_64_GOTPC64:
            DUMP_SLOTINFO(name, R_X86_64_GOTPC64);
            break;
          case R_X86_64_GOTPLT64:
            DUMP_SLOTINFO(name, R_X86_64_GOTPLT64);
            break;
          case R_X86_64_PLTOFF64:
            DUMP_SLOTINFO(name, R_X86_64_PLTOFF64);
            break;
          case R_X86_64_SIZE32:
            DUMP_SLOTINFO(name, R_X86_64_SIZE32);
            break;
          case R_X86_64_SIZE64:
            DUMP_SLOTINFO(name, R_X86_64_SIZE64);
            break;
          case R_X86_64_GOTPC32_TLSDESC:
            DUMP_SLOTINFO(name, R_X86_64_GOTPC32_TLSDESC);
            break;
          case R_X86_64_TLSDESC_CALL:
            DUMP_SLOTINFO(name, R_X86_64_TLSDESC_CALL);
            break;
          case R_X86_64_TLSDESC:
            DUMP_SLOTINFO(name, R_X86_64_TLSDESC);
            break;
          case R_X86_64_IRELATIVE:
            DUMP_SLOTINFO(name, R_X86_64_IRELATIVE);
            break;
          case R_X86_64_RELATIVE64:
            DUMP_SLOTINFO(name, R_X86_64_RELATIVE64);
            break;
          default:
            DUMP_SLOTINFO(name, chr);
        }
    }

    return 0;
}

int
process_dt_rel (const void *start,
                int relasz,
                const char *strtab,
                const void *symtab,
                ElfW(Addr)  base,
                void *data)
{
    ElfW(Rel) *entry;

    for( entry = (ElfW(Rel) *)start;
         entry < (ElfW(Rel) *)(start + relasz);
         entry++ )
    {
        int sym;
        int chr;
        char *name;

        const ElfW(Sym) *symbol;

#if __ELF_NATIVE_CLASS == 32
        sym = ELF32_R_SYM (entry->r_info);
        chr = ELF32_R_TYPE(entry->r_info);
#elif __ELF_NATIVE_CLASS == 64
        sym = ELF64_R_SYM (entry->r_info);
        chr = ELF64_R_TYPE(entry->r_info);
#else
        fprintf( stderr, "__ELF_NATIVE_CLASS is neither 32 nor 64" );
        exit( 22 );
#endif

        symbol = find_symbol( sym, symtab, strtab, &name );

        if( !symbol || !name || !*name )
            continue;

        switch( chr )
        {
            void *slot;

       // case R_386_JMP_SLOT: secretly the same
          case R_X86_64_JUMP_SLOT:
            slot = addr( base, entry->r_offset, 0 );
            try_relocation( slot, name, data );
            break;
        }
    }

    return 0;
}

int
process_pt_dynamic (void *start,
                    size_t size,
                    ElfW(Addr) base,
                    relocate_cb_t process_rela,
                    relocate_cb_t process_rel,
                    void *data)
{
    int ret = 0;
    ElfW(Dyn) *entry;

    int strsiz     = -1;
    int relasz     = -1;
    int jmprelsz   = -1;
    int jmpreltype = DT_NULL;
    void *relstart;
    const void *symtab = NULL;
    const char *strtab = find_strtab( base, start, size, &strsiz );

    DEBUG( DEBUG_ELF,
           "start: %p; size: %"FMT_SIZE"; base: %p; handlers: %p %p; …",
           start, size, (void *)base, process_rela, process_rel );
    DEBUG( DEBUG_ELF, "dyn entry: %p", start + base );

    DEBUG( DEBUG_ELF,
           "strtab is at %p: %s%s", strtab, strtab, strtab ? "…" : "");

    for( entry = start + base;
         (entry->d_tag != DT_NULL) &&
           ((size == 0) || ((void *)entry < (start + base + size)));
         entry++ )
        switch( entry->d_tag )
        {
          case DT_PLTRELSZ:
            jmprelsz = entry->d_un.d_val;
            DEBUG( DEBUG_ELF, "jmprelsz is %d", jmprelsz );
            break;

          case DT_SYMTAB:
            symtab = addr( base, entry->d_un.d_ptr, 0 );
            DEBUG( DEBUG_ELF, "symtab is %p", symtab );
            break;

          case DT_RELA:
            if( process_rela != NULL )
            {
                DEBUG( DEBUG_ELF, "processing DT_RELA section" );
                if( relasz == -1 )
                    relasz = find_value( base, start, size, DT_RELASZ );
                relstart = addr( base, entry->d_un.d_ptr, 0 );
                process_rela( relstart, relasz, strtab, symtab, base, data );
            }
            else
            {
                DEBUG( DEBUG_ELF|DEBUG_RELOCS,
                       "skipping DT_RELA section: no handler" );
            }
            break;

          case DT_RELASZ:
            relasz = entry->d_un.d_val;
            DEBUG( DEBUG_ELF, "relasz is %d", relasz );
            break;

          case DT_PLTREL:
            jmpreltype = entry->d_un.d_val;
            DEBUG( DEBUG_ELF, "jmpreltype is %d : %s", jmpreltype,
                   jmpreltype == DT_REL  ? "DT_REL"  :
                   jmpreltype == DT_RELA ? "DT_RELA" : "???" );
            break;

          case DT_JMPREL:
            if( jmprelsz == -1 )
                jmprelsz = find_value( base, start, size, DT_PLTRELSZ );
            if( jmpreltype == DT_NULL )
                jmpreltype = find_value( base, start, size, DT_PLTREL );

            switch( jmpreltype )
            {
              case DT_REL:
                if( process_rel != NULL )
                {
                    DEBUG( DEBUG_ELF|DEBUG_RELOCS,
                           "processing DT_JMPREL/DT_REL section" );
                    relstart = addr( base, entry->d_un.d_ptr, 0 );
                    DEBUG( DEBUG_ELF, "  -> REL antry #0 at %p", relstart );
                    ret = process_rel( relstart, jmprelsz, strtab,
                                       symtab, base, data );
                }
                else
                {
                    DEBUG( DEBUG_ELF|DEBUG_RELOCS,
                           "skipping DT_JMPREL/DT_REL section: no handler" );
                }
                break;

              case DT_RELA:
                if( process_rela != NULL )
                {
                    DEBUG( DEBUG_ELF,
                           "processing DT_JMPREL/DT_RELA section" );
                    relstart = addr( base, entry->d_un.d_ptr, 0 );
                    ret = process_rela( relstart, jmprelsz, strtab,
                                        symtab, base, data );
                }
                else
                {
                    DEBUG( DEBUG_ELF,
                           "skipping DT_JMPREL/DT_RELA section: no handler" );
                }
                break;

              default:
                DEBUG( DEBUG_RELOCS|DEBUG_ELF,
                       "Unknown DT_PLTREL value: %d (expected %d or %d)",
                       jmpreltype, DT_REL, DT_RELA );
                ret = 1;
                break;
            }
        }

    return ret;
}

