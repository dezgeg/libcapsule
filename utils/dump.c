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

// this file is a home for the various ways of parsing the ELF layout
// of a program or library from within the executable itself, ie
// it allows the different parts of the in-memory ELF layout to be
// extracted in some useful way. not all these sections are relevant
// or useful for our eventual goals, but as this knowledge is hard
// to come by it is [literally] codified here

// these macros are secretly the same for elf32 & elf64:
#define ELFW_ST_TYPE(a)       ELF32_ST_TYPE(a)
#define ELFW_ST_BIND(a)       ELF32_ST_BIND(a)
#define ELFW_ST_VISIBILITY(a) ELF32_ST_VISIBILITY(a)

typedef enum
{
    TTYPE_VAL,
    TTYPE_PTR,
    TTYPE_STR,
} ttype;

static const char *
pt_flags (int x)
{
    static char flags[80];

    flags[sizeof(flags) - 1] = '\0';
    snprintf( flags, sizeof(flags) - 1,
              "%c%c%c [%x %x]",
              (x & PF_R) ? 'R' : '-',
              (x & PF_W) ? 'W' : '-',
              (x & PF_X) ? 'X' : '-',
              x & PF_MASKOS   ,
              x & PF_MASKPROC );

    return flags;
}

static const char *
pt_type (int x)
{
    switch (x)
    {
      case PT_NULL:         return "NULL";
      case PT_LOAD:         return "LOAD";
      case PT_DYNAMIC:      return "DYNAMIC";
      case PT_INTERP:       return "INTERP";
      case PT_NOTE:         return "NOTE";
      case PT_SHLIB:        return "SHLIB";
      case PT_PHDR:         return "PHDR";
      case PT_TLS:          return "TLS";
      case PT_NUM:          return "NUM";
      case PT_LOOS:         return "LOOS";
      case PT_GNU_EH_FRAME: return "GNU_EH_FRAME";
      case PT_GNU_STACK:    return "GNU_STACK";
      case PT_GNU_RELRO:    return "GNU_RELRO";
      case PT_SUNWBSS:      return "SUNWBSS";
      case PT_SUNWSTACK:    return "SUNWSTACK";
      case PT_HISUNW:       return "HISUNW";
      case PT_LOPROC:       return "LOPROC";
      case PT_HIPROC:       return "HIPROC";
      default:              return "-unknown-";
    };
}

static const char *
d_tag (unsigned long tag, int *tag_type)
{
    static char label[80];
    const char *rval = label;

    label[0] = '\0';
    *tag_type = TTYPE_VAL;

    switch( tag )
    {
      case DT_NULL: // Marks end of dynamic section
        rval = "NULL";
        break;

      case DT_NEEDED: // Name of needed library
        *tag_type = TTYPE_STR;
        rval = "NEEDED";
        break;

      case DT_PLTRELSZ:		// Size in bytes of PLT relocs
        rval = "PLTRELSZ";
        break;

      case DT_PLTGOT:   // Processor defined value
        *tag_type = TTYPE_PTR;
        rval = "PLTGOT";
        break;

      case DT_HASH: // Address of symbol hash table
        *tag_type = TTYPE_PTR;
        rval = "HASH";
        break;

      case DT_STRTAB: // Address of string table
        *tag_type = TTYPE_PTR;
        rval = "STRTAB";
        break;

      case DT_SYMTAB: // Address of symbol table
        *tag_type = TTYPE_PTR;
        rval = "SYMTAB";
        break;

      case DT_RELA: // Address of Rela relocs
        *tag_type = TTYPE_PTR;
        rval = "RELA";
        break;

      case DT_RELASZ:		// Total size of Rela relocs
        rval = "RELASZ";
        break;

      case DT_RELAENT: // Size of one Rela reloc
        rval = "RELAENT";
        break;

      case DT_STRSZ: // Size of string table
        rval = "STRSZ";
        break;

      case DT_SYMENT: // Size of one symbol table entry
        rval = "SYMENT";
        break;

      case DT_INIT: // Address of init function
        *tag_type = TTYPE_PTR;
        rval = "INIT";
        break;

      case DT_FINI: // Address of termination function
        *tag_type = TTYPE_PTR;
        rval = "FINI";
        break;

      case DT_SONAME: // Name of shared object
        *tag_type = TTYPE_STR;
        rval = "SONAME";
        break;

      case DT_RPATH: // Library search path (deprecated)
        *tag_type = TTYPE_STR;
        rval = "RPATH (deprecated)";
        break;

      case DT_SYMBOLIC: // Start symbol search here
        *tag_type = TTYPE_PTR;
        rval = "SYMBOLIC";
        break;

      case DT_REL: // Address of Rel relocs
        *tag_type = TTYPE_PTR;
        rval = "REL";
        break;

      case DT_RELSZ: // Total size of Rel relocs
        rval = "RELSZ";
        break;

      case DT_RELENT: // Size of one Rel reloc
        rval = "RELENT";
        break;

      case DT_PLTREL: // Type of reloc in PLT
        rval = "PLTREL";
        break;

      case DT_DEBUG: // For debugging; unspecified
        rval = "DEBUG";
        break;

      case DT_TEXTREL: // Reloc might modify .text
        rval = "TEXTREL";
        break;

      case DT_JMPREL: // Address of PLT relocs
        *tag_type = TTYPE_PTR;
        rval = "JMPREL";
        break;

      case DT_BIND_NOW: // Process relocations of object
        rval = "BIND_NOW";
        break;

      case DT_INIT_ARRAY:			// Array with addresses of init fct
        *tag_type = TTYPE_PTR;
        rval = "INIT_ARRAY";
        break;

      case DT_FINI_ARRAY: // Array with addresses of fini fct
        *tag_type = TTYPE_PTR;
        rval = "FINI_ARRAY";
        break;

      case DT_INIT_ARRAYSZ: // Size in bytes of DT_INIT_ARRAY
        rval = "INIT_ARRAYSZ";
        break;

      case DT_FINI_ARRAYSZ: // Size in bytes of DT_FINI_ARRAY
        rval = "FINI_ARRAYSZ";
        break;

      case DT_RUNPATH: // Library search path
        *tag_type = TTYPE_PTR;
        rval = "RUNPATH";
        break;

      case DT_FLAGS: // Flags for the object being loaded
        rval = "FLAGS";
        break;

      case DT_PREINIT_ARRAY:		// Array with addresses of preinit fct
        *tag_type = TTYPE_PTR;
        rval = "PREINIT_ARRAY";
        break;

      case DT_PREINIT_ARRAYSZ: // size in bytes of DT_PREINIT_ARRAY
        rval = "PREINIT_ARRAYSZ";
        break;

      case DT_NUM:          // Number used
        rval = "NUM";
        break;

      case DT_GNU_PRELINKED:
        rval = "GNU_PRELINKED"; // Prelinking timestamp
        break;

      case DT_GNU_CONFLICTSZ:
        rval = "GNU_CONFLICTSZ"; // Size of conflict section
        break;

      case DT_GNU_LIBLISTSZ:
        rval = "GNU_LIBLISTSZ"; // Size of library list
        break;

      case DT_CHECKSUM:
        rval = "CHECKSUM"; // Feature selection (DTF_*).
        break;

      case DT_POSFLAG_1:
        rval = "POSFLAG_1"; // Flags for DT_* entries, effecting the following DT_* entry.
        break;

      case DT_SYMINSZ:
        rval = "SYMINSZ"; // Size of syminfo table (in bytes)
        break;

      case DT_SYMINENT:
        rval = "SYMINENT"; // Entry size of syminfo
        break;

      case DT_GNU_HASH:
        rval = "GNU_HASH"; // GNU-style hash table.
        break;

      case DT_TLSDESC_PLT:
        rval = "TLSDESC_PLT"; // Start of conflict section
        break;

      case DT_GNU_LIBLIST:
        rval = "GNU_LIBLIST"; // Library list
        break;

      case DT_CONFIG:
        rval = "CONFIG"; // Configuration information.
        break;

      case DT_DEPAUDIT:
        rval = "DEPAUDIT"; // Dependency auditing.
        break;

      case DT_AUDIT:
        rval = "AUDIT"; // Object auditing.
        break;

      case DT_PLTPAD:
        rval = "PLTPAD"; // PLT padding.
        break;

      case DT_MOVETAB:
        rval = "MOVETAB"; // Move table.
        break;

      case DT_SYMINFO:
        rval = "SYMINFO";
        break;

      case DT_VERSYM:
        rval = "DT_VERSYM";
        *tag_type = TTYPE_PTR;
        break;

      case DT_RELACOUNT:
          rval = "RELACOUNT";
        break;

      case DT_RELCOUNT:
          rval = "DT_RELCOUNT";
        break;

      case DT_FLAGS_1:  /* State flags, see DF_1_* below.  */
        rval = "DT_FLAGS_1";
        break;

      case DT_VERDEF:  /* Address of version definition table */
        rval = "DT_VERDEF";
        break;

      case DT_VERDEFNUM:  /* Number of version definitions */
        rval = "VERDEFNUM";
        break;

      case DT_VERNEED: /* Address of table with needed versions */
        *tag_type = TTYPE_PTR;
        rval = "DT_VERNEED";
        break;

      case DT_VERNEEDNUM:
        rval = "DT_VERNEEDNUM";
        break;

      default:
        label[sizeof(label) - 1] = '\0';
        if( tag >= DT_LOOS && tag <= DT_HIOS )
            snprintf( label, sizeof(label) - 1, "OS_SPECIFIC:%lx", tag );
        else if ( tag >= DT_LOPROC && tag <= DT_HIPROC )
            snprintf( label, sizeof(label) - 1, "PROC_SPECIFIC:%lx", tag );
        else
            snprintf( label, sizeof(label) - 1, "-unknown-:%lx", tag );
        rval = &label[0];
    }

    if ( tag >= DT_ADDRRNGLO && tag <= DT_ADDRRNGHI )
        *tag_type = TTYPE_PTR;

    return rval;
}

static const char *
st_bind(int bind)
{
    switch( bind )
    {
      case STB_LOCAL:      return "LOCAL"          ; // Local symbol
      case STB_GLOBAL:     return "GLOBAL"         ; // Global symbol
      case STB_WEAK:       return "WEAK"           ; // Weak symbol
      case STB_NUM:        return "NUM"            ; // Number of defined types.
      case STB_LOOS:       return "LOOS/GNU_UNIQUE"; // Start of OS-specific
      case STB_HIOS:       return "HIOS"           ; // End of OS-specific
      case STB_LOPROC:     return "LOPROC"         ; // Start of processor-specific
      case STB_HIPROC:     return "HIPROC"         ; // End of processor-specific
      default:             return "???";
    }
}

static const char *
st_type(int type)
{
    switch( type )
    {
      case STT_NOTYPE:    return "NOTYPE"   ; // Symbol type is unspecified
      case STT_OBJECT:    return "OBJECT"   ; // Symbol is a data object
      case STT_FUNC:      return "FUNC"     ; // Symbol is a code object
      case STT_SECTION:   return "SECTION"  ; // associated with a section
      case STT_FILE:      return "FILE"     ; // Symbol's name is file name
      case STT_COMMON:    return "COMMON"   ; // common data object
      case STT_TLS:       return "TLS"      ; // thread-local data object
      case STT_NUM:       return "NUM"      ; // Number of defined types.
      case STT_LOOS:      return "LOOS/GNU_IFUNC"; // Start of OS-specific
      case STT_HIOS:      return "HIOS"     ; // End of OS-specific
      case STT_LOPROC:    return "LOPROC"   ; // Start of processor-specific
      case STT_HIPROC:    return "HIPROC"   ; // End of processor-specific
      default:            return "???";
   }
}

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

static void
dump_symtab (const char *indent,
             const void *start,
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
         entry++ )
    {
        int defversym = 0;
        const char *version = NULL;
        ElfW(Versym) vs = 0;

        symbol_version( entry, x, strtab, versym, verdef, verdefnum,
                        &defversym, &version, &vs );

        fprintf(stderr, "%s    // %02d [%-8s %-8s] size:%lu %s%s%s%s %04x %p\n",
                indent,
                x,
                st_type( ELFW_ST_TYPE(entry->st_info) ),
                st_bind( ELFW_ST_BIND(entry->st_info) ),
                // ELFW_ST_VISIBILITY(entry->st_other),
                entry->st_size  ,
                strtab + entry->st_name ,
                version   ? "@"     : "",
                defversym ? "@"     : "",
                version   ? version : "",
                vs,
                (void *)entry->st_value );
        x++;
    }
}

static void
dump_interp (const char *indent, void *start, size_t size, ElfW(Addr) base)
{
    char interpreter[PATH_MAX + 1] = "";
    interpreter[PATH_MAX] = '\0';

    strncpy( &interpreter[0], start + base, PATH_MAX );

    fprintf( stderr, "%s// %p %lu %p %s", indent, start, size, (void *)base,
             &interpreter[0] );
    return;
}

static void *
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

static int
find_value (ElfW(Addr) base, void *start, size_t size, int what)
{
    const ElfW(Dyn) *entry = find_dyn( base, start, size, what );
    return entry ? entry->d_un.d_val : -1;
}

static ElfW(Addr)
find_ptr (ElfW(Addr) base, void *start, size_t size, int what)
{
    const ElfW(Dyn) *entry = find_dyn( base, start, size, what );
    return entry ? entry->d_un.d_ptr : (ElfW(Addr)) NULL;
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

static const char *
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

static const char *
reloc_type (int rtype)
{
    switch( __ELF_NATIVE_CLASS )
    {
      case 64:
        switch( rtype )
        {
          case R_X86_64_NONE:      return "NONE";      // No reloc
          case R_X86_64_64:        return "64";        // Direct 64 bit
          case R_X86_64_PC32:      return "PC32";      // PC rel 32 bit signed
          case R_X86_64_GOT32:     return "GOT32";     // 32 bit GOT entry
          case R_X86_64_PLT32:     return "PLT32";     // 32 bit PLT address
          case R_X86_64_COPY:      return "COPY";      // Copy symbol at runtime
          case R_X86_64_GLOB_DAT:  return "GLOB_DAT";  // Create GOT entry
          case R_X86_64_JUMP_SLOT: return "JUMP_SLOT"; // Create PLT entry
          case R_X86_64_RELATIVE:  return "RELATIVE";  // Adjust by program base
          case R_X86_64_GOTPCREL:  return "GOTPCREL";  // 32 bit GOT PC ofset
          case R_X86_64_32:        return "32";        // Direct 32 bit zero
          case R_X86_64_32S:       return "32S";       // Direct 32 bit sign
          case R_X86_64_16:        return "16";        // Direct 16 bit zero
          case R_X86_64_PC16:      return "PC16";      // 16 bit extended pc
          case R_X86_64_8:         return "8";         // Direct 8 bit extended
          case R_X86_64_PC8:       return "PC8";       // 8 bit sign extended pc relative
          case R_X86_64_DTPMOD64:  return "DTPMOD64";  // ID of containing symbol module
          case R_X86_64_DTPOFF64:  return "DTPOFF64";  // Offset in module's TLS
          case R_X86_64_TPOFF64:   return "TPOFF64";   // Offset in initial TLS
          case R_X86_64_TLSGD:     return "TLSGD";     // 32 bit PC relative offset to two GOT entries for GD symbol
          case R_X86_64_TLSLD:     return "TLSLD";     // 32 bit PC relative offset to two GOT entries for LD symbol
          case R_X86_64_DTPOFF32:  return "DTPOFF32";  // Offset in TLS block
          case R_X86_64_GOTTPOFF:  return "GOTTPOFF";  // 32 bit PC relative offset to GOT entry for IE symbol
          case R_X86_64_TPOFF32:   return "TPOFF32";   // Offset in initial TLS
        }
        break;
      case 32:
        switch( rtype )
        {
          case R_386_NONE:         return "NONE";         // No reloc
          case R_386_32:           return "32";           // Direct 32 bit
          case R_386_PC32:         return "PC32";         // PC relative 32 bit
          case R_386_GOT32:        return "GOT32";        // 32 bit GOT entry
          case R_386_PLT32:        return "PLT32";        // 32 bit PLT address
          case R_386_COPY:         return "COPY";         // Copy symbol at runtime
          case R_386_GLOB_DAT:     return "GLOB_DAT";     // Create GOT entry
          case R_386_JMP_SLOT:     return "JMP_SLOT";     // Create PLT entry
          case R_386_RELATIVE:     return "RELATIVE";     // Adjust by program base
          case R_386_GOTOFF:       return "GOTOFF";       // 32 bit offset to GOT
          case R_386_GOTPC:        return "GOTPC";        // 32 bit PC relative offset to GOT
          case R_386_32PLT:        return "32PLT";
          case R_386_TLS_TPOFF:    return "TLS_TPOFF";    // Offset in static TLS block
          case R_386_TLS_IE:       return "TLS_IE";       // Address of GOT entry for static TLS block offset
          case R_386_TLS_GOTIE:    return "TLS_GOTIE";    // GOT entry for static TLS block offset
          case R_386_TLS_LE:       return "TLS_LE";       // Offset relative to static TLS block
          case R_386_TLS_GD:       return "TLS_GD";       // Direct 32 bit for GNU version of general dynamic thread local data
          case R_386_TLS_LDM:      return "TLS_LDM";      // Direct 32 bit for GNU version of local dynamic thread local data in LE code
          case R_386_16:           return "16";
          case R_386_PC16:         return "PC16";
          case R_386_8:            return "8";
          case R_386_PC8:          return "PC8";
          case R_386_TLS_GD_32:    return "TLS_GD_32";    // Direct 32 bit for general dynamic thread local data
          case R_386_TLS_GD_PUSH:  return "TLS_GD_PUSH";  // Tag for pushl in GD TLS code
          case R_386_TLS_GD_CALL:  return "TLS_GD_CALL";  // Relocation for call to __tls_get_addr()
          case R_386_TLS_GD_POP:   return "TLS_GD_POP";   // Tag for popl in GD TLS code
          case R_386_TLS_LDM_32:   return "TLS_LDM_32";   // Direct 32 bit for local dynamic thread local data in LE code
          case R_386_TLS_LDM_PUSH: return "TLS_LDM_PUSH"; // Tag for pushl in LDM TLS code
          case R_386_TLS_LDM_CALL: return "TLS_LDM_CALL"; // Relocation for call to __tls_get_addr() in LDM code
          case R_386_TLS_LDM_POP:  return "TLS_LDM_POP";  // Tag for popl in LDM TLS code
          case R_386_TLS_LDO_32:   return "TLS_LDO_32";   // Offset relative to TLS block
          case R_386_TLS_IE_32:    return "TLS_IE_32";    // GOT entry for negated static TLS block offset
          case R_386_TLS_LE_32:    return "TLS_LE_32";    // Negated offset relative to static TLS block
          case R_386_TLS_DTPMOD32: return "TLS_DTPMOD32"; // ID of module containing symbol
          case R_386_TLS_DTPOFF32: return "TLS_DTPOFF32"; // Offset in TLS block
          case R_386_TLS_TPOFF32:  return "TLS_TPOFF32";  // Negated offset in static TLS block
        }
        break;
    }

    return "???";
}

static void
dump_rel (const char *indent,
          const void *start,
          int relsz,
          const char *strtab,
          const void *symtab)
{
    int x = 0;
    ElfW(Rel) *entry;

    for( entry = (ElfW(Rel) *)start;
         entry < (ElfW(Rel) *)(start + relsz);
         entry++ )
    {
        int sym;
        int chr;
        char *name;

        const ElfW(Sym) *symbol;

        switch( __ELF_NATIVE_CLASS )
        {
          case 32:
            sym = ELF32_R_SYM (entry->r_info);
            chr = ELF32_R_TYPE(entry->r_info);
            break;
          case 64:
            sym = ELF64_R_SYM (entry->r_info);
            chr = ELF64_R_TYPE(entry->r_info);
            break;
          default:
            fprintf( stderr,
                     "__ELF_NATIVE_CLASS is NOT 32 or 64:"
                     " What the actual hell\n" );
            exit(-1);
        }

        symbol = find_symbol( sym, symtab, strtab, &name );
        if( symbol )
            fprintf( stderr, "%s    // [%03d] %16s off: %lx; %s;\n",
                     indent,
                     x++,
                     reloc_type(chr),
                     entry->r_offset,
                     name );
        else
            fprintf( stderr, "%s    // [%03d] %16s off: %lx; sym[%d];\n",
                     indent,
                     x++,
                     reloc_type(chr),
                     entry->r_offset,
                     sym );
    }
}

static void
dump_rela (const char *indent,
           const void *start,
           int relasz,
           const char *strtab,
           const void *symtab,
           ElfW(Addr)  base)
{
    int x = 0;
    ElfW(Rela) *entry;

    for( entry = (ElfW(Rela) *)start;
         entry < (ElfW(Rela) *)(start + relasz);
         entry++ )
    {
        int sym;
        int chr;
        char *name = NULL;

        const ElfW(Sym) *symbol;

        switch( __ELF_NATIVE_CLASS )
        {
          case 32:
            sym = ELF32_R_SYM (entry->r_info);
            chr = ELF32_R_TYPE(entry->r_info);
            break;
          case 64:
            sym = ELF64_R_SYM (entry->r_info);
            chr = ELF64_R_TYPE(entry->r_info);
            break;
          default:
            fprintf( stderr,
                     "__ELF_NATIVE_CLASS is NOT 32 or 64:"
                     " What the actual hell\n" );
            exit(-1);
        }

        symbol = find_symbol( sym, symtab, strtab, &name );
        if( symbol )
            fprintf( stderr, "%s    // [%03d] %16s off: %lx; %s; add: 0x%ld\n",
                     indent,
                     x++,
                     reloc_type(chr),
                     entry->r_offset,
                     name,
                     entry->r_addend );
        else
            fprintf( stderr, "%s    // [%03d] %16s off: %lx; sym: %d; add: %ld\n",
                     indent,
                     x++,
                     reloc_type(chr),
                     entry->r_offset,
                     sym,
                     entry->r_addend );

        switch( chr )
        {
            ElfW(Addr) *reloc_addr;
          case R_X86_64_JUMP_SLOT:
            reloc_addr = addr( base, entry->r_offset );
            fprintf( stderr,
                     "%s    // JUMP_SLOT relocation for %s is at %p "
                     "and contains %p\n",
                     indent,
                     (symbol && name) ? name : "*unnamed*",
                     (void *)reloc_addr,
                     (void *)*((ElfW(Addr) *) reloc_addr) );
            break;
          default:
            break;
        }
    }
}

static void
dump_verneed(const char *indent,
             const void *start,
             int entries,
             const char *strtab,
             ElfW(Addr)  base)
{
    const char *vn = start;

    for( int x = 0; x < entries; x++ )
    {
        ElfW(Verneed) *entry = (ElfW(Verneed) *) vn;

        fprintf( stderr, "%s    // %02d %-15s : %d entries %d aux\n",
                 indent, x,
                 strtab + entry->vn_file,
                 entry->vn_cnt,
                 entry->vn_aux );

        const char *au = vn + entry->vn_aux;

        for( int y = 0; y < entry->vn_cnt; y++ )
        {
            ElfW(Vernaux) *aux = (ElfW(Vernaux) *) au;
            fprintf( stderr, "%s    //    %s %s\n",
                     indent,
                     strtab + aux->vna_name,
                     (aux->vna_flags & VER_FLG_WEAK) ? "(weak symbol)" : "" );
            au = au + aux->vna_next;
        }

        vn = vn + entry->vn_next;
    }
}

static void
dump_verdef(const char *indent,
            const void *start,
            int entries,
            const char *strtab,
            ElfW(Addr)  base)
{
    const char *vd = start;

    for( int x = 0; x < entries; x++ )
    {
        ElfW(Verdef) *entry = (ElfW(Verdef) *) vd;

        fprintf( stderr, "%s    // %02d [%d]; ndx: %0x; flags: %0x\n",
                 indent, x,
                 entry->vd_cnt  ,
                 entry->vd_ndx  ,
                 entry->vd_flags);

        const char *au = vd + entry->vd_aux;

        for( int y = 0; y < entry->vd_cnt; y++ )
        {
            ElfW(Verdaux) *aux = (ElfW(Verdaux) *) au;
            fprintf( stderr, "%s    //    %s\n",
                     indent,
                     strtab + aux->vda_name );
            au = au + aux->vda_next;
        }

        vd = vd + entry->vd_next;
    }
}


static void
dump_dynamic (const char *indent, void *start, size_t size, ElfW(Addr) base)
{
    int x = 0;
    const char *tag;
    ElfW(Dyn) *entry;

    int strsiz     = -1;
    int relasz     = -1;
    int jmprelsz   = -1;
    int verneednum = -1;
    int verdefnum  = -1;
    int jmpreltype = DT_NULL;

    const void *symtab = NULL;
    const void *versym = NULL;
    const void *verdef = NULL;
    const char *strtab = find_strtab( base, start, size, &strsiz );
    int tag_type = TTYPE_VAL;

    fprintf( stderr, "%s{\n", indent );
    for( entry = start + base;
         (entry->d_tag != DT_NULL) && ((void *)entry < (start + base + size));
         entry++ )
    {
        tag = d_tag( entry->d_tag, &tag_type );

        switch( tag_type )
        {
          case TTYPE_VAL:
            fprintf( stderr, "%s    { #%03d %20s(%ld) = val:%ld }\n",
                     indent,
                     x++,
                     tag,
                     entry->d_tag,
                     entry->d_un.d_val );
            break;
          case TTYPE_PTR:
            fprintf( stderr, "%s    { #%03d %20s(%ld) = ptr:%p }\n",
                     indent, x++,
                     tag,
                     entry->d_tag,
                     (void *)addr( base, entry->d_un.d_ptr ) );
            break;
          case TTYPE_STR:
            fprintf( stderr, "%s    { #%03d %20s(%ld) = str:%s }\n",
                     indent,
                     x++,
                     tag,
                     entry->d_tag,
                     strtab + entry->d_un.d_ptr );
            break;
          default:
            fprintf( stderr, "%s    { #%03d %20s(%ld) = ???:%p }\n",
                     indent,
                     x++,
                     tag,
                     entry->d_tag,
                     (void *)entry->d_un.d_ptr );
            break;
        }

        switch( entry->d_tag )
        {
          case DT_PLTRELSZ:
            jmprelsz = entry->d_un.d_val;
            break;

          case DT_SYMTAB:
            if( versym == NULL )
                versym = addr( base, find_ptr( base, start, size, DT_VERSYM ) );
            if( verdef == NULL )
                verdef = addr( base, find_ptr( base, start, size, DT_VERDEF ) );
            if( verdefnum == -1 )
                verdefnum = find_value( base, start, size, DT_VERDEFNUM );
            symtab = addr( base, entry->d_un.d_ptr );
            dump_symtab( indent, symtab, strtab, versym, verdef, verdefnum );
            break;

          case DT_RELA:
            if( relasz == -1 )
                relasz = find_value( base, start, size, DT_RELASZ );
            dump_rela( indent, addr(base, entry->d_un.d_ptr), relasz,
                       strtab, symtab, base );
            break;

          case DT_RELASZ:
            relasz = entry->d_un.d_val;
            break;

          case DT_PLTREL:
            jmpreltype = entry->d_un.d_val;
            break;

          case DT_JMPREL:
            if( jmprelsz == -1 )
                jmprelsz = find_value( base, start, size, DT_PLTRELSZ );
            if( jmpreltype == DT_NULL )
                jmpreltype = find_value( base, start, size, DT_PLTREL );

            switch( jmpreltype )
            {
                int unused;

              case DT_REL:
                dump_rel( indent, addr(base, entry->d_un.d_ptr), jmprelsz,
                          strtab, symtab );
                break;

              case DT_RELA:
                dump_rela( indent, addr(base, entry->d_un.d_ptr), jmprelsz,
                           strtab, symtab, base );
                break;

              default:
                fprintf( stderr, "%s    // unknown DT_PLTREL value: %d (%s)\n",
                         indent, jmpreltype, d_tag( jmpreltype, &unused ) );
                fprintf( stderr, "%s    // expected DT_REL or DT_RELA\n", indent );
                break;
            }
            break;

          case DT_VERNEEDNUM:
            verneednum = entry->d_un.d_val;
            break;

          case DT_VERNEED:
            if( verneednum == -1 )
                verneednum = find_value( base, start, size, DT_VERNEEDNUM );
            dump_verneed( indent, addr(base, entry->d_un.d_ptr), verneednum,
                          strtab, base );
            break;

          case DT_VERDEFNUM:
            verdefnum = entry->d_un.d_val;
            break;

          case DT_VERDEF:
            if( verdefnum == -1 )
                verdefnum = find_value( base, start, size, DT_VERDEFNUM );
            verdef = addr( base, entry->d_un.d_ptr );
            dump_verdef( indent, verdef, verdefnum, strtab, base );
            break;

          case DT_VERSYM:
            if( versym == NULL )
                versym = addr( base, entry->d_un.d_ptr );
            break;

          default:
            break;
        }
    }
    fprintf(stderr, "%s}\n", indent);
    return;
}

static int
phdr_cb (struct dl_phdr_info *info, size_t size, void *data)
{
    int j;

    fprintf(stderr, "\n\
===============================================================================\n\
struct dl_phdr_info                  \n\
{                                    \n\
    ElfW(Addr)        dlpi_addr;  %p \n\
    const char       *dlpi_name; \"%s\" \n\
    ElfW(Half)        dlpi_phnum; %d \n\
    const ElfW(Phdr) *dlpi_phdr;  %p \n",
            (void *)info->dlpi_addr  ,
            info->dlpi_name  ,
            info->dlpi_phnum ,
            (void *)info->dlpi_phdr );

    for( j = 0; j < info->dlpi_phnum; j++ )
    {
        fprintf(stderr, "    { // #%03d @ ( %p + %p ) %p\n\
        ElfW(Word)  p_type;    %d %s   \n\
        ElfW(Off)   p_offset;  %ld     \n\
        ElfW(Addr)  p_vaddr;   %p      \n\
        ElfW(Addr)  p_paddr;   %p      \n\
        ElfW(Word)  p_filesz;  0x%lx    \n\
        ElfW(Word)  p_memsz;   0x%lx    \n\
        ElfW(Word)  p_flags;   0x%x %s \n\
        ElfW(Word)  p_align;   %lu \n",
                j,
                (void *)info->dlpi_addr             ,
                (void *)info->dlpi_phdr[j].p_vaddr  ,
                (void *) ( info->dlpi_addr + info->dlpi_phdr[j].p_vaddr ),
                info->dlpi_phdr[j].p_type   ,
                pt_type( info->dlpi_phdr[j].p_type ),
                info->dlpi_phdr[j].p_offset ,
                (void *)info->dlpi_phdr[j].p_vaddr  ,
                (void *)info->dlpi_phdr[j].p_paddr  ,
                info->dlpi_phdr[j].p_filesz ,
                info->dlpi_phdr[j].p_memsz  ,
                info->dlpi_phdr[j].p_flags  ,
                pt_flags( info->dlpi_phdr[j].p_flags ),
                info->dlpi_phdr[j].p_align    );
        switch(info->dlpi_phdr[j].p_type)
        {
          case PT_DYNAMIC:
            dump_dynamic("        ",
                         (void *) info->dlpi_phdr[j].p_vaddr,
                         info->dlpi_phdr[j].p_memsz,
                         info->dlpi_addr);
            break;
          case PT_INTERP:
            dump_interp("        ",
                        (void *) info->dlpi_phdr[j].p_vaddr,
                        info->dlpi_phdr[j].p_memsz,
                        info->dlpi_addr);
          default:
            break;
        }
        fprintf(stderr, "\n    }\n");
    }

    fprintf(stderr, "};\n");
    return 0;
}

void dump_elf_data (void)
{
    dl_iterate_phdr( phdr_cb, NULL );
}

static int
dlhdr_cb (struct dl_phdr_info *info, size_t size, void *data)
{
    ElfW(Dyn) *dyn = NULL;

    for( int j = 0; j < info->dlpi_phnum; j++ )
        if( info->dlpi_phdr[j].p_type == PT_DYNAMIC )
            dyn = (ElfW(Dyn) *)info->dlpi_phdr[j].p_vaddr;

    if( dyn )
        fprintf(stderr, "+ dl_phdr: %p | %50s | addr: %p | dyn: %p |\n",
                info,
                info->dlpi_name,
                (void *)info->dlpi_addr,
                dyn + info->dlpi_addr );
    else
        fprintf(stderr, "+ dl_phdr: %p | %50s | addr: %p | dyn: NOT-FOUND |\n",
                info,
                info->dlpi_name,
                (void *)info->dlpi_addr );

    return 0;
}

void debug_link_maps (void)
{
    struct link_map *map;
    void *handle;

    handle = dlopen( NULL, RTLD_LAZY );
    dlinfo( handle, RTLD_DI_LINKMAP, &map );

    if (map->l_prev)
        for( struct link_map *m = map; m; m = m->l_prev )
            fprintf(stderr, "-link_map: %p | %50s | addr: %p | dyn: %p \n",
                    m, m->l_name, (void *)m->l_addr, m->l_ld);

    if (map->l_next)
        for( struct link_map *m = map; m; m = m->l_next )
            fprintf(stderr, "+link_map: %p | %50s | addr: %p | dyn: %p |\n",
                    m, m->l_name, (void *)m->l_addr, m->l_ld);

    dl_iterate_phdr( dlhdr_cb, NULL );
}
