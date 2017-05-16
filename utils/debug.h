#pragma once

enum
{
    DEBUG_NONE       = 0,
    DEBUG_PATH       = 0x1,
    DEBUG_SEARCH     = 0x1 << 1,
    DEBUG_LDCACHE    = 0x1 << 2,
    DEBUG_CAPSULE    = 0x1 << 3,
    DEBUG_MPROTECT   = 0x1 << 4,
    DEBUG_WRAPPERS   = 0x1 << 5,
    DEBUG_RELOCS     = 0x1 << 6,
    DEBUG_ELF        = 0x1 << 7,
    DEBUG_ALL        = 0xffff,
};

#define LDLIB_DEBUG(ldl, flags, fmt, args...)  \
    if( ldl->debug && (ldl->debug & (flags)) ) \
        fprintf( stderr, "%s:" fmt "\n", __PRETTY_FUNCTION__, ##args )

#define DEBUG(flags, fmt, args...)               \
    if( debug_flags && (debug_flags & (flags)) ) \
        fprintf( stderr, "%s:" fmt "\n", __PRETTY_FUNCTION__, ##args )

extern unsigned long debug_flags;
void  set_debug_flags (const char *control);
