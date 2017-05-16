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

#ifdef DEBUG
#define debug(fmt, args...) \
    fprintf( stderr, "%s:" fmt "\n", __PRETTY_FUNCTION__, ##args )
#else
#define debug(fmt, args...) \

#endif

extern unsigned long debug_flags;
void  set_debug_flags (const char *control);
