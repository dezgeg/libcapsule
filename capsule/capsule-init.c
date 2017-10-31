#include "capsule.h"
#include "utils/utils.h"
#include <stdlib.h>

void *(*capsule_dlsym)(void* handle, const char* symbol);

void
capsule_init ()
{
    set_debug_flags( secure_getenv("CAPSULE_DEBUG") );
    capsule_dlsym = dlsym( RTLD_DEFAULT, "dlsym" );
}

