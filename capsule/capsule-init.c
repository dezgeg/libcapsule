#include "capsule.h"
#include "utils/utils.h"
#include <stdlib.h>

void
capsule_init ()
{
    set_debug_flags( secure_getenv("CAPSULE_DEBUG") );
}

