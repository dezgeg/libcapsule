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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>

#include <capsule/capsule.h>

#define UNVERSIONED_STUB(name) \
    void name (void) { fprintf(stderr, "! SHIM " #name " called\n" ); return; }

#define VERSIONED_STUB(name,version) \
    UNVERSIONED_STUB(name);

// we used to do the linking here but that actually gets messy
// since you need the link map anyway to declare the version nodes
// and it turns out you have to make an extra _name symbol to do
// versioned symbols via __asm__ directives
// __asm__(".symver _" #name "," #name #version)

