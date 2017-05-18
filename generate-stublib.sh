#!/bin/bash

# Copyright © 2017 Collabora Ltd

# This file is part of libcapsule.

# libcapsule is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.

# libcapsule is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public
# License along with libcapsule.  If not, see <http://www.gnu.org/licenses/>.

set -u
set -e

declare -A NODE;
top=$(dirname $0);
top=${top:-.};

proxied_dso=$1;    shift;
proxy_excluded=$1; shift;
proxy_extra=$1;    shift;
proxy_src=$1;      shift;
symbol_file=${proxy_src%.c}.symbols;
map_file=${proxy_src%.c}.map;
dlopen_file=${proxy_src}.dlopen;
echo -n > $symbol_file;
echo -n > $map_file;

exec >& $proxy_src;

cat $top/capsule-shim.h;

for pt in $proxied_dso $(cat $proxy_extra);
do
    $top/print-libstubs $pt;
done > $symbol_file;

while read symbol version dependency;
do
    case $version in
        @*)
            echo "VERSIONED_STUB  ( $symbol, $version );";
            node=${version##*@};
            NODE[$node]=${NODE[$node]:-}" "$symbol;
            ;;
        *)
            echo "UNVERSIONED_STUB( $symbol );";
            ;;
    esac;
done < $symbol_file;

cat - <<EOF
static Lmid_t symbol_ns;
static char *prefix;
static void *dso;
// should we exclude libpthread here?
// in any case, these are DSOs we do _not_ want to isolate
static const char *exclude[] = { // MUST NOT be pulled from the capsule
                                 // prefixed filesystem tree:
                                 "libc.so.6",
                                 "libpthread.so.0",
                                 "libpthread-2.19.so",
                                 "libdl.so.2",
EOF

while read excluded x;
do
    case $excluded in lib*) printf "%32s \"%s\",\n" "" $excluded; ;; esac;
done < $proxy_excluded;
cat - <<EOF
                                 NULL };
EOF

if [ -f ${dlopen_file} ];
then
    echo "// -------------------------------------------------------------";
    echo "// start of ${proxy_src%.c} dlopen wrapper";
    cat $dlopen_file;
    echo "// end of ${proxy_src%.c} dlopen wrapper";
    echo "// -------------------------------------------------------------";
else
    cat - <<EOF
// -------------------------------------------------------------------------
// start of default capsule dlopen wrapper function section
static void *_dlopen (const char *filename, int flag)
{
    if( flag & RTLD_GLOBAL )
    {
        fprintf( stderr, "Warning: libcapsule dlopen wrapper cannot pass "
                         "RTLD_GLOBAL to underlying dlmopen(%s...) call\\n",
                 filename );
        flag = (flag & ~RTLD_GLOBAL) & 0xfffff;
    }
    return capsule_shim_dlopen( symbol_ns, prefix, exclude, filename, flag );
}
// end of default capsule dlopen wrapper function section
// -------------------------------------------------------------------------
EOF
fi

cat - <<EOF

static void __attribute__ ((constructor)) _capsule_init (void)
{
    int   capsule_errno = 0;
    char *capsule_error = NULL;

    // this is an array of the functions we want to act as a shim for:
    capsule_item_t relocs[] =
      {
EOF

while read sym x; do echo "         { \"$sym\" },"; done < $symbol_file;

cat - <<EOF
        { NULL }
      };

    // and this is an aray of functions we must override in the DSOs
    // inside the capsule (mostly to take account of the fact that
    // they're pulled in from a tree with a filesystem prefix like /host)
    // NOTE: the shim address here isn't used, but we give it the same
    // value as the real function address so it's never accidentally
    // a value the capsule code will care about:
    capsule_item_t wrappers[] =
      {
        { "dlopen", (ElfW(Addr)) _dlopen, (ElfW(Addr)) _dlopen },
        { NULL }
      };

    symbol_ns = LM_ID_NEWLM;
    prefix = "/host";

    capsule_init();

    dso = capsule_dlmopen( "$proxied_dso", prefix, &symbol_ns, wrappers,
                           0, exclude, &capsule_errno, &capsule_error );

    if( dso )
    {
        capsule_relocate( "$proxied_dso", dso, 0, relocs, &capsule_error );
    }
    else
    {
        fprintf( stderr, "capsule_dlmopen() failed: %s\\n", capsule_error );
        exit( 1 );
    }
}
EOF

exec >& $map_file;

for node in ${!NODE[@]};
do
    echo "$node {";
    echo "  global:";
    for symbol in ${NODE[$node]};
    do
        echo "    $symbol;";
    done;
    echo "};";
    echo;
done;
