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
echo -n > $proxy_src.symbols;
echo -n > $proxy_src.map;

exec >& $proxy_src;

cat $top/capsule-shim.h;
for proxied_target in $proxied_dso $(cat $proxy_extra);
do
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
        echo "         { \"$symbol\" }," >> $proxy_src.symbols
    done < <($top/print-libstubs $proxied_target);
done;
cat - <<EOF
static Lmid_t symbol_ns;
static char *prefix;
static void *dso;
// should we exclude libpthread here?
// in any case, these are DSOs we do _not_ want to isolate
static const char *exclude[] = { // MUST NOT be pulled from the capsule prefixed filesystem tree:
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

static void *_dlopen (const char *filename, int flag)
{
    return capsule_shim_dlopen( dso, symbol_ns, prefix, exclude, filename, flag );
}

static void __attribute__ ((constructor)) _capsule_init (void)
{
     int   capsule_errno = 0;
     char *capsule_error = NULL;

     // this is an array of the functions we want to act as a shim for:
     capsule_item_t relocs[] =
       {
EOF
cat $proxy_src.symbols;
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

exec >& $proxy_src.map;

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