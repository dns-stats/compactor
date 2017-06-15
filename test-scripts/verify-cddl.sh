#!/bin/sh
# 
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# Check that C-DNS output file matches the CDDL definition.

COMP=./compactor
DATAFILE=./gold.pcap
CDDL=$srcdir/doc/c-dns-working.cddl

tmpdir=`mktemp -d -t "verify-cddl.XXXXXX"`

cleanup()
{
    rm -rf $tmpdir
    exit $1
}

trap "cleanup 1" HUP INT TERM

command -v cddl > /dev/null 2>&1 || { echo "No cddl, skipping test." >&2; exit 77; }

# Run the conversion.
$COMP -c /dev/null --include all -o $tmpdir/out.cbor $DATAFILE
if [ $? -ne 0 ]; then
    cleanup 1
fi

# Verify compactor output conforms to the CDDL spec.
cddl $CDDL validate $tmpdir/out.cbor
cleanup $?
