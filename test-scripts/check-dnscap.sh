#!/bin/sh
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# Check that compactor understands PCAPs produced by dnscap.

COMP=./compactor
DATAFILE=./dnscap.pcap

command -v mktemp > /dev/null 2>&1 || { echo "No mktemp, skipping test." >&2; exit 77; }

tmpdir=`mktemp -d -t "check-dnscap.XXXXXX"`

cleanup()
{
    rm -rf $tmpdir
    exit $1
}

trap "cleanup 1" HUP INT TERM

# Run the compactor with debug-dns and verify it succeeds
# and produces non-empty output. We don't bother checking
# output content at present.
$COMP -c /dev/null --debug-dns -n all $DATAFILE > $tmpdir/debug.out
if [ $? -ne 0 ]; then
    cleanup 1
fi

if [ ! -s $tmpdir/debug.out ]; then
    cleanup 1
fi

cleanup 0
