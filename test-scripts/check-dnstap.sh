#!/bin/sh
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# Check that compactor understands DNSTAP files.

COMP=./compactor
DATAFILE=$srcdir/test-scripts/test.dnstap
OUTPUTFILE=$srcdir/test-scripts/test.dnstap.debug-dns

command -v mktemp > /dev/null 2>&1 || { echo "No mktemp, skipping test." >&2; exit 77; }
command -v diff > /dev/null 2>&1 || { echo "No diff, skipping test." >&2; exit 77; }

tmpdir=`mktemp -d -t "check-dnstap.XXXXXX"`

cleanup()
{
    rm -rf $tmpdir
    exit $1
}

trap "cleanup 1" HUP INT TERM

# Run the compactor with debug-dns and verify it succeeds
# and produces the expected output.
$COMP -c /dev/null --debug-dns -n all --dnstap on $DATAFILE > $tmpdir/debug.out
if [ $? -ne 0 ]; then
    cleanup 1
fi

diff -i $OUTPUTFILE $tmpdir/debug.out
cleanup $?
