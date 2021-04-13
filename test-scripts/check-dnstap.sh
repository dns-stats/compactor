#!/usr/bin/env bash
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# Check that compactor understands DNSTAP files.

COMP=./compactor
DATAFILE=$srcdir/test-scripts/test.dnstap
OUTPUTFILE=$srcdir/test-scripts/test.dnstap.debug-dns
OUTPUTFILE_REPORTINFO=$srcdir/test-scripts/test.dnstap.debug-dns-reportinfo

command -v mktemp > /dev/null 2>&1 || { echo "No mktemp, skipping test." >&2; exit 77; }
command -v diff > /dev/null 2>&1 || { echo "No diff, skipping test." >&2; exit 77; }
command -v nc > /dev/null 2>&1 || { echo "No nc, skipping test." >&2; exit 77; }

tmpdir=`mktemp -d -t "check-dnstap.XXXXXX"`

cleanup()
{
    rm -rf $tmpdir
    exit $1
}

trap "cleanup 1" HUP INT TERM

# Run the compactor with debug-dns, read from file, and verify it succeeds
# and produces the expected output.
$COMP -c /dev/null --report-info --debug-dns -n all --dnstap on $DATAFILE > $tmpdir/debug.out
if [ $? -ne 0 ]; then
    cleanup 1
fi

diff -i $OUTPUTFILE_REPORTINFO $tmpdir/debug.out
if [ $? -ne 0 ]; then
    cleanup 1
fi

# Run the compactor with debug-dns, read from socket, and verify it
# produces the expected output.
$COMP -c /dev/null --debug-dns -n all --dnstap-socket $tmpdir/dnstap.sock > $tmpdir/debug2.out &
if [ $? -ne 0 ]; then
    cleanup 1
fi
sleep 1
nc -U $tmpdir/dnstap.sock < $DATAFILE &
sleep 2
kill %2
sleep 1
kill %1

diff -i $OUTPUTFILE $tmpdir/debug2.out
cleanup $?
