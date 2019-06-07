#!/bin/sh
# 
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# Check that test content C-DNS values are as expected when excludes
# are specified. See check-testcontent.sh. Exclude client and server
# address and port so we check Q/R and Q/R sig.

COMP=./compactor

CBOR2DIAG=cbor2diag.rb
DATAFILE=./testcontent.pcap
DATADIAG=$srcdir/test-scripts/testcontent-exclude.diag
EXCLUDE=$srcdir/test-scripts/testcontent-exclude.conf

command -v $CBOR2DIAG > /dev/null 2>&1 || { echo "No cbor2diag, skipping test." >&2; exit 77; }
command -v cmp > /dev/null 2>&1 || { echo "No cmp, skipping test." >&2; exit 77; }
command -v diff > /dev/null 2>&1 || { echo "No diff, skipping test." >&2; exit 77; }
command -v mktemp > /dev/null 2>&1 || { echo "No mktemp, skipping test." >&2; exit 77; }

tmpdir=`mktemp -d -t "check-testcontent-exclude.XXXXXX"`

cleanup()
{
    rm -rf $tmpdir
    exit $1
}

trap "cleanup 1" HUP INT TERM


# Check compactor fails when given excludes AND include.
$COMP -c /dev/null --excludesfile $EXCLUDE -n all --omit-system-id -o $tmpdir/out.cbor $DATAFILE
if [ $? -eq 0 ]; then
    cleanup 1
fi

$COMP -c /dev/null --excludesfile $EXCLUDE --omit-system-id -o $tmpdir/out.cbor $DATAFILE
if [ $? -ne 0 ]; then
    cleanup 1
fi

$CBOR2DIAG $tmpdir/out.cbor > $tmpdir/out.diag
if [ $? -ne 0 ]; then
    cleanup 1
fi

diff -i $tmpdir/out.diag $DATADIAG
cleanup $?
