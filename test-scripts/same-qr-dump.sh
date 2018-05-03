#!/bin/sh
# 
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# Check that dumping Query/Response text from compactor and inspector
# produces the same result.

COMP=./compactor
INSP=./inspector
DATAFILE=./dns.pcap

command -v cmp > /dev/null 2>&1 || { echo "No cmp, skipping test." >&2; exit 77; }
command -v mktemp > /dev/null 2>&1 || { echo "No mktemp, skipping test." >&2; exit 77; }

tmpdir=`mktemp -d -t "same-qr-dump.XXXXXX"`

cleanup()
{
    rm -rf $tmpdir
    exit $1
}

trap "cleanup 1" HUP INT TERM

# Run the converter.
$COMP -c /dev/null --debug-qr --include all -o $tmpdir/out.cbor $DATAFILE > $tmpdir/compactor-qr.txt
if [ $? -ne 0 ]; then
    cleanup 1
fi

# Convert output back to pcap.
$INSP --debug-qr $tmpdir/out.cbor > $tmpdir/inspector-qr.txt
if [ $? -ne 0 ]; then
    cleanup 1
fi

cmp -s $tmpdir/compactor-qr.txt $tmpdir/inspector-qr.txt
cleanup $?
