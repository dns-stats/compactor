#!/bin/sh
# 
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# Check that converting version 0.2 cbor->pcap produces the expected output.

COMP=./compactor
INSP=./inspector

DEFAULTS="--defaultsfile $srcdir/test-scripts/test.defaults"

CBORFILE=./gold.cbor05
PCAPFILE=./gold.pcap

command -v cmp > /dev/null 2>&1 || { echo "No cmp, skipping test." >&2; exit 77; }
command -v mktemp > /dev/null 2>&1 || { echo "No mktemp, skipping test." >&2; exit 77; }

tmpdir=`mktemp -d -t "verify-cbor02.XXXXXX"`

cleanup()
{
    rm -rf $tmpdir
    exit $1
}

trap "cleanup 1" HUP INT TERM

# Convert cbor v0.5 back to pcap.
$INSP $DEFAULTS -o $tmpdir/out.pcap $CBORFILE
if [ $? -ne 0 ]; then
    cleanup 1
fi

cmp -s $tmpdir/out.pcap $PCAPFILE
cleanup $?
