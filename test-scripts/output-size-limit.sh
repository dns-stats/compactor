#!/bin/sh
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# Check max-file-qr-items works.

COMP=./compactor
DATAFILE=./dns.pcap

tmpdir=`mktemp -d -t "file-size-limit.XXXXXX"`

cleanup()
{
    rm -rf $tmpdir
    exit $1
}

trap "cleanup 1" HUP INT TERM

# Run compactor twice, once with block count limit.
$COMP -c /dev/null -o "$tmpdir/out.cbor" $DATAFILE
if [ $? -ne 0 ]; then
    cleanup 1
fi

$COMP -c /dev/null --max-output-size 10k --max-block-qr-items 100 -o "$tmpdir/out2.cbor" $DATAFILE
if [ $? -ne 0 ]; then
    cleanup 1
fi

# There should be one out file and 5 out2 files.
NOUT=$(ls $tmpdir/out.cbor* | wc -l)
NOUT2=$(ls $tmpdir/out2.cbor* | wc -l)
if [ $NOUT -eq 1 -a $NOUT2 -eq 5 ]; then
    cleanup 0
fi
cleanup 1
