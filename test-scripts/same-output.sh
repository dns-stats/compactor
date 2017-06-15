#!/bin/sh
# 
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# Check that running the conversion twice produces the same output.

DNSCAP=./compactor
DATAFILE=./dns.pcap

#set -x

tmpdir=`mktemp -d -t "same-output.XXXXXX"`

cleanup()
{
    rm -rf $tmpdir
    exit $1
}

trap "cleanup 1" HUP INT TERM

# Run the converter twice.
$DNSCAP -c /dev/null -o $tmpdir/out.cbor $DATAFILE
if [ $? -ne 0 ]; then
    cleanup 1
fi

$DNSCAP -c /dev/null -o $tmpdir/out2.cbor $DATAFILE
if [ $? -ne 0 ]; then
    cleanup 1
fi

cmp $tmpdir/out.cbor $tmpdir/out2.cbor
cleanup $?
