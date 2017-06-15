#!/bin/sh
# 
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# Check that running tools against 'gold' data produces correct output.

COMP=./compactor
INSP=./inspector
DATAFILE=./dns.pcap
GOLD_CBORFILE=./gold.cbor
GOLD_PCAPFILE=./gold.pcap
GOLD_INFOFILE=$srcdir/test-scripts/gold.pcap.info

tmpdir=`mktemp -d -t "same-file-output.XXXXXX"`

cleanup()
{
    rm -rf $tmpdir
    exit $1
}

trap "cleanup 1" HUP INT TERM

# Run the converter.
$COMP -c /dev/null --omit-system-id -n all -g DLV --vlan-id 10 --filter "ip or ip6" -o $tmpdir/out.cbor $DATAFILE
if [ $? -ne 0 ]; then
    cleanup 1
fi

$INSP -o $tmpdir/out.pcap $tmpdir/out.cbor
if [ $? -ne 0 ]; then
    cleanup 1
fi

$INSP -o - $tmpdir/out.cbor > $tmpdir/out2.pcap
if [ $? -ne 0 ]; then
    cleanup 1
fi

cmp $tmpdir/out.cbor $GOLD_CBORFILE &&
    cmp $tmpdir/out.pcap $GOLD_PCAPFILE &&
    cmp $tmpdir/out2.pcap $GOLD_PCAPFILE &&
    cmp $tmpdir/out.pcap.info $GOLD_INFOFILE
cleanup $?
