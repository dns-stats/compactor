#!/bin/sh
# 
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# Create the 'gold' data files. Run from the build dir.

COMP=./compactor
INSP=./inspector
DATAFILE=./dns.pcap
GOLD_CBORFILE=gold.cbor
GOLD_PCAPFILE=gold.pcap
GOLD_INFOFILE=gold.pcap.info

tmpdir=`mktemp -d -t "make-gold-files.XXXXXX"`

cleanup()
{
    rm -rf $tmpdir
    exit $1
}

trap "cleanup 1" HUP INT TERM

# First, the gold CBOR.
$COMP -c /dev/null -n all -g DLV --vlan-id 10 --filter "ip or ip6" --omit-system-id -o $tmpdir/$GOLD_CBORFILE $DATAFILE
if [ $? -ne 0 ]; then
    cleanup 1
fi

# Next the gold PCAP-from-CBOR.
$INSP -o $tmpdir/$GOLD_PCAPFILE $tmpdir/$GOLD_CBORFILE
if [ $? -ne 0 ]; then
    cleanup 1
fi

# Compress everything.
xz $tmpdir/$GOLD_CBORFILE $tmpdir/$GOLD_PCAPFILE
if [ $? -ne 0 ]; then
    cleanup 1
fi

# Success!
mv $tmpdir/* .
cleanup $?
