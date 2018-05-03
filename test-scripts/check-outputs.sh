#!/bin/sh
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# Check that running the conversion produces the expected output files.

COMP=./compactor
DATAFILE=./malformed.pcap

command -v mktemp > /dev/null 2>&1 || { echo "No mktemp, skipping test." >&2; exit 77; }

tmpdir=`mktemp -d -t "check-outputs.XXXXXX"`

cleanup()
{
    rm -rf $tmpdir
    exit $1
}

trap "cleanup 1" HUP INT TERM

# Run the converter producing raw pcap, ignored pcap and CBOR.
$COMP -c /dev/null --raw-pcap $tmpdir/raw.pcap --ignored-pcap $tmpdir/ignored.pcap -o $tmpdir/out.cbor $DATAFILE
if [ $? -ne 0 ]; then
    cleanup 1
fi

if [ ! \( -s $tmpdir/raw.pcap -a -s $tmpdir/ignored.pcap -a -s $tmpdir/out.cbor \) ]; then
    cleanup 1
fi

$COMP -c /dev/null --gzip-output --gzip-pcap --raw-pcap $tmpdir/raw.pcap --ignored-pcap $tmpdir/ignored.pcap -o $tmpdir/out.cbor $DATAFILE
if [ $? -ne 0 ]; then
    cleanup 1
fi

if [ ! \( -s $tmpdir/raw.pcap.gz -a -s $tmpdir/ignored.pcap.gz -a -s $tmpdir/out.cbor.gz \) ]; then
    cleanup 1
fi

$COMP -c /dev/null --xz-output --xz-pcap --raw-pcap $tmpdir/raw.pcap --ignored-pcap $tmpdir/ignored.pcap -o $tmpdir/out.cbor $DATAFILE
if [ $? -ne 0 ]; then
    cleanup 1
fi

if [ ! \( -s $tmpdir/raw.pcap.xz -a -s $tmpdir/ignored.pcap.xz -a -s $tmpdir/out.cbor.xz \) ]; then
    cleanup 1
fi

cleanup 0
