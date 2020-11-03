#!/bin/sh
# 
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# Check that test content C-DNS start and end time values are as expected.
#
# There are problems currently with cbor2json (which crashes on the
# strings) and cbor2yaml (which breaks binary string content into
# output lines on xenial but not on mac). cbor2diag is consistent,
# so use that.

COMP=./compactor
INSP=./inspector

DEFAULTS="--defaultsfile $srcdir/test-scripts/test.defaults"

CBOR2DIAG=cbor2diag.rb
DATAFILE=./testcontent.pcap
BIGDATAFILE=./nsd-live.raw.pcap
DATADIAG=$srcdir/test-scripts/testcontent-endtime.diag
DATAINFO=$srcdir/test-scripts/testcontent-endtime.info
BIGDATAINFO=$srcdir/test-scripts/testcontent-endtime.big.info
BIGDATA2INFO=$srcdir/test-scripts/testcontent-endtime.big2.info

command -v $CBOR2DIAG > /dev/null 2>&1 || { echo "No cbor2diag, skipping test." >&2; exit 77; }
command -v cmp > /dev/null 2>&1 || { echo "No cmp, skipping test." >&2; exit 77; }
command -v diff > /dev/null 2>&1 || { echo "No diff, skipping test." >&2; exit 77; }
command -v mktemp > /dev/null 2>&1 || { echo "No mktemp, skipping test." >&2; exit 77; }

tmpdir=`mktemp -d -t "check-testcontent-endtime.XXXXXX"`

cleanup()
{
    rm -rf $tmpdir
    exit $1
}

trap "cleanup 1" HUP INT TERM

$COMP -c /dev/null --omit-system-id --start-end-times-from-data -n all -o $tmpdir/out.cbor $DATAFILE
if [ $? -ne 0 ]; then
    cleanup 1
fi

$CBOR2DIAG $tmpdir/out.cbor > $tmpdir/out.diag
if [ $? -ne 0 ]; then
    cleanup 1
fi

$INSP $DEFAULTS --info-only -o $tmpdir/out3.pcap $tmpdir/out.cbor
if [ $? -ne 0 ]; then
    cleanup 1
fi

$COMP -c /dev/null --omit-system-id -n all --max-output-size 500k -o $tmpdir/outbig.cbor $BIGDATAFILE
if [ $? -ne 0 ]; then
    cleanup 1
fi

$INSP $DEFAULTS --info-only -o $tmpdir/outbig.pcap $tmpdir/outbig.cbor
if [ $? -ne 0 ]; then
    cleanup 1
fi

$INSP $DEFAULTS --info-only -o $tmpdir/outbig.pcap2 $tmpdir/outbig.cbor-2
if [ $? -ne 0 ]; then
    cleanup 1
fi

diff -i $tmpdir/out.diag $DATADIAG &&
    diff -i $tmpdir/out3.pcap.info $DATAINFO &&
    diff -i $tmpdir/outbig.pcap.info $BIGDATAINFO &&
    diff -i $tmpdir/outbig.pcap2.info $BIGDATA2INFO
cleanup $?
