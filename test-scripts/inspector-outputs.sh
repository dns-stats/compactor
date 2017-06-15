#!/bin/sh
# 
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# Check the inspector produces expected output files and reports.

COMP=./compactor
INSP=./inspector
DATAFILE=./dns.pcap

tmpdir=`mktemp -d -t "inspector-outputs.XXXXXX"`

cleanup()
{
    rm -rf $tmpdir
    exit $1
}

trap "cleanup 1" HUP INT TERM

# Run the converter.
$COMP -c /dev/null -o $tmpdir/out.cbor $DATAFILE
if [ $? -ne 0 ]; then
    cleanup 1
fi

# No arguments. Expect .info and named output.
$INSP -o $tmpdir/out.pcap $tmpdir/out.cbor
if [ $? -ne 0 ]; then
    cleanup 1
fi

# -R. Expect stdout to produce same output as previous .info.
# Strip off initial "INPUT: " line.
$INSP --report-only $tmpdir/out.cbor | tail -n +3 > $tmpdir/out.report-only
if [ $? -ne 0 ]; then
    cleanup 1
fi

# -r. Expect stdout to produce same output as previous .info, plus
# info file and pcap output. Strip off initial " INPUT:" and " OUTPUT:" lines
# from stdout.
$INSP --report-info -o $tmpdir/out2.pcap $tmpdir/out.cbor | tail -n +4 > $tmpdir/out2.report
if [ $? -ne 0 ]; then
    cleanup 1
fi

# -I. Expect only .info to be produced.
$INSP --info-only -o $tmpdir/out3.pcap $tmpdir/out.cbor
if [ $? -ne 0 ]; then
    cleanup 1
fi

# -r -I. Expect stdout to produce same output as previous .info, plus
# info file but no pcap output. Strip off initial " INPUT:" and " OUTPUT:"
# lines from stdout.
$INSP --report-info --info-only -o $tmpdir/out4.pcap $tmpdir/out.cbor | tail -n +4 > $tmpdir/out4.report
if [ $? -ne 0 ]; then
    cleanup 1
fi

test -f $tmpdir/out.pcap -a -f $tmpdir/out.pcap.info -a ! \( -f $tmpdir/out3.pcap \) -a ! \( -f $tmpdir/out4.pcap \) &&
    diff -q $tmpdir/out.pcap.info $tmpdir/out.report-only &&
    diff -q $tmpdir/out.pcap.info $tmpdir/out2.report &&
    diff -q $tmpdir/out.pcap.info $tmpdir/out2.pcap.info &&
    diff -q $tmpdir/out.pcap.info $tmpdir/out3.pcap.info &&
    diff -q $tmpdir/out.pcap.info $tmpdir/out4.report &&
    diff -q $tmpdir/out.pcap.info $tmpdir/out4.pcap.info
cleanup $?
