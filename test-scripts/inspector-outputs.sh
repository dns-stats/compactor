#!/bin/sh
# 
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# Check the inspector produces expected output files and reports.

COMP=./compactor
INSP=./inspector

DEFAULTS="--defaultsfile $srcdir/test-scripts/test.defaults"

DATAFILE=./dns.pcap

command -v diff > /dev/null 2>&1 || { echo "No diff, skipping test." >&2; exit 77; }
command -v mktemp > /dev/null 2>&1 || { echo "No mktemp, skipping test." >&2; exit 77; }
command -v tail > /dev/null 2>&1 || { echo "No tail, skipping test." >&2; exit 77; }

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
$INSP $DEFAULTS -o $tmpdir/out.pcap $tmpdir/out.cbor
if [ $? -ne 0 ]; then
    cleanup 1
fi

# -R. Expect stdout to produce same output as previous .info.
# Strip off initial "INPUT: " line.
$INSP $DEFAULTS --report-only $tmpdir/out.cbor | tail -n +3 > $tmpdir/out.report-only
if [ $? -ne 0 ]; then
    cleanup 1
fi

# -r. Expect stdout to produce same output as previous .info, plus
# info file and pcap output. Strip off initial " INPUT:" and " OUTPUT:" lines
# from stdout.
$INSP $DEFAULTS --report-info -o $tmpdir/out2.pcap $tmpdir/out.cbor | tail -n +4 > $tmpdir/out2.report
if [ $? -ne 0 ]; then
    cleanup 1
fi

# -I. Expect only .info to be produced.
$INSP $DEFAULTS --info-only -o $tmpdir/out3.pcap $tmpdir/out.cbor
if [ $? -ne 0 ]; then
    cleanup 1
fi

# -r -I. Expect stdout to produce same output as previous .info, plus
# info file but no pcap output. Strip off initial " INPUT:" and " OUTPUT:"
# lines from stdout.
$INSP $DEFAULTS --report-info --info-only -o $tmpdir/out4.pcap $tmpdir/out.cbor | tail -n +4 > $tmpdir/out4.report
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
