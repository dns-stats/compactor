#!/bin/sh
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# Check that test content stats values are as expected.
#
# The test content starts with 2 non-DNS packets and is otherwise
# 3 unanswered queries, each with an ICMP immediately following.

COMP=./compactor
INSP=./inspector

DEFAULTS="--defaultsfile $srcdir/test-scripts/test.defaults"

DATAFILE=$srcdir/test-scripts/teststats.pcap
STATSINFO=$srcdir/test-scripts/teststats.info

command -v diff > /dev/null 2>&1 || { echo "No diff, skipping test." >&2; exit 77; }
command -v sed > /dev/null 2>&1 || { echo "No sed, skipping test." >&2; exit 77; }
command -v mktemp > /dev/null 2>&1 || { echo "No mktemp, skipping test." >&2; exit 77; }

tmpdir=`mktemp -d -t "check-stats.XXXXXX"`

cleanup()
{
    #rm -rf $tmpdir
    exit $1
}

trap "cleanup 1" HUP INT TERM

$COMP -c /dev/null --omit-system-id -n all -o $tmpdir/out.cbor $DATAFILE
if [ $? -ne 0 ]; then
    cleanup 1
fi

$INSP $DEFAULTS --no-output $tmpdir/out.cbor
if [ $? -ne 0 ]; then
    cleanup 1
fi

sed -e "1,/STATISTICS/d" $tmpdir/out.cbor.pcap.info > $tmpdir/out.info
diff -q $tmpdir/out.info $STATSINFO
cleanup $?
