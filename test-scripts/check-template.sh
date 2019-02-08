#!/bin/sh
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# Check that running the conversion produces the expected output files.

COMP=./compactor
INSP=./inspector

command -v diff > /dev/null 2>&1 || { echo "No diff, skipping test." >&2; exit 77; }
command -v head > /dev/null 2>&1 || { echo "No head, skipping test." >&2; exit 77; }

tmpdir=`mktemp -d -t "check-template.XXXXXX"`

cleanup()
{
    rm -rf $tmpdir
    exit $1
}

trap "cleanup 1" HUP INT TERM

error()
{
    echo $1
    cleanup 1
}

RAW=nsd-live.raw.pcap
FMT=$srcdir/test-scripts/test-csv.tpl

if [ ! \( -r $RAW -a $FMT \) ]; then
    error "Missing input file"
fi

# Convert to C-DNS.
$COMP -c /dev/null --omit-system-id -n all -o $tmpdir/gold.cdns $RAW
if [ $? -ne 0 ]; then
    error "compactor failed"
fi

# Template output, first 100 lines.
$INSP -o - -F template -g . -t $FMT --value node=42 $tmpdir/gold.cdns > $tmpdir/gold.dump.full
if [ $? -ne 0 ]; then
    error "dumper failed"
fi
head -n 100 $tmpdir/gold.dump.full > $tmpdir/gold.dump
if [ $? -ne 0 ]; then
    error "head failed"
fi

diff -q $tmpdir/gold.dump nsd-live.dump
if [ $? -ne 0]; then
    error "CSV dump failed"
fi

RAW_EYEBALL=$srcdir/test-scripts/template.pcap
FMT_EYEBALL=$srcdir/test-scripts/test-block.tpl

if [ ! \( -r $RAW_EYEBALL -a $FMT_EYEBALL \) ]; then
    error "Missing input file"
fi

# Convert to C-DNS.
$COMP -c /dev/null --omit-system-id -n all -o $tmpdir/gold2.cdns $RAW_EYEBALL
if [ $? -ne 0 ]; then
    error "compactor failed"
fi

# Template output
$INSP -o - -F template -g . -t $FMT_EYEBALL --value node=42 $tmpdir/gold2.cdns > $tmpdir/gold2.dump
if [ $? -ne 0 ]; then
    error "dumper failed (2)"
fi

diff -q $tmpdir/gold2.dump $srcdir/test-scripts/template.dump
if [ $? -ne 0 ]; then
    error "Eyeball dump failed"
fi

cleanup 0
