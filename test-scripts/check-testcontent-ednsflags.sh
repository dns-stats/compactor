#!/bin/sh
# 
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# Check that test content C-DNS values are as expected, and --debug-qr
# output is as expected.
#
# Specifically test the new edns flag handling (CO and DE).
#
# There are problems currently with cbor2json (which crashes on the
# strings) and cbor2yaml (which breaks binary string content into
# output lines on xenial but not on mac). cbor2diag is consistent,
# so use that.

COMP=./compactor
INSP=./inspector

DEFAULTS="--defaultsfile $srcdir/test-scripts/test.defaults"

CBOR2DIAG=cbor2diag.rb
DATAFILE=./testcontent-ednsflags.pcap
DATADIAG=$srcdir/test-scripts/testcontent-ednsflags.diag
DATAQR=$srcdir/test-scripts/testcontent-ednsflags.debugqr
DATADUMP=$srcdir/test-scripts/testcontent-ednsflags.dump
TEMPLATE=$srcdir/test-scripts/test-block.tpl

command -v $CBOR2DIAG > /dev/null 2>&1 || { echo "No cbor2diag, skipping test." >&2; exit 77; }
command -v cmp > /dev/null 2>&1 || { echo "No cmp, skipping test." >&2; exit 77; }
command -v diff > /dev/null 2>&1 || { echo "No diff, skipping test." >&2; exit 77; }
command -v mktemp > /dev/null 2>&1 || { echo "No mktemp, skipping test." >&2; exit 77; }

tmpdir=`mktemp -d -t "check-testcontent-ednsflags.XXXXXX"`

cleanup()
{
    rm -rf $tmpdir
    exit $1
}

trap "cleanup 1" HUP INT TERM

$COMP -c /dev/null --omit-system-id -n all -o $tmpdir/out.cbor $DATAFILE
if [ $? -ne 0 ]; then
    cleanup 1
fi

$INSP $DEFAULTS --debug-qr $tmpdir/out.cbor > $tmpdir/out.debugqr
if [ $? -ne 0 ]; then
    cleanup 1
fi

$CBOR2DIAG $tmpdir/out.cbor > $tmpdir/out.diag
if [ $? -ne 0 ]; then
    cleanup 1
fi

# Template output
$INSP -o - -F template -g . -t $TEMPLATE --value node=42 $tmpdir/out.cbor > $tmpdir/out.dump
if [ $? -ne 0 ]; then
    error "dumper failed (2)"
fi

diff -i $tmpdir/out.debugqr $DATAQR &&
    diff -i $tmpdir/out.diag $DATADIAG &&
      diff -i $tmpdir/out.dump $DATADUMP
cleanup $?
