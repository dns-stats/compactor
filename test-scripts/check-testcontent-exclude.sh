#!/bin/sh
# 
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# Check that test content C-DNS values are as expected when excludes
# are specified. See check-testcontent.sh. Exclude client and server
# address and port so we check Q/R and Q/R sig.

COMP=./compactor
INSP=./inspector
CBOR2DIAG=cbor2diag.rb

DEFAULTS="--defaultsfile $srcdir/test-scripts/test.defaults"

DATAFILE=./testcontent.pcap
DATADIAG=$srcdir/test-scripts/testcontent-exclude.diag
EXCLUDE=$srcdir/test-scripts/testcontent-exclude.conf
DATADIAG_SIGFLAGS=$srcdir/test-scripts/testcontent-exclude-sigflags.diag
EXCLUDE_SIGFLAGS=$srcdir/test-scripts/testcontent-exclude-sigflags.conf
DATADIAG_SIG=$srcdir/test-scripts/testcontent-exclude-sig.diag
EXCLUDE_SIG=$srcdir/test-scripts/testcontent-exclude-sig.conf

command -v $CBOR2DIAG > /dev/null 2>&1 || { echo "No cbor2diag, skipping test." >&2; exit 77; }
command -v cmp > /dev/null 2>&1 || { echo "No cmp, skipping test." >&2; exit 77; }
command -v diff > /dev/null 2>&1 || { echo "No diff, skipping test." >&2; exit 77; }
command -v mktemp > /dev/null 2>&1 || { echo "No mktemp, skipping test." >&2; exit 77; }

tmpdir=`mktemp -d -t "check-testcontent-exclude.XXXXXX"`

cleanup()
{
    rm -rf $tmpdir
    exit $1
}

trap "cleanup 1" HUP INT TERM


# Check compactor fails when given excludes AND include.
$COMP -c /dev/null --excludesfile $EXCLUDE -n all --omit-system-id -o $tmpdir/out.cbor $DATAFILE
if [ $? -eq 0 ]; then
    cleanup 1
fi

$COMP -c /dev/null --excludesfile $EXCLUDE --omit-system-id -o $tmpdir/out.cbor $DATAFILE
if [ $? -ne 0 ]; then
    cleanup 1
fi

$CBOR2DIAG $tmpdir/out.cbor > $tmpdir/out.diag
if [ $? -ne 0 ]; then
    cleanup 1
fi

diff -u -i $tmpdir/out.diag $DATADIAG
if [ $? -ne 0 ]; then
    cleanup 1
fi

$INSP $DEFAULTS --excludesfile --no-info --no-output -o $tmpdir/out.pcap $tmpdir/out.cbor
if [ $? -ne 0 ]; then
    cleanup 1
fi

cmp -s $tmpdir/out.pcap.excludesfile $EXCLUDE
if [ $? -ne 0 ]; then
    echo "Generated excludes file does not match $EXCLUDE."
    cleanup 1
fi

# Prepare a full info C-DNS and the inspector output from that.
$COMP -c /dev/null --omit-system-id -n all -o $tmpdir/out-all.cbor $DATAFILE
if [ $? -ne 0 ]; then
    cleanup 1
fi

$INSP $DEFAULTS --no-info -o $tmpdir/out-all.pcap $tmpdir/out-all.cbor
if [ $? -ne 0 ]; then
    cleanup 1
fi

# Now a C-DNS omitting only qr-sig-flags.
$COMP -c /dev/null --excludesfile $EXCLUDE_SIGFLAGS --omit-system-id -o $tmpdir/out-sigflags.cbor $DATAFILE
if [ $? -ne 0 ]; then
    cleanup 1
fi

$CBOR2DIAG $tmpdir/out-sigflags.cbor > $tmpdir/out-sigflags.diag
if [ $? -ne 0 ]; then
    cleanup 1
fi

diff -u -i $tmpdir/out-sigflags.diag $DATADIAG_SIGFLAGS
if [ $? -ne 0 ]; then
    echo "sigflags: diag differs"
    cleanup 1
fi

# Run that through inspector, and we should get identical output
# to the full info inspector output, because we always have the info to
# re-create the Q/R flags.
$INSP $DEFAULTS --excludesfile --no-info -o $tmpdir/out-sigflags.pcap $tmpdir/out-sigflags.cbor
if [ $? -ne 0 ]; then
    cleanup 1
fi

cmp -s $tmpdir/out-sigflags.pcap $tmpdir/out-all.pcap
if [ $? -ne 0 ]; then
    echo "sigflags: Inspector output does not match."
    cleanup 1
fi

cmp -s $tmpdir/out-sigflags.pcap.excludesfile $EXCLUDE_SIGFLAGS
if [ $? -ne 0 ]; then
    echo "Generated excludes file does not match $EXCLUDE_SIGFLAGS."
    cleanup 1
fi

# Now try with entire signature omitted.
$COMP -c /dev/null --excludesfile $EXCLUDE_SIG --omit-system-id -o $tmpdir/out-sig.cbor $DATAFILE
if [ $? -ne 0 ]; then
    cleanup 1
fi

$CBOR2DIAG $tmpdir/out-sig.cbor > $tmpdir/out-sig.diag
if [ $? -ne 0 ]; then
    cleanup 1
fi

diff -u -i $tmpdir/out-sig.diag $DATADIAG_SIG
if [ $? -ne 0 ]; then
    echo "sig: diag differs"
    cleanup 1
fi

$INSP $DEFAULTS --excludesfile --no-output --no-info -o $tmpdir/out-sig.pcap $tmpdir/out-sig.cbor
if [ $? -ne 0 ]; then
    cleanup 1
fi

cmp -s $tmpdir/out-sig.pcap.excludesfile $EXCLUDE_SIG
if [ $? -ne 0 ]; then
    echo "Generated excludes file does not match $EXCLUDE_SIG."
    cleanup 1
fi

cleanup $?
