#!/bin/sh
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# Check that inspector generates response OPTs when necessary.

COMP='./compactor --extended-qrsig-mode'
INSP=./inspector
DATAFILE=./cookie.pcap

DEFAULTS="--defaultsfile $srcdir/test-scripts/test.defaults"

command -v diff > /dev/null 2>&1 || { echo "No diff, skipping test." >&2; exit 77; }
command -v mktemp > /dev/null 2>&1 || { echo "No mktemp, skipping test." >&2; exit 77; }
command -v sed > /dev/null 2>&1 || { echo "No sed, skipping test." >&2; exit 77; }
command -v tshark > /dev/null 2>&1 || { echo "No tshark, skipping test." >&2; exit 77; }

tmpdir=`mktemp -d -t "check-response-opt.XXXXXX"`

cleanup()
{
    if [ $1 -ne 0 ]; then
      localdir=FAILED_TEST_RESUTLS_$(basename "$0")
      rm -rf $localdir
      mkdir $localdir
      cp $tmpdir/* $localdir
    fi
    rm -rf $tmpdir
    exit $1
}

trap "cleanup 1" HUP INT TERM

# Run the compactor recording minimal data.
$COMP -c /dev/null -o $tmpdir/out.cdns $DATAFILE
if [ $? -ne 0 ]; then
    cleanup 1
fi

# Convert back to PCAP.
$INSP $DEFAULTS -o $tmpdir/out.pcap $tmpdir/out.cdns
if [ $? -ne 0 ]; then
    cleanup 1
fi

# Get detailed text description of first query and extract the
# bit that should be about the OPT.
tshark -c 2 -T text -r $tmpdir/out.pcap -Y dns.flags.response==0 -V | \
    sed -e "1,/OPT/d" -e "/Request In:/,\$d" -e "s/^            //" -e "/^$/d" > $tmpdir/opt.txt
if [ $? -ne 0 ]; then
    cleanup 1
fi

# Tshark 4.2.2 has trailing whitespace that needs to be stripped
sed -i -e 's/[ \t]*$//' $tmpdir/opt.txt

# Make text file with expected responses.
cat > $tmpdir/opt.gold <<EOF
Name: <Root>
Type: OPT (41)
UDP payload size: 4096
Higher bits in extended RCODE: 0x00
EDNS0 version: 0
Z: 0x8000
    1... .... .... .... = DO bit: Accepts DNSSEC security RRs
    .000 0000 0000 0000 = Reserved: 0x0000
Data length: 12
Option: COOKIE
    Option Code: COOKIE (10)
    Option Length: 8
    Option Data: 0000000000000000
    Client Cookie: 0000000000000000
    Server Cookie: <MISSING>
EOF

diff $tmpdir/opt.gold $tmpdir/opt.txt
cleanup $?
