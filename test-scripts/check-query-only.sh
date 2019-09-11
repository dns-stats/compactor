#!/bin/sh
# 
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# Check that excluding all replies works. Test for excluding all response
# fields, and a separate test for not capturing replies via filter.

COMP=./compactor
INSP=./inspector

DEFAULTS="--defaultsfile $srcdir/test-scripts/test.defaults"

TCPDUMP=/usr/sbin/tcpdump

DATAFILE=./dns.pcap

command -v diff > /dev/null 2>&1 || { echo "No diff, skipping test." >&2; exit 77; }
command -v mktemp > /dev/null 2>&1 || { echo "No mktemp, skipping test." >&2; exit 77; }
command -v $TCPDUMP > /dev/null 2>&1 || { echo "No tcpdump, skipping test." >&2; exit 77; }

tmpdir=`mktemp -d -t "check-query-only.XXXXXX"`

cleanup()
{
    rm -rf $tmpdir
    exit $1
}

trap "cleanup 1" HUP INT TERM

# Create an excluded fields file.
cat > $tmpdir/excludes.conf <<EOF
[dns-header]
transaction-id
response-rcode

[dns-payload]
rr-ttl
rr-rdata
response-answer-sections
response-authority-sections
response-additional-sections
EOF

# Create defaults for the above.
cat > $tmpdir/defaults.conf <<EOF
[dns-header]
transaction-id=1234
response-rcode=NOERROR

[dns-payload]
rr-ttl=128
rr-rdata=
EOF

# Run the converter with excluded data.
$COMP -c /dev/null --excludesfile $tmpdir/excludes.conf -o $tmpdir/out-exclude.cbor $DATAFILE
if [ $? -ne 0 ]; then
    cleanup 1
fi

$INSP $DEFAULTS -o $tmpdir/out-exclude.pcap $tmpdir/out-exclude.cbor
if [ $? -ne 0 ]; then
    echo "Can't regenerate when no response data."
    cleanup 1
fi

TZ=GMT $TCPDUMP -c 2 -n -r $tmpdir/out-exclude.pcap > $tmpdir/out-exclude.txt
if [ $? -ne 0 ]; then
    echo "tcpdump failed on exclude."
    cleanup 1
fi

cat > $tmpdir/out-exclude.gold <<EOF
15:52:14.321102 IP 22.58.218.199.44878 > 22.58.218.195.53: 1234+ AAAA? www.wind-energy-the-facts.org. (47)
15:52:14.321181 IP 22.58.218.195.53 > 22.58.218.199.44878: 1234- 0/0/0 (47)
EOF

# Run the converter using filter to exclude responses.
$COMP -c /dev/null --filter "dst host 22.58.218.195" -o $tmpdir/out-filter.cbor $DATAFILE
if [ $? -ne 0 ]; then
    cleanup 1
fi

$INSP $DEFAULTS -o $tmpdir/out-filter.pcap $tmpdir/out-filter.cbor
if [ $? -ne 0 ]; then
    echo "Can't regenerate when no response data."
    cleanup 1
fi

TZ=GMT $TCPDUMP -c 2 -n -r $tmpdir/out-filter.pcap > $tmpdir/out-filter.txt
if [ $? -ne 0 ]; then
    echo "tcpdump failed on filter."
    cleanup 1
fi

cat > $tmpdir/out-filter.gold <<EOF
15:52:14.321102 IP 22.58.218.199.44878 > 22.58.218.195.53: 1331+ AAAA? www.wind-energy-the-facts.org. (47)
15:52:14.331106 IP 22.58.218.199.44878 > 22.58.218.195.53: 1332+ A? smtp.cbi.com. (30)
EOF

diff -q $tmpdir/out-exclude.txt $tmpdir/out-exclude.gold &&
    diff -q $tmpdir/out-filter.txt $tmpdir/out-filter.gold
cleanup $?
