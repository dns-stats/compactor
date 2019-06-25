#!/bin/sh
# 
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# Check that excluded data requires defaults to generate PCAP.

COMP=./compactor
INSP=./inspector

DEFAULTS="--defaultsfile $srcdir/test-scripts/test.defaults"

DATAFILE=./dns.pcap

command -v mktemp > /dev/null 2>&1 || { echo "No mktemp, skipping test." >&2; exit 77; }

tmpdir=`mktemp -d -t "check-defaults-required.XXXXXX"`

cleanup()
{
    rm -rf $tmpdir
    exit $1
}

trap "cleanup 1" HUP INT TERM

# Create an excluded fields file.
cat > $tmpdir/excludes.conf <<EOF
[ip-header]
client-address

[dns-header]
transaction-id
query-rcode

[dns-payload]
query-name
query-class-type
rr-ttl
EOF

# Run the converter with excluded data.
$COMP -c /dev/null --excludesfile $tmpdir/excludes.conf --omit-system-id -o $tmpdir/out.cbor $DATAFILE
if [ $? -ne 0 ]; then
    cleanup 1
fi

$INSP -o $tmpdir/out.pcap $tmpdir/out.cbor
if [ $? -eq 0 ]; then
    echo "No defaults, should fail."
    cleanup 1
fi

# Add client address default.
cat > $tmpdir/defaults.conf <<EOF
[ip-header]
client-address=192.168.1.1
EOF

$INSP -o $tmpdir/out.pcap r/defaults.conf $tmpdir/out.cbor
if [ $? -eq 0 ]; then
    echo "Too few defaults, should fail."
    cleanup 1
fi

# Add client address default.
cat >> $tmpdir/defaults.conf <<EOF
[dns-header]
transaction-id=1234
EOF

$INSP -o $tmpdir/out.pcap --defaultsfile $tmpdir/defaults.conf $tmpdir/out.cbor
if [ $? -eq 0 ]; then
    echo "Too few defaults, should fail."
    cleanup 1
fi

# Add client address default.
cat >> $tmpdir/defaults.conf <<EOF
query-rcode=NoError
EOF

$INSP -o $tmpdir/out.pcap --defaultsfile $tmpdir/defaults.conf $tmpdir/out.cbor
if [ $? -eq 0 ]; then
    echo "Too few defaults, should fail."
    cleanup 1
fi

# Add qname default.
cat >> $tmpdir/defaults.conf <<EOF
[dns-payload]
query-name=example.com
EOF

$INSP -o $tmpdir/out.pcap --defaultsfile $tmpdir/defaults.conf $tmpdir/out.cbor
if [ $? -eq 0 ]; then
    echo "Too few defaults, should fail."
    cleanup 1
fi

# Add client address default.
cat >> $tmpdir/defaults.conf <<EOF
query-class=IN
EOF

$INSP -o $tmpdir/out.pcap --defaultsfile $tmpdir/defaults.conf $tmpdir/out.cbor
if [ $? -eq 0 ]; then
    echo "Too few defaults, should fail."
    cleanup 1
fi

# Add client address default.
cat >> $tmpdir/defaults.conf <<EOF
query-type=A
EOF

$INSP -o $tmpdir/out.pcap --defaultsfile $tmpdir/defaults.conf $tmpdir/out.cbor
if [ $? -eq 0 ]; then
    echo "Too few defaults, should fail."
    cleanup 1
fi

# Add rr-ttl default. And now it would work if just on hints, but fails
# because we now demand all defaults be present.
cat >> $tmpdir/defaults.conf <<EOF
rr-ttl=128
EOF

$INSP -o $tmpdir/out.pcap --defaultsfile $tmpdir/defaults.conf $tmpdir/out.cbor
if [ $? -eq 0 ]; then
    echo "Too few defaults, should fail."
    cleanup 1
fi

# Finally, run with the master test defaults and it should work.
$INSP $DEFAULTS -o $tmpdir/out.pcap $tmpdir/out.cbor
if [ $? -ne 0 ]; then
    cleanup 1
fi

cleanup 0
