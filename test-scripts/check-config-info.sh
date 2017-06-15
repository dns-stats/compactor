#!/bin/sh
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# Check that main configuration info is correct in .info.

COMP=./compactor
INSP=./inspector
DATAFILE=./dns.pcap

tmpdir=`mktemp -d -t "check-config-info.XXXXXX"`

cleanup()
{
    rm -rf $tmpdir
    exit $1
}

error()
{
    echo $1
    cleanup 1
}

trap "cleanup 1" HUP INT TERM

# Run the converter producing CBOR with non-default configs.
$COMP -c /dev/null --query-timeout 2 --skew-timeout 5 --snaplen 200 --promiscuous-mode=true --filter "ip" --max-block-qr-items 2000 --include all --vlan-id 1234 --accept-rr-type AAAA --server-address-hint 1.2.3.4 -o $tmpdir/out.cbor $DATAFILE
if [ $? -ne 0 ]; then
    cleanup 1
fi

# Produce the .info file.
$INSP -I $tmpdir/out.cbor

grep "Query timeout *: 2 seconds" $tmpdir/out.cbor.pcap.info > /dev/null
if [ $? -ne 0 ]; then
    error "Bad query timeout"
fi

grep "Skew timeout *: 5 microseconds" $tmpdir/out.cbor.pcap.info > /dev/null
if [ $? -ne 0 ]; then
    error "Bad skew timeout"
fi

grep "Snap length *: 200$" $tmpdir/out.cbor.pcap.info > /dev/null
if [ $? -ne 0 ]; then
    error "Bad snap length"
fi

grep "Max block items *: 2000$" $tmpdir/out.cbor.pcap.info > /dev/null
if [ $? -ne 0 ]; then
    error "Bad max block items"
fi

grep "Promiscuous mode *: On$" $tmpdir/out.cbor.pcap.info > /dev/null
if [ $? -ne 0 ]; then
    error "Bad promiscuous mode"
fi

grep "Server addresses *: 1.2.3.4$" $tmpdir/out.cbor.pcap.info > /dev/null
if [ $? -ne 0 ]; then
    error "Bad server addresses"
fi

grep "VLAN IDs *: 1234$" $tmpdir/out.cbor.pcap.info > /dev/null
if [ $? -ne 0 ]; then
    error "Bad VLAN IDs"
fi

grep "Filter *: ip$" $tmpdir/out.cbor.pcap.info > /dev/null
if [ $? -ne 0 ]; then
    error "Bad filter"
fi

grep "Query options *: Extra questions, Answers, Authorities, Additionals$" $tmpdir/out.cbor.pcap.info > /dev/null
if [ $? -ne 0 ]; then
    error "Bad query options"
fi

grep "Response options *: Extra questions, Answers, Authorities, Additionals$" $tmpdir/out.cbor.pcap.info > /dev/null
if [ $? -ne 0 ]; then
    error "Bad response options"
fi

grep "Accept RR types *: AAAA$" $tmpdir/out.cbor.pcap.info > /dev/null
if [ $? -ne 0 ]; then
    error "Bad accept RR types"
fi

cleanup 0
