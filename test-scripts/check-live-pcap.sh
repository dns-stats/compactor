#!/bin/sh
# 
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# Check a live PCAP. Take the raw capture, convert it to CBOR and back
# to PCAP. Take that PCAP, merge it with the ignored PCAP from the capture.
#
# Then:
# i)  Check that the .info from the CBOR->PCAP conversion matches the
#     golden value.
# ii) Do a comparison of the original raw PCAP and the reconstructed
#     PCAP. At the moment this means getting a line per packet description
#     out of tcpdump (and, so keep things really simple, only considering
#     UDP port 53 traffic), and counting the number of differences. We
#     expect there to be some, but fail if the number is not that
#     expected. Rmember the inspector puts out packets in query/response
#     pairs, so sort the output from tcpdump before comparing.

COMP=./compactor
INSP=./inspector

TCPDUMP=/usr/sbin/tcpdump

command -v cmp > /dev/null 2>&1 || { echo "No cmp, skipping test." >&2; exit 77; }
command -v diff > /dev/null 2>&1 || { echo "No diff, skipping test." >&2; exit 77; }
command -v mergecap > /dev/null 2>&1 || { echo "No mergecap, skipping test." >&2; exit 77; }
command -v $TCPDUMP > /dev/null 2>&1 || { echo "No tcpdump, skipping test." >&2; exit 77; }

tmpdir=$(mktemp -d -t "check_live_pcap.XXXXXX")

cleanup()
{
    rm -rf $tmpdir
    exit $1
}

trap "cleanup 1" HUP INT TERM

usage()
{
    echo "Usage: check_live_pcap.sh <basename> <expected error number>"
    echo "Input files <basename>.raw.pcap, <basename>.ignored.pcap, <basename>.info"
    echo "must exist."
    exit 1
}

error()
{
    echo $1
    cleanup 1
}

if [ $# != 2 ]; then
    usage
fi

GOLDRAW=$1.raw.pcap
GOLDIGNORED=$1.ignored.pcap
GOLDINFO=$srcdir/test-scripts/$1.info
EXPECTED_ERRS=$2

if [ ! \( -r $GOLDRAW -a -r $GOLDIGNORED -a -r $GOLDINFO \) ]; then
    error "Missing input file"
fi

# Convert to CBOR and back.
$COMP -c /dev/null --omit-system-id -n all -o $tmpdir/gold.cbor $GOLDRAW
if [ $? -ne 0 ]; then
    error "compactor failed"
fi

$INSP -o $tmpdir/gold.cbor.pcap $tmpdir/gold.cbor
if [ $? -ne 0 ]; then
    error "inspector failed"
fi

cmp -s $tmpdir/gold.cbor.pcap.info $GOLDINFO
if [ $? -ne 0 ]; then
    error ".info does not match"
fi

mergecap -w $tmpdir/gold.merged.pcap $tmpdir/gold.cbor.pcap $GOLDIGNORED
if [ $? -ne 0 ]; then
    error "mergecap failed"
fi

$TCPDUMP -n -r $tmpdir/gold.merged.pcap udp port 53 2> /dev/null | sort > $tmpdir/gold.merged.pcap.dump
if [ $? -ne 0 ]; then
    error "tcpdump failed"
fi
$TCPDUMP -n -r $GOLDRAW udp port 53 2> /dev/null | sort > $tmpdir/gold.raw.pcap.dump
if [ $? -ne 0 ]; then
    error "tcpdump 2 failed"
fi

diff -y -W 320 --suppress-common-lines $tmpdir/gold.raw.pcap.dump $tmpdir/gold.merged.pcap.dump > $tmpdir/diff.out
if [ $? -eq 2 ]; then
    error "diff failed"
fi
errcount=$(cat $tmpdir/diff.out | wc -l)
if [ $errcount -ne $EXPECTED_ERRS ]; then
    error "Wrong number of errors: $errcount != $EXPECTED_ERRS"
fi

cleanup 0
