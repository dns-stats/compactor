#!/usr/bin/env bash
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# Check that running from pcap->cbor->pseudo-anonymised pcap produces
# different IP addresses for IPv4 src and dst, IPv6 src and dst,
# and IPv4 EDNS0 client subnet. We don't have any data with IPv6 client
# subnets yet.

COMP=./compactor
INSP=./inspector

DEFAULTS="--defaultsfile $srcdir/test-scripts/test.defaults"

INPUT_FILES="nsd-live.raw.pcap knot-live.raw.pcap"

#set -x

command -v comm > /dev/null 2>&1 || { echo "No comm, skipping test." >&2; exit 77; }
command -v tshark > /dev/null 2>&1 || { echo "No tshark, skipping test." >&2; exit 77; }

tmpdir=`mktemp -d -t "pseudoanon-output.XXXXXX"`

cleanup()
{
    rm -rf $tmpdir
    exit $1
}

trap "cleanup 1" HUP INT TERM

# Error if a line in $1 is the same as the corresponding line in $2
cmpfiles()
{
    comm -12 $1 $2 > $tmpdir/comm.out
    if [ -s $tmpdir/comm.out ]; then
        cleanup 1
    fi
}

for DATAFILE in $INPUT_FILES
do
    ANONDATAFILE=anon-$DATAFILE

    # Run the converter.
    $COMP -c /dev/null -n all -o $tmpdir/$DATAFILE.cdns $DATAFILE
    if [ $? -ne 0 ]; then
        echo "Compactor failed"
        cleanup 1
    fi

    $INSP $DEFAULTS -P test -p -o $tmpdir/$ANONDATAFILE $tmpdir/$DATAFILE.cdns
    if [ $? -ne 0 ]; then
        echo "Inspector failed"
        cleanup 1
    fi

    tshark -n -T fields -e frame.time -e ip.src -e ip.dst -r $DATAFILE ip.src | sort > $tmpdir/$DATAFILE.ip
    if [ $? -ne 0 ]; then
        echo "tshark failed"
        cleanup 1
    fi
    tshark -n -T fields -e frame.time -e ip.src -e ip.dst -r $tmpdir/$ANONDATAFILE ip.src | sort > $tmpdir/$ANONDATAFILE.ip
    if [ $? -ne 0 ]; then
        echo "tshark failed"
        cleanup 1
    fi

    tshark -n -T fields -e frame.time -e ipv6.src -e ipv6.dst -r $DATAFILE ipv6.src | sort > $tmpdir/$DATAFILE.ip6
    if [ $? -ne 0 ]; then
        echo "tshark failed"
        cleanup 1
    fi
    tshark -n -T fields -e frame.time -e ipv6.src -e ipv6.dst -r $tmpdir/$ANONDATAFILE ipv6.src | sort > $tmpdir/$ANONDATAFILE.ip6
    if [ $? -ne 0 ]; then
        echo "tshark failed"
        cleanup 1
    fi

    tshark -n -T fields -e frame.time -e dns.opt.client.addr4 -r $DATAFILE dns.opt.client.addr4 | sort > $tmpdir/$DATAFILE.ecs4
    if [ $? -ne 0 ]; then
        echo "tshark failed"
        cleanup 1
    fi
    tshark -n -T fields -e frame.time -e dns.opt.client.addr4 -r $tmpdir/$ANONDATAFILE dns.opt.client.addr4 | sort > $tmpdir/$ANONDATAFILE.ecs4
    if [ $? -ne 0 ]; then
        echo "tshark failed"
        cleanup 1
    fi

    cmpfiles $tmpdir/$DATAFILE.ip $tmpdir/$ANONDATAFILE.ip
    cmpfiles $tmpdir/$DATAFILE.ip6 $tmpdir/$ANONDATAFILE.ip6
    cmpfiles $tmpdir/$DATAFILE.ecs4 $tmpdir/$ANONDATAFILE.ecs4
done

cleanup 0
