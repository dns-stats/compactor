#!/usr/bin/env bash
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# Check that running from pcap->cbor->pcap produces the same output

COMP=./compactor
INSP=./inspector

DEFAULTS="--defaultsfile $srcdir/test-scripts/test.defaults"

INPUT_FILES="matching.pcap unmatched.pcap"

#set -x

command -v diff > /dev/null 2>&1 || { echo "No diff, skipping test." >&2; exit 77; }
command -v sed > /dev/null 2>&1 || { echo "No sed, skipping test." >&2; exit 77; }
command -v tshark > /dev/null 2>&1 || { echo "No tshark, skipping test." >&2; exit 77; }
command -v mktemp > /dev/null 2>&1 || { echo "No mktemp, skipping test." >&2; exit 77; }

tmpdir=`mktemp -d -t "same-tshark-output.XXXXXX"`

cleanup()
{
    rm -rf $tmpdir
    exit $1
}

trap "cleanup 1" HUP INT TERM

call_tshark()
{
    # $1 == Input PCAP.
    # $2 = dns.id to select.
    # $3 = Base output file path.

    # Should be able to remove the last 2 deletions when we have name compression
     tshark -nr $1 -Y "dns.id==$2" -T text -V  >  $3.full
     sed -r -e '/Frame [0-9]/,/^.*\[Time shift/d' \
              -e '/^.*\[Time delta/,/Internet/d' \
              -e '/^.*\[Timestamps/d' \
              -e '/^.*\[Time since/d' \
              -e '/^.*Version: 4/,/Fragment offset:/d' \
              -e '/^.*Version: 6/,/Next header:/d' \
              -e '/^.*Identification:/d' \
              -e '/^.*Header checksum:/d' \
              -e '/^.*Checksum:/d' \
              -e '/^.*Total length:/d' \
              -e '/^.*Window size value:/,/^.*\[PDU Size/d' \
              -e '/^.*TCP segment data/,/^.*\[Reassembled TCP Data/d' \
              -e '/^.*Transmission Control Protocol/d' \
              -e '/^.*\[Next sequence number:/d' \
              -e '/^.*\Acknowledgment number:/d' \
              -e '/^.*\Sequence number:/d' \
              -e '/^.*\[Stream index:/d' \
              -e '/^.*\[.*(Source|Destination) GeoIP/d' \
              -e '/^.*Request In:/d' \
              $3.full > $3.out
}

SUCCESS=0
for DATAFILE in $INPUT_FILES
do
    CBORFILE=$tmpdir/$DATAFILE.cbor
    OUTFILE=$tmpdir/$DATAFILE.pcap
    TSFILE=$tmpdir/$DATAFILE.ts

    # Run the converter.
    $COMP -c /dev/null -n all -o $CBORFILE $DATAFILE
    if [ $? -ne 0 ]; then
        cleanup 1
    fi

    $INSP $DEFAULTS -o $OUTFILE $CBORFILE
    if [ $? -ne 0 ]; then
        cleanup 1
    fi

    good=0
    total=0
    tshark -nr $DATAFILE -T fields -e dns.id | sort -u | sed '/^\s*$/d' > $tmpdir/ids.out
    readarray ids < $tmpdir/ids.out

    for i in "${ids[@]}" ; do
        j=`echo $(($i))`
        call_tshark $DATAFILE $j ${TSFILE}.orig.$j
        call_tshark $OUTFILE $j ${TSFILE}.conv.$j
        if [ ! -s ${TSFILE}.orig.$j.out ] || [ ! -s ${TSFILE}.conv.$j.out ]; then
            continue
        fi
        total=$((total+1))
        echo $total " of " ${#ids[@]} " with id " $j ", " $i
        diff -u ${TSFILE}.orig.$j.out ${TSFILE}.conv.$j.out && good=$((good+1))
    done
    echo "Total " $total ", good " $good
    if [ $good -eq $total ] ; then
        echo "All good"
    else
        SUCCESS=1
    fi
    echo
done

cleanup $SUCCESS
