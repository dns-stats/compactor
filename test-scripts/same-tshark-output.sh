#!/usr/bin/env bash
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# Check that running from pcap->cbor->pcap produces the same output

DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

COMP=./compactor
INSP=./inspector
TSHARK=tshark
INPUT_FILES="matching.pcap
unmatched.pcap"

#set -x


if [ -z "$1" ] ; then
    echo "Using default input"
else
    INPUT_FILES=$1
fi
USR_TMPDIR=$2

rm_files()
{
    rm $tmpdir/tshark$1*.out
    rm $tmpdir/tshark$1*.full
    rm $tmpdir/ids.out
    rm $CBORFILE
    rm $OUTFILE
}

cleanup()
{
    rm -rf $tmpdir
    exit $1
}

call_tshark()
{
    # Should be able to remove the last 2 deletions when we have name compression
     $TSHARK -nr $1 -Y $FILTER_COND -T text -V  >  $tmpdir/tshark$2.full
     sed -r -e '/Frame [0-9]/,/^.*\[Time shift/d' \
              -e '/^.*\[Time delta/,/Internet/d' \
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
              -e '/^.*Request In:/d' \
              $tmpdir/tshark$2.full  > $tmpdir/tshark$2.out
}

trap "cleanup 1" HUP INT TERM

SUCCESS=0
for DATAFILE in $INPUT_FILES
do

    if [ -z $USR_TMPDIR ] ; then
        tmpdir=`mktemp -d --tmpdir "same-bytes.XXXXXX"`
        trap "cleanup 1" HUP INT TERM
    else
        mkdir -p $USR_TMPDIR/"same-bytes" &&
        tmpdir=$USR_TMPDIR/"same-bytes"
        rm  $USR_TMPDIR/"same-bytes"/*
    fi
    if [ -z "$tmpdir" ] ; then
        echo "Couldn't create tmpdir"
        exit $1
    fi
    echo "tmpdir is  " $tmpdir
    echo "Processing " $DATAFILE

    CBORFILE=$tmpdir/message1.cbor
    OUTFILE=$tmpdir/message2.pcap

    # Run the converter.
    $COMP -c /dev/null -n all -o $CBORFILE $DATAFILE
    if [ $? -ne 0 ]; then
        echo "Compactor failed"
        continue
    fi

    $INSP -o $OUTFILE $CBORFILE
    if [ $? -ne 0 ]; then
        echo "Inspector failed"
        continue
    fi

    good=0
    total=0
    $TSHARK -nr $DATAFILE -T fields -e dns.id | sort -u | sed '/^\s*$/d' > $tmpdir/ids.out
    readarray ids < $tmpdir/ids.out

    for i in "${ids[@]}" ; do
        j=`echo $(($i))`
        FILTER_COND="dns.id=="$j
        call_tshark $DATAFILE $j-1
        call_tshark $OUTFILE $j-2
        if [ ! -s $tmpdir/tshark$j-1.out ]  || [ ! -s $tmpdir/tshark$j-2.out ] ; then
            rm_files $j
            continue
        fi
        total=$((total+1))
        echo $total " of " ${#ids[@]} " with id " $j ", " $i
        cmp $tmpdir/tshark$j-1.out $tmpdir/tshark$j-2.out  && good=$((good+1))
    done
    echo "Total " $total ", good " $good
    if [ $good -eq $total ] ; then
        echo "All good"
    else
        SUCCESS=1
    fi
    echo
    rm_files $j
    if [ -z $USR_TMPDIR ] ; then
        rm -rf $tmpdir
    fi
done

cleanup $SUCCESS
