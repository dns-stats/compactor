#!/bin/bash
# 
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# Given a directory containing:
#
# 1. Raw and ignored PCAP output files from the compactor.
# 2. tcpdump captures from the same source.
#
# this script aggregates combines the individual files into one file per
# type, and trims those files so that they all cover the same time range.
#
# It is therefore useful when preparing raw capture files from a live
# host for further analysis.
#
# To use, give a single parameter, the name of the directory containing
# the files. All files ending .raw.pcap are considered raw PCAP files
# from the compactor, all ending .ignored.pcap are considered
# ignored PCAP files from the compactor, and remaining files ending
# .pcap are considered as tcpdump output.
#
# Three files are written, named raw.pcap, ignored.pcap and tcpdump.pcap.
# They are written to the current directory.
#
# This script requires the mergecap and capinfos tools. It also requires
# a modern GNU date and so won't run on MacOS Sierra.

CAPINFOS="capinfos -a -e -S -T -m -r"

tmpdir=$(mktemp -d -t "check_live_pcap.XXXXXX")

cleanup()
{
    rm -rf $tmpdir
    exit $1
}

trap "cleanup 1" HUP INT TERM

usage()
{
    echo "Usage: aggregate-live-capture.sh <directory>"
    exit 1
}

error()
{
    echo $1
    cleanup 1
}

if [ $# -ne 1 ]; then
    usage
fi

echo "Merging input captures."

ln -s $(readlink -f $1)/*.pcap $tmpdir

mergecap -w $tmpdir/raw.pcap.out $tmpdir/*.raw.pcap
if [ $? -ne 0 ]; then
    error "raw merge failed"
fi
rm $tmpdir/*.raw.pcap

mergecap -w $tmpdir/ignored.pcap.out $tmpdir/*.ignored.pcap
if [ $? -ne 0 ]; then
    error "ignored merge failed"
fi
rm $tmpdir/*.ignored.pcap

mergecap -w $tmpdir/tcpdump.pcap.out $tmpdir/*.pcap
if [ $? -ne 0 ]; then
    error "tcpdump merge failed"
fi
rm $tmpdir/*.pcap

echo "Calculating overlapping time window."

# Get start and end timestamps in seconds since epoch.
rawinfo=($($CAPINFOS $tmpdir/raw.pcap.out))
ignoredinfo=($($CAPINFOS $tmpdir/ignored.pcap.out))
tcpdumpinfo=($($CAPINFOS $tmpdir/tcpdump.pcap.out))

IFS=, read fname fstart fend <<< "$rawinfo"
IFS=, read fname istart iend <<< "$ignoredinfo"
IFS=, read fname tstart tend <<< "$tcpdumpinfo"

# Some versions of capinfos return fractional parts in the timestamps.
# Remove them; bash doesn't do floating point.
fstart=${fstart/.*/}
fend=${fend/.*/}
istart=${istart/.*/}
iend=${iend/.*/}
tstart=${tstart/.*/}
tend=${tend/.*/}

if [ $istart -gt $fstart ]; then
    fstart=$istart
fi
if [ $iend -lt $fend ]; then
    fend=$iend
fi
if [ $tstart -gt $fstart ]; then
    fstart=$tstart
fi
if [ $tend -lt $fend ]; then
    fend=$tend
fi

# Start and end may be part way through the second in question. So
# move to the first and last whole second boundaries so we don't get
# fractional second periods that are not, in fact, in common.
fstart=$(($fstart + 1))
fend=$(($fend - 1))

# Convert to YYYY-MM-DD HH:MM:SS in local time for editcap.
fstart=$(date '+%F %T' --date="@$fstart")
fend=$(date '+%F %T' --date="@$fend")

echo "Writing outputs. Time window $fstart to $fend"

# Trim the files.
editcap -A "$fstart" -B "$fend" $tmpdir/raw.pcap.out ./raw.pcap
if [ $? -ne 0 ]; then
    error "editcap raw failed"
fi
editcap -A "$fstart" -B "$fend" $tmpdir/ignored.pcap.out ./ignored.pcap
if [ $? -ne 0 ]; then
    error "editcap ignored failed"
fi
editcap -A "$fstart" -B "$fend" $tmpdir/tcpdump.pcap.out ./tcpdump.pcap
if [ $? -ne 0 ]; then
    error "editcap tcpdump failed"
fi

echo "Written raw.pcap, ignored.pcap, tcpdump.pcap. Done."

exit 0
