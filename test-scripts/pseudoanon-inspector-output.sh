#!/bin/sh
# 
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# Check the inspector pseudo-anonymises report contents.

COMP=./compactor
INSP=./inspector
DATAFILE=./knot-live.raw.pcap
INFOFILE=$srcdir/test-scripts/knot-live.anon.info

#set -x

tmpdir=`mktemp -d -t "pseudoanon-inspector-output.XXXXXX"`

cleanup()
{
    rm -rf $tmpdir
    exit $1
}

trap "cleanup 1" HUP INT TERM

# Run the converter.
$COMP -c /dev/null -S 192.168.1.1 -S ::1 -o $tmpdir/out.cbor $DATAFILE
if [ $? -ne 0 ]; then
    cleanup 1
fi

# -I. Expect only .info to be produced.
$INSP --info-only -P test -p -o $tmpdir/out.pcap $tmpdir/out.cbor
if [ $? -ne 0 ]; then
    cleanup 1
fi

test -f $tmpdir/out.pcap.info -a ! \( -f $tmpdir/out.pcap \) &&
    diff -q $tmpdir/out.pcap.info $INFOFILE
cleanup $?
