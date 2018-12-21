#!/bin/sh
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# Check that running the conversion produces the expected output files.

COMP=./compactor
INSP=./inspector

command -v diff > /dev/null 2>&1 || { echo "No diff, skipping test." >&2; exit 77; }
command -v head > /dev/null 2>&1 || { echo "No head, skipping test." >&2; exit 77; }

GEOASN=$GEOIPDIR/GeoLite2-ASN.mmdb
GEOLOC=$GEOIPDIR/GeoLite2-City.mmdb

if [ ! \( -r $GEOASN -a -r $GEOLOC \) ]; then
    echo "No geo data installed in $GEOIPDIR, skipping test"
    exit 77
fi

tmpdir=`mktemp -d -t "check-template.XXXXXX"`

cleanup()
{
#    rm -rf $tmpdir
    exit $1
}

trap "cleanup 1" HUP INT TERM

error()
{
    echo $1
    cleanup 1
}

RAW=nsd-live.raw.pcap
FMT=$srcdir/test-scripts/test.tpl

if [ ! \( -r $RAW -a $FMT \) ]; then
    error "Missing input file"
fi

# Convert to C-DNS.
$COMP -c /dev/null --omit-system-id -n all -o $tmpdir/gold.cdns $RAW
if [ $? -ne 0 ]; then
    error "compactor failed"
fi

# Template output, first 100 lines.
$INSP -o - -B template -t $FMT --value node=42 $tmpdir/gold.cdns > $tmpdir/gold.dump.full
if [ $? -ne 0 ]; then
    error "dumper failed"
fi
head -n 100 $tmpdir/gold.dump.full > $tmpdir/gold.dump
if [ $? -ne 0 ]; then
    error "head failed"
fi

# Now, we have a problem. The gold output is a nsd-live.dump. But as the
# MaxMind database gets updated, some GeoIP data in the dump may change.
# Generally, though, this shouldn't be by too much over a reasonable
# period of time, so for now let's just diff the two and see if the
# number of lines different exceeds a threshold. There are 100 lines in
# nsd-live.dump, so let's set the threshold at 25%.
diff -y -W 320 --suppress-common-lines $tmpdir/gold.dump nsd-live.dump > $tmpdir/dump.diff
ndiff=$(wc -l $tmpdir/dump.diff | sed -e "s/ .*//")
if [ $ndiff -gt 25 ]; then
    error "Template output differs"
fi

cleanup 0
