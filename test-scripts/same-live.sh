#!/bin/sh
# 
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# Make sure checking the live raw PCAPS proceeds as expected.

CHECK=$srcdir/test-scripts/check-live-pcap.sh

do_check()
{
    $CHECK $1 $2
    checkres=$?
    if [ $checkres -ne 0 ]; then
        echo "Checking $1 failed."
        exit $checkres
    fi
}

do_check nsd-live 0
do_check knot-live 6
exit 0
