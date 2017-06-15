#!/bin/sh
#
# Print the version. If this is a git repo, use the output of
# 'git describe', and update the content of .version iff it differs
# from the output of 'git describe'. Otherwise use the contents of
# .version. If that isn't present, fall back to '0.1-dev'.
#
# Copyright 2016-2017 Internet Corporation for Assigned Names and Numbers.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#

if git describe > .gitversion 2> /dev/null; then
    if [ -f .version ]; then
        if ! diff .version .gitversion > /dev/null 2>&1; then
            mv .gitversion .version
        fi
    else
        mv .gitversion .version
    fi
fi

ver=$(cat .version 2> /dev/null)
if [ $? != 0 ]; then
    ver="0.1-dev"
fi

printf %s "$ver"
exit 0
