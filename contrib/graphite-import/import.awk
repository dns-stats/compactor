#!/usr/bin/gawk -f
#
# A sample GNU Awk script for scanning Compactor/Inspector .info files and
# converting the Statistics data into metrics suitable for use with Carbon
# and Graphite/Grafana.
#
BEGIN {
    FS = ":"

    CARBON_METRIC = "compactor-info"
}

BEGINFILE {
    rotation_period = 300

    split(FILENAME, fpath, "/")
    hostname = fpath[1]
    sitename = substr(hostname, 1, 3)
    basename = fpath[2]
    year = substr(basename, 1, 4)
    month = substr(basename, 5, 2)
    day = substr(basename, 7, 2)
    hour = substr(basename, 10, 2)
    min = substr(basename, 12, 2)
    sec = substr(basename, 14, 2)
    timestamp = mktime(year " " month " " day " " hour " " min " " sec " 0")
}

/File rotation period/ {
    rotation_period = $2
}

/Total Packets processed/ {
    print CARBON_METRIC "." hostname ".packet " $2/rotation_period " " timestamp
}

/Matched DNS query\/response pairs/ {
    print CARBON_METRIC "." hostname ".qr " $2/rotation_period " " timestamp
}

/Dropped C-DNS items/ {
    print CARBON_METRIC "." hostname ".qr-drop " $2/rotation_period " " timestamp
}

/Unmatched DNS queries/ {
    print CARBON_METRIC "." hostname ".unmatched-query " $2/rotation_period " " timestamp
}

/Unmatched DNS response/ {
    print CARBON_METRIC "." hostname ".unmatched-response " $2/rotation_period " " timestamp
}

/Malformed DNS packets/ {
    print CARBON_METRIC "." hostname ".malformed-dns " $2/rotation_period " " timestamp
}

/Non-DNS packets/ {
    print CARBON_METRIC "." hostname ".non-dns " $2/rotation_period " " timestamp
}

/Out-of-order DNS query\/responses/ {
    print CARBON_METRIC "." hostname ".out-of-order " $2/rotation_period " " timestamp
}
