/*
 * Copyright 2018 Internet Corporation for Assigned Names and Numbers.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Developed by Sinodun IT (www.sinodun.com)
 */

#include <sstream>

#include "geoip.hpp"

GeoIPContext::GeoIPContext(std::string const & geoip_db_dir_path)
    : GeoIPContext(geoip_db_dir_path + "/GeoLite2-City.mmdb",
                   geoip_db_dir_path + "/GeoLite2-ASN.mmdb")
{
}

GeoIPContext::GeoIPContext(std::string const & city_path, std::string const & as_path)
{
    city_db.filename = as_db.filename = NULL;
    if ( MMDB_open(city_path.c_str(), MMDB_MODE_MMAP, &city_db) != MMDB_SUCCESS )
        throw geoip_error("Can't open " + city_path);
    if ( MMDB_open(as_path.c_str(), MMDB_MODE_MMAP, &as_db) != MMDB_SUCCESS )
        throw geoip_error("Can't open " + as_path);
}

GeoIPContext::~GeoIPContext()
{
    if ( as_db.filename )
        MMDB_close(&as_db);
    if ( city_db.filename )
        MMDB_close(&city_db);
}

static MMDB_lookup_result_s lookup(MMDB_s * const db, IPAddress const & addr)
{
    int gai_error, mmdb_error;
    MMDB_lookup_result_s res =
        MMDB_lookup_string(db, addr.str().c_str(), &gai_error, &mmdb_error);
    if ( gai_error != 0 )
        throw geoip_error("getaddrinfo() error");
    if ( mmdb_error != MMDB_SUCCESS )
        throw geoip_error("MMDB lookup failure");
    return res;
}

uint32_t GeoIPContext::location_code(IPAddress const & addr)
{
    MMDB_lookup_result_s res = lookup(&city_db, addr);
    if ( !res.found_entry )
        return 0;

    /* Look first for city, country if not there, otherwise continent. */
    MMDB_entry_data_s entry_data;
    int status = MMDB_get_value(&res.entry, &entry_data, "city", "geoname_id", NULL);
    if ( status == MMDB_SUCCESS && entry_data.has_data )
        return entry_data.uint32;
    if ( status != MMDB_SUCCESS && status != MMDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR )
        throw geoip_error("MMDB entry error");

    status = MMDB_get_value(&res.entry, &entry_data, "country", "geoname_id", NULL);
    if ( status == MMDB_SUCCESS && entry_data.has_data )
        return entry_data.uint32;
    if ( status != MMDB_SUCCESS && status != MMDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR )
        throw geoip_error("MMDB entry error");

    status = MMDB_get_value(&res.entry, &entry_data, "continent", "geoname_id", NULL);
    if ( status == MMDB_SUCCESS && entry_data.has_data )
        return entry_data.uint32;
    if ( status != MMDB_SUCCESS && status != MMDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR )
        throw geoip_error("MMDB entry error");
    return 0;
}

uint32_t GeoIPContext::as_number(IPAddress const & addr)
{
    MMDB_lookup_result_s res = lookup(&as_db, addr);
    if ( !res.found_entry )
        return 0;

    MMDB_entry_data_s entry_data;
    int status = MMDB_get_value(&res.entry, &entry_data, "autonomous_system_number", NULL);
    if ( status == MMDB_SUCCESS && entry_data.has_data )
        return entry_data.uint32;
    if ( status != MMDB_SUCCESS && status != MMDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR )
        throw geoip_error("MMDB entry error");
    return 0;
}
