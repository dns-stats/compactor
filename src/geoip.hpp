/*
 * Copyright 2018-2019, 2021 Internet Corporation for Assigned Names and Numbers.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Developed by Sinodun IT (www.sinodun.com)
 */

/**
 * \file geoip.hpp
 * \brief Geographic information for IP addresses.
 */

#ifndef GEOIP_HPP
#define GEOIP_HPP

#include <cstdint>
#include <stdexcept>
#include <string>

#include <maxminddb.h>

#include "configuration.hpp"

/**
 * \exception geoip_error
 * \brief Signals a GeoIP lookup error.
 */
class geoip_error : public std::runtime_error
{
public:
    /**
     * \brief Constructor.
     *
     * \param what message detailing the problem.
     */
    explicit geoip_error(std::string const & what)
        : std::runtime_error(what) {}

    /**
     * \brief Constructor.
     *
     * \param what message detailing the problem.
     */
    explicit geoip_error(char const *  what)
        : std::runtime_error(what) {}
};

/**
 * \class GeoIPContext
 * \brief Context for obtaining geographic info for IP addresses.
 */
class GeoIPContext
{
public:
    /**
     * \brief Constructor.
     *
     * Obtain databases from configuration.
     *
     * \param geoip_db_dir_path path to geoip data directory.
     * \throws geoip_error on error
     */
    explicit GeoIPContext(std::string const & geoip_db_dir_path);

    /**
     * \brief Constructor.
     *
     * Open all necessary databases.
     *
     * \param city_path Path to city database.
     * \param as_path   Path to AS database.
     * \throws geoip_error on error
     */
    GeoIPContext(std::string const & city_path, std::string const & as_path);

    /**
     * \brief Destructor.
     *
     * Close databases.
     */
    virtual ~GeoIPContext();

    /**
     * \brief Get an IP's location code.
     *
     * \param addr the address to look up.
     * \returns location code or 0 if none available.
     * \throws geoip_error on error
     */
    uint32_t location_code(IPAddress const & addr);

    /**
     * \brief Get an IP's AS number.
     *
     * \param addr the address to look up.
     * \returns AS number or 0 if none available.
     * \throws geoip_error on error
     */
    uint32_t as_number(IPAddress const & addr);

    /**
     * \brief Get the netmask for the matching subnet in an AS lookup.
     *
     * \param addr the address to look up.
     * \returns the netmask, or 0 if no match.
     * if none available.
     * \throws geoip_error on error
     */
    uint16_t as_netmask(IPAddress const & addr);

private:
    /**
     * \brief the city database.
     */
    MMDB_s city_db;

    /**
     * \brief the AS database.
     */
    MMDB_s as_db;
};

#endif
