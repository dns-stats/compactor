/*
 * Copyright 2016-2017 Internet Corporation for Assigned Names and Numbers.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Developed by Sinodun IT (www.sinodun.com)
 */

#ifndef IPADDRESS_HPP
#define IPADDRESS_HPP

#include <chrono>
#include <iostream>
#include <string>

#include <boost/functional/hash.hpp>

#include <tins/tins.h>

#include "bytestring.hpp"

/**
 * \class IPAddress
 * \brief An IPv4 or an IPv6 address.
 */
class IPAddress
{
public:
    /**
     * \brief Constructor for an IPv4 address.
     *
     * \param a TINS IPv4 address.
     */
    explicit IPAddress(const Tins::IPv4Address& a);

    /**
     * \brief Constructor for an IPv6 address.
     *
     * \param a TINS IPv6 address.
     */
    explicit IPAddress(const Tins::IPv6Address& a);

    /**
     * \brief Constructor from network binary data.
     *
     * \param data network binary data.
     * \throws Tins::invalid_address if data is not a valid address.
     */
    explicit IPAddress(const byte_string& data);

    /**
     * \brief Constructor from string.
     *
     * \param str string with IPv4 or IPv6 address.
     * \throws Tins::invalid_address if data is not a valid address.
     */
    IPAddress(const std::string& str);

    /**
     * \brief Constructor from const char*.
     *
     * \param str string with IPv4 or IPv6 address.
     * \throws Tins::invalid_address if data is not a valid address.
     */
    IPAddress(const char* str);

    /**
     * \brief Default constructor for an empty address.
     */
    IPAddress(){}

    /**
     * \brief Return `true` if this address is IPv6.
     */
    bool is_ipv6() const {
        return ipv6_;
    }

    /**
     * \brief Return a binary representation of the address.
     */
    byte_string asNetworkBinary() const;

    /**
     * \brief Equality operator.
     *
     * \param rhs the address to compare to.
     * \returns `true` if this address has the same value as `rhs`.
     */
    bool operator==(const IPAddress& rhs) const {
        return
            ( ipv6_ == rhs.ipv6_ ) &&
            ( ipv6_ )
            ? ( addr6_ == rhs.addr6_ )
            : ( addr4_ == rhs.addr4_ );
    }

    /**
     * \brief Less than operator.
     *
     * \param rhs the address to compare to.
     * \returns `true` if this address has a value less than `rhs`.
     */
    bool operator<(const IPAddress& rhs) const {
        return
            ( ipv6_ == rhs.ipv6_ ) &&
            ( ipv6_ )
            ? ( addr6_ < rhs.addr6_ )
            : ( addr4_ < rhs.addr4_ );
    }

    /**
     * \brief Inequality operator.
     *
     * \param rhs the address to compare to.
     * \returns `false` if this address has the same value as `rhs`.
     */
    bool operator!=(const IPAddress& rhs) const {
        return !(*this == rhs);
    }

    /**
     * \brief Return IPv4 TINS address.
     */
    operator Tins::IPv4Address() const
    {
        return addr4_;
    }

    /**
     * \brief Return IPv6 TINS address.
     */
    operator Tins::IPv6Address() const
    {
        return addr6_;
    }

    /**
     * \brief Write human-readable address to the output stream.
     *
     * \param output the output stream.
     * \param addr   the address.
     * \return the output stream.
     */
    friend std::ostream& operator<<(std::ostream& output, const IPAddress& addr);

    /**
     * \brief Calculate a hash value for the address.
     *
     * \returns hash value.
     */
    friend std::size_t hash_value(const IPAddress& addr);

private:
    /**
     * \brief IPv4 address.
     */
    Tins::IPv4Address addr4_;

    /**
     * \brief IPv6 address.
     */
    Tins::IPv6Address addr6_;

    /**
     * \brief `true` if this address is IPv6, `false` if IPv4.
     */
    bool ipv6_;
};

#endif
