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

#include <iostream>

#include <tins/tins.h>

#include "ipaddress.hpp"

IPAddress::IPAddress(const Tins::IPv4Address& a)
    : addr4_(a), ipv6_(false)
{
}

IPAddress::IPAddress(const Tins::IPv6Address& a)
    : addr6_(a), ipv6_(true)
{
}

IPAddress::IPAddress(const byte_string& data)
{
    if ( data.size() == sizeof(uint32_t) )
    {
        union
        {
            uint32_t uint_val;
            unsigned char c[sizeof(uint32_t)];
        } u;
        ipv6_ = false;
        std::copy(data.begin(), data.end(), u.c);
        addr4_ = Tins::IPv4Address(u.uint_val);
    }
    else if ( data.size() == Tins::IPv6Address::address_size )
    {
        ipv6_ = true;
        addr6_ = Tins::IPv6Address(data.data());
    }
    else
        throw Tins::invalid_address();
}

IPAddress::IPAddress(const std::string& str)
    : IPAddress(str.c_str())
{
}

IPAddress::IPAddress(const char* str)
{
    try
    {
        addr4_ = Tins::IPv4Address(str);
        ipv6_ = false;
    }
    catch (const Tins::invalid_address&)
    {
        addr6_ = Tins::IPv6Address(str);
        ipv6_ = true;
    }
}

byte_string IPAddress::asNetworkBinary() const
{
    if ( ipv6_ )
    {
        byte_string res(addr6_.begin(), addr6_.end());
        return res;
    }
    else
    {
        union
        {
            uint32_t uint_val;
            unsigned char c[sizeof(uint32_t)];
        } u;
        u.uint_val = addr4_;
        return byte_string(std::begin(u.c), std::end(u.c));
    }
}

std::ostream& operator<<(std::ostream& output, const IPAddress& addr)
{
    if ( addr.ipv6_ )
        output << addr.addr6_;
    else
        output << addr.addr4_;
    return output;
}

std::size_t hash_value(IPAddress const& addr)
{
    if ( addr.ipv6_ )
        return boost::hash_range(addr.addr6_.begin(), addr.addr6_.end());
    else
        return boost::hash_value(static_cast<uint32_t>(addr.addr4_));
}
