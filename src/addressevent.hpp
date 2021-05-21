/*
 * Copyright 2016-2017, 2021 Internet Corporation for Assigned Names and Numbers.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Developed by Sinodun IT (www.sinodun.com)
 */

/**
 * \file addressevent.hpp
 * \brief Address events record IP related events related to an IP address.
 *
 * These events are mostly ICMP/ICMPv6.
 */

#ifndef ADDRESSEVENT_HPP
#define ADDRESSEVENT_HPP

#include <boost/functional/hash.hpp>

#include "ipaddress.hpp"

/**
 * \class AddressEvent
 * \brief An event related to a particular IP address.
 */
class AddressEvent
{
public:
    /**
     * \brief Address event type identifier enum.
     */
    enum EventType
    {
        TCP_RESET,
        ICMP_TIME_EXCEEDED,
        ICMP_DEST_UNREACHABLE,
        ICMPv6_TIME_EXCEEDED,
        ICMPv6_DEST_UNREACHABLE,
        ICMPv6_PACKET_TOO_BIG,
    };

    /**
     * \brief Constructor.
     *
     * \param event_type        type of the event.
     * \param address           associated address.
     * \param event_code        event code.
     */
    AddressEvent(EventType event_type, const IPAddress& address, unsigned event_code = 0)
        : address_(address), event_type_(event_type), event_code_(event_code)
    {
    }

    /**
     * \brief Return the address.
     */
    const IPAddress& address() const
    {
        return address_;
    }

    /**
     * \brief Return the event type.
     */
    EventType type() const
    {
        return event_type_;
    }

    /**
     * \brief Return the event code.
     */
    unsigned code() const
    {
        return event_code_;
    }

    /**
     * \brief Equality operator.
     *
     * \param rhs the address event to compare to.
     * \returns `true` if this address event has the same value as `rhs`.
     */
    bool operator==(const AddressEvent& rhs) const
    {
        return
            ( event_type_ == rhs.event_type_ ) &&
            ( event_code_ == rhs.event_code_ ) &&
            ( address_ == rhs.address_ );
    }

    /**
     * \brief Inequality operator.
     *
     * \param rhs the address event to compare to.
     * \returns `false` if this address event has the same value as `rhs`.
     */
    bool operator!=(const AddressEvent& rhs) const
    {
        return !(*this == rhs);
    }

    /**
     * \brief Calculate a hash value for the address event.
     *
     * \returns hash value.
     */
    friend std::size_t hash_value(const AddressEvent& ae)
    {
        std::size_t seed = boost::hash_value(ae.event_type_);
        boost::hash_combine(seed, ae.event_code_);
        boost::hash_combine(seed, ae.address_);
        return seed;
    }

private:
    /**
     * \brief the event address.
     */
    IPAddress address_;

    /**
     * \brief the event type.
     */
    EventType event_type_;

    /**
     * \brief the event code.
     */
    unsigned event_code_;
};

#endif
