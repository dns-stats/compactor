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

#ifndef NOCOPYPACKET_HPP
#define NOCOPYPACKET_HPP

#include <chrono>

#include <tins/tins.h>

/**
 * \class NoCopyPacket
 * \brief Wrap a PDU in a packet without taking ownership of the packet.
 *
 * Create a Tins::Packet by wrapping the PDU, but don't take ownership and
 * in the destructor release the PDU.
 */
class NoCopyPacket
{
    /**
     * \brief constant indicating the PDU is not to be copied.
     */
    const Tins::Packet::own_pdu dont_copy_pdu = {};

public:
    /**
     * \brief Constructor.
     *
     * \param  pdu    the PDU to wrap.
     * \param  tstamp the packet timestamp.
     */
    NoCopyPacket(Tins::PDU* pdu, const std::chrono::system_clock::time_point& tstamp)
        : pkt_(pdu, tsToTins(tstamp), dont_copy_pdu)
    {
    }

    /**
     * \brief Destructor.
     *
     * Release the PDU from the packet before the packet is destroyed, thus
     * ensuring the packet won't attempt to free the PDU data.
     */
    virtual ~NoCopyPacket()
    {
        pkt_.release_pdu();
    }

    /**
     * \brief Return the wrapped packet.
     */
    Tins::Packet& packet()
    {
        return pkt_;
    }

    /**
     * \brief Convert a standard C++ time point to a Tins::Timestamp.
     */
    static Tins::Timestamp tsToTins(const std::chrono::system_clock::time_point& t)
    {
        Tins::Timestamp res(std::chrono::duration_cast<std::chrono::microseconds>(t.time_since_epoch()));
        return res;
    }

private:
    /**
     * \brief the packet.
     */
    Tins::Packet pkt_;
};

#endif
