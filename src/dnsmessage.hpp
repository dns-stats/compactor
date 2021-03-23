/*
 * Copyright 2016-2021 Internet Corporation for Assigned Names and Numbers.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Developed by Sinodun IT (www.sinodun.com)
 */

#ifndef DNSMESSAGE_HPP
#define DNSMESSAGE_HPP

#include <chrono>
#include <iostream>

#include <boost/optional.hpp>

#include <tins/tins.h>

#include "capturedns.hpp"
#include "ipaddress.hpp"
#include "packetstatistics.hpp"
#include "transporttype.hpp"

/**
 * \struct DNSMessage
 * \brief Content of a single DNS message.
 */
struct DNSMessage
{
    /**
     * \brief Default constructor. Construct an empty message.
     */
    DNSMessage()
        : clientIP(), serverIP(), clientPort(), serverPort(),
          hoplimit(), ipv6(), transport_type(TransportType::UDP),
          transaction_type(TransactionType::NONE), wire_size() {}

    /**
     * \brief Construct a message received via PCAP.
     *
     * \param pdu      packet payload data.
     * \param tstamp   packet timestamp.
     * \param srcIP    source IP address.
     * \param dstIP    destination IP address.
     * \param srcPort  source port.
     * \param dstPort  destination port.
     * \param hoplimit packet hoplimit.
     * \param transport_type the transport type the message was received over.
     */
    DNSMessage(const Tins::RawPDU& pdu,
               const std::chrono::system_clock::time_point& tstamp,
               const IPAddress& srcIP, const IPAddress& dstIP,
               uint16_t srcPort, uint16_t dstPort,
               uint8_t hoplimit, TransportType transport_type);

    /**
     * \brief Construct a message received via DNSTAP.
     *
     * \param pdu      packet payload data.
     * \param tstamp   packet timestamp.
     * \param transport_type the transport type the message was received over.
     */
    DNSMessage(const Tins::RawPDU& pdu,
               const std::chrono::system_clock::time_point& tstamp,
               TransportType transport_type,
               TransactionType transaction_type);

    /**
     * \brief Return `true` if this message is IPv6.
     */
    bool is_ipv6() const {
        if ( ipv6 )
            return *ipv6;
        else if ( clientIP )
            return (*clientIP).is_ipv6();
        else if ( serverIP )
            return (*serverIP).is_ipv6();

        return false;
    }

    /**
     * \brief Write basic information on the message to the output stream.
     *
     * \param output the output stream.
     * \param msg    the message.
     * \return the output stream.
     */
    friend std::ostream& operator<<(std::ostream& output, const DNSMessage& msg);
    /**
     * \brief Message reception timestamp.
     */
    std::chrono::system_clock::time_point timestamp;

    /**
     * \brief IP address of client.
     *
     * If the message is a query, the client IP is the sender IP. Otherwise
     * it is the destination IP.
     */
    boost::optional<IPAddress> clientIP;

    /**
     * \brief IP address of server.
     *
     * If the message is a response, the server IP is the sender IP. Otherwise
     * it is the destination IP.
     */
    boost::optional<IPAddress> serverIP;

    /**
     * \brief port used by client.
     *
     * If the message is a query, the client port is the sender port.
     * Otherwise it is the destination port.
     */
    boost::optional<uint16_t> clientPort;

    /**
     * \brief port used by server.
     *
     * If the message is a response, the server port is the sender port.
     * Otherwise it is the destination port.
     */
    boost::optional<uint16_t> serverPort;

    /**
     * \brief sender packet hop limit.
     *
     * This is the TTL in IPv4, and the hop limit in IPv6.
     */
    boost::optional<uint8_t> hoplimit;

    /**
     * \brief IPv4 or IPv6?
     */
    boost::optional<bool> ipv6;

    /**
     * \brief the transport type the message was received over.
     */
    TransportType transport_type;

    /**
     * \brief the transaction type, if available.
     */
    TransactionType transaction_type;

    /**
     * \brief the size of the message on the wire.
     */
    boost::optional<unsigned> wire_size;

    /**
     * \brief DNS-related contents of the DNS message.
     */
    CaptureDNS dns;
};

#endif
