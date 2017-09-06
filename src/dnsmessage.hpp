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

#ifndef DNSMESSAGE_HPP
#define DNSMESSAGE_HPP

#include <chrono>
#include <iostream>

#include <tins/tins.h>

#include "bytestring.hpp"
#include "capturedns.hpp"
#include "ipaddress.hpp"
#include "packetstatistics.hpp"

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
        : clientIP(), serverIP(), clientPort(0), serverPort(0),
          hoplimit(64), tcp(false), wire_size(0) {}

    /**
     * \typedef OptData
     * \brief OPT data, in structure OptData.
     *
     * \struct OptData_s
     * \brief OPT data.
     *
     * This struct holds data in an OPT record. These are special records
     * not resident in the DNS zone, but generated on the fly by client
     * and server to provide extended information about the transaction.
     * See DNS documentation for more information.
     */
    using OptData = struct OptData_s
    {
        /**
         * \brief `true` if the message contains OPT data.
         */
        bool present;

        /**
         * \brief OPT UDP payload size.
         */
        uint16_t udp_payload_size;

        /**
         * \brief OPT EDNS version.
         */
        uint8_t edns_version;

        /**
         * \brief OPT extended RCODE information.
         *
         * This provides a top 8 bits of a 12 bit RCODE.
         */
        uint8_t extended_rcode;

        /**
         * \brief OPT DO bit.
         */
        bool opt_do;

        /**
         * \brief OPT RDATA.
         */
        byte_string rdata;
    };

    /**
     * \brief Construct a message.
     *
     * \param pdu      packet payload data.
     * \param tstamp   packet timestamp.
     * \param srcIP    source IP address.
     * \param dstIP    destination IP address.
     * \param srcPort  source port.
     * \param dstPort  destination port.
     * \param hoplimit packet hoplimit.
     * \param tcp      `true` if received via TCP.
     */
    DNSMessage(const Tins::RawPDU& pdu,
               const std::chrono::system_clock::time_point& tstamp,
               const IPAddress& srcIP, const IPAddress& dstIP,
               uint16_t srcPort, uint16_t dstPort,
               uint8_t hoplimit, bool tcp);

    /**
     * \brief Extract OPT data from message, if present.
     *
     * \return completed OptData.
     */
    OptData opt() const;

    /**
     * \brief Write basic information on the message to the output stream.
     *
     * \param output the output stream.
     * \param msg    the message.
     * \return the output stream.
     */
    friend std::ostream& operator<<(std::ostream& output, const DNSMessage& msg)
    {
        std::time_t t = std::chrono::system_clock::to_time_t(msg.timestamp);
        std::tm tm = *std::gmtime(&t);
        char buf[40];
        std::strftime(buf, sizeof(buf), "%Y-%m-%d %Hh%Mm%Ss", &tm);
        double us = std::chrono::duration_cast<std::chrono::microseconds>(msg.timestamp.time_since_epoch()).count() % 1000000;
        output << buf << us << "us UTC:"
               << "\n\tClient IP: " << msg.clientIP
               << "\n\tServer IP: " << msg.serverIP
               << "\n\tTransport: ";
        if ( msg.tcp )
            output << "TCP";
        else
            output << "UDP";
        output << "\n\tClient port: " << msg.clientPort
               << "\n\tServer port: " << msg.serverPort
               << "\n\tHop limit: " << +msg.hoplimit
               << "\n\tDNS QR: ";
        if  ( msg.dns.type() == CaptureDNS::RESPONSE )
            output << "Response";
        else
            output << "Query";
        output << "\n\tID: " << msg.dns.id()
               << "\n\tOpcode: " << +msg.dns.opcode()
               << "\n\tRcode: " << +msg.dns.rcode();
        output << "\n\tFlags: ";
        if ( msg.dns.authoritative_answer() )
            output << "AA ";
        if ( msg.dns.truncated() )
            output << "TC ";
        if ( msg.dns.recursion_desired() )
            output << "RD ";
        if ( msg.dns.recursion_available() )
            output << "RA ";
        if ( msg.dns.authenticated_data() )
            output << "AD ";
        if ( msg.dns.checking_disabled() )
            output << "CD ";
        output << "\n\tQdCount: " << msg.dns.questions_count()
               << "\n\tAnCount: " << msg.dns.answers_count()
               << "\n\tNsCount: " << msg.dns.authority_count()
               << "\n\tArCount: " << msg.dns.additional_count();
        for ( const auto &q : msg.dns.queries() )
            output << "\n\tName: " << CaptureDNS::decode_domain_name(q.dname())
                   << "\n\tType: " << q.query_type()
                   << "\n\tClass: " << q.query_class();
        output << std::endl;
        return output;
    }

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
    IPAddress clientIP;

    /**
     * \brief IP address of server.
     *
     * If the message is a response, the server IP is the sender IP. Otherwise
     * it is the destination IP.
     */
    IPAddress serverIP;

    /**
     * \brief port used by client.
     *
     * If the message is a query, the client port is the sender port.
     * Otherwise it is the destination port.
     */
    uint16_t clientPort;

    /**
     * \brief port used by server.
     *
     * If the message is a response, the server port is the sender port.
     * Otherwise it is the destination port.
     */
    uint16_t serverPort;

    /**
     * \brief sender packet hop limit.
     *
     * This is the TTL in IPv4, and the hop limit in IPv6.
     */
    uint8_t hoplimit;

    /**
     * \brief `true` if the message is received via TCP.
     *
     * `false` if the message is received via UDP.
     */
    bool tcp;

    /**
     * \brief the size of the message on the wire.
     */
    unsigned wire_size;

    /**
     * \brief DNS-related contents of the DNS message.
     */
    CaptureDNS dns;
};

#endif
