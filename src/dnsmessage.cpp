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

#include <algorithm>
#include <chrono>
#include <ctime>
#include <exception>
#include <iomanip>
#include <iostream>
#include <utility>

#include <tins/tins.h>

#include "packetstream.hpp"

#include "dnsmessage.hpp"

DNSMessage::DNSMessage(const Tins::RawPDU& pdu,
                       const std::chrono::system_clock::time_point& tstamp,
                       const IPAddress& srcIP, const IPAddress& dstIP,
                       uint16_t srcPort, uint16_t dstPort,
                       uint8_t hoplimit, bool tcp)
    : timestamp(tstamp), clientIP(srcIP), serverIP(dstIP),
      clientPort(srcPort), serverPort(dstPort),
      hoplimit(hoplimit), tcp(tcp), wire_size(pdu.size())
{
    try
    {
        this->dns = (&pdu)->to<CaptureDNS>();
        if ( this->dns.type() == CaptureDNS::RESPONSE )
        {
            std::swap(clientIP, serverIP);
            std::swap(clientPort, serverPort);
        }
    }
    catch (const Tins::malformed_packet& e)
    {
        throw malformed_packet();
    }
}

DNSMessage::OptData DNSMessage::opt() const
{
    DNSMessage::OptData res = {};

    for ( const auto& rr : dns.additional() )
    {
        if ( rr.query_type() == CaptureDNS::QueryType::OPT )
        {
            uint32_t ttl = rr.ttl();
            res.d0 = ((ttl & 0x8000) != 0);
            ttl >>= 16;
            res.edns_version = (ttl & 0xff);
            ttl >>= 8;
            res.extended_rcode = ttl;
            res.present = true;
            res.rdata = rr.data();
            res.udp_payload_size = rr.query_class();
            break;
        }
    }

    return res;
}
