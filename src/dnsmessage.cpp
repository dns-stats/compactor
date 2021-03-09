/*
 * Copyright 2016-2018, 2021 Internet Corporation for Assigned Names and Numbers.
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
                       uint8_t hoplimit, TransportType transport_type)
    : timestamp(tstamp), clientIP(srcIP), serverIP(dstIP),
      clientPort(srcPort), serverPort(dstPort),
      hoplimit(hoplimit), transport_type(transport_type),
      transaction_type(), wire_size(pdu.size())
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

std::ostream& operator<<(std::ostream& output, const DNSMessage& msg)
{
    std::time_t t = std::chrono::system_clock::to_time_t(msg.timestamp);
    std::tm tm = *std::gmtime(&t);
    char buf[40];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %Hh%Mm%Ss", &tm);
    double us = std::chrono::duration_cast<std::chrono::microseconds>(msg.timestamp.time_since_epoch()).count() % 1000000;
    output << buf << us << "us UTC";
    if ( msg.clientIP )
        output << "\n\tClient IP: " << *msg.clientIP;
    if ( msg.serverIP )
        output << "\n\tServer IP: " << *msg.serverIP;
    output << "\n\tTransport: ";
    switch ( msg.transport_type )
    {
    case TransportType::DOH:  output << "DoH"; break;
    case TransportType::DOT:  output << "DoT"; break;
    case TransportType::DDOT: output << "DDoT"; break;
    case TransportType::TCP:  output << "TCP"; break;
    case TransportType::UDP:  output << "UDP"; break;
    }
    if ( msg.clientPort )
        output << "\n\tClient port: " << *msg.clientPort;
    if ( msg.serverPort )
        output << "\n\tServer port: " << *msg.serverPort;
    if ( msg.hoplimit )
        output << "\n\tHop limit: " << +(*msg.hoplimit);
    if ( msg.transaction_type != TransactionType::NONE )
    {
        output << "\n\tTransaction type: ";
        switch(msg.transaction_type)
        {
        case TransactionType::AUTH_QUERY: output << "Auth query"; break;
        case TransactionType::AUTH_RESPONSE: output << "Auth response"; break;
        case TransactionType::RESOLVER_QUERY: output << "Resolver query"; break;
        case TransactionType::RESOLVER_RESPONSE: output << "Resolver response"; break;
        case TransactionType::CLIENT_QUERY: output << "Client query"; break;
        case TransactionType::CLIENT_RESPONSE: output << "Client response"; break;
        case TransactionType::FORWARDER_QUERY: output << "Forwarder query"; break;
        case TransactionType::FORWARDER_RESPONSE: output << "Forwarder response"; break;
        case TransactionType::STUB_QUERY: output << "Stub query"; break;
        case TransactionType::STUB_RESPONSE: output << "Stub response"; break;
        case TransactionType::TOOL_QUERY: output << "Tool query"; break;
        case TransactionType::TOOL_RESPONSE: output << "Tool response"; break;
        case TransactionType::UPDATE_QUERY: output << "Update query"; break;
        case TransactionType::UPDATE_RESPONSE: output << "Update response"; break;
        default: output << "Unknown"; break;
        }
    }
    output << "\n\tDNS QR: ";
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
               << "\n\tType: " << static_cast<unsigned>(q.query_type())
               << "\n\tClass: " << static_cast<unsigned>(q.query_class());
    output << std::endl;
    return output;
}
