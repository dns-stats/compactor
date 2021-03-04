/*
 * Copyright 2016-2019, 2021 Internet Corporation for Assigned Names and Numbers.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Developed by Sinodun IT (www.sinodun.com)
 */

#include <functional>
#include <iostream>

#include "dnsmessage.hpp"
#include "makeunique.hpp"
#include "nocopypacket.hpp"

#include "packetstream.hpp"

PacketStream::PacketStream(const Configuration& config, DNSSink dns_sink, AddressEventSink address_event_sink)
    : config_(config), dns_sink_(dns_sink), address_event_sink_(address_event_sink)
{
    tcp_stream_follower_.new_stream_callback(std::bind(&PacketStream::on_new_stream, this, std::placeholders::_1));
}

void PacketStream::on_new_stream(Tins::TCPIP::Stream& stream)
{
    // I will handle clearing the payloads.
    stream.auto_cleanup_payloads(false);

    stream.client_data_callback(std::bind(&PacketStream::on_new_client_data, this, std::placeholders::_1));
    stream.server_data_callback(std::bind(&PacketStream::on_new_server_data, this, std::placeholders::_1));
}

void PacketStream::on_new_client_data(Tins::TCPIP::Stream& stream)
{
    on_new_stream_data(stream.client_payload());
}

void PacketStream::on_new_server_data(Tins::TCPIP::Stream& stream)
{
    on_new_stream_data(stream.server_payload());
}

void PacketStream::on_new_stream_data(Tins::TCPIP::Stream::payload_type& payload)
{
    for (;;)
    {
        if ( payload.size() < 2 )
            break;

        unsigned dns_len = (payload[0] << 8) + payload[1];
        if ( (dns_len + 2) > payload.size() )
            break;

        Tins::RawPDU pdu(&(payload.data()[2]), dns_len);
        dispatch_dns(&pdu, *last_tcp_packet_data_);

        payload.erase(payload.begin(), payload.begin() + dns_len + 2);
    }
}

Tins::PDU* PacketStream::find_ip_pdu(Tins::PDU* pdu)
{
    while ( pdu &&
            pdu->pdu_type() != Tins::PDU::IP &&
            pdu->pdu_type() != Tins::PDU::IPv6 )
    {
        if ( pdu->pdu_type() == Tins::PDU::DOT1Q &&
             !config_.vlan_ids.empty() )
        {
            const Tins::Dot1Q* dot1q = reinterpret_cast<const Tins::Dot1Q*>(pdu);
            bool watched_vlan = false;

            for ( auto vl_id : config_.vlan_ids )
                if ( vl_id == dot1q->id() )
                {
                    watched_vlan = true;
                    break;
                }

            if ( !watched_vlan )
                return nullptr;
        }

        pdu = pdu->inner_pdu();
    }

    if ( !pdu )
        throw unhandled_packet();

    return pdu;
}

Tins::PDU* PacketStream::ipv4_packet(Tins::IP* ip, PktData& pkt_data)
{
    if ( reassembler_ipv4_.process(*ip) == Tins::IPv4Reassembler::FRAGMENTED )
        return NULL;

    pkt_data.hoplimit = ip->ttl();
    pkt_data.srcIP = IPAddress(ip->src_addr());
    pkt_data.dstIP = IPAddress(ip->dst_addr());

    Tins::PDU* res = ip->inner_pdu();
    if ( !res )
        throw malformed_packet();

    return res;
}

Tins::PDU* PacketStream::ipv6_packet(Tins::IPv6* ip6, PktData& pkt_data)
{
    // TODO: Add IPv6 fragmentation detection into condition.
    pkt_data.hoplimit = ip6->hop_limit();
    pkt_data.srcIP = IPAddress(ip6->src_addr());
    pkt_data.dstIP = IPAddress(ip6->dst_addr());

    Tins::PDU* res = ip6->inner_pdu();
    if ( !res )
        throw malformed_packet();

    return res;
}

void PacketStream::udp_packet(Tins::UDP* udp, PktData& pkt_data)
{
    if ( udp->dport() != config_.dns_port && udp->sport() != config_.dns_port )
        throw unhandled_packet();

    pkt_data.srcPort = udp->sport();
    pkt_data.dstPort = udp->dport();
    pkt_data.transport_type = TransportType::UDP;

    Tins::PDU* pdu = udp->inner_pdu();
    if ( !pdu || pdu->pdu_type() != Tins::PDU::RAW )
        throw malformed_packet();

    dispatch_dns(reinterpret_cast<Tins::RawPDU*>(pdu), pkt_data);
}

void PacketStream::tcp_packet(Tins::TCP* tcp, Tins::PDU* ip_pdu,
                              PktData& pkt_data)
{
    if ( tcp->dport() != config_.dns_port && tcp->sport() != config_.dns_port )
        throw unhandled_packet();

    pkt_data.srcPort = tcp->sport();
    pkt_data.dstPort = tcp->dport();
    pkt_data.transport_type = TransportType::TCP;
    last_tcp_packet_data_ = &pkt_data;

    if ( tcp->flags() & Tins::TCP::RST )
    {
        std::shared_ptr<AddressEvent> ae =
            std::make_shared<AddressEvent>(AddressEvent::EventType::TCP_RESET, pkt_data.srcIP);
        address_event_sink_(ae);
    }

    // It looks like the TCP stream follower stuff *modifies* the
    // PDU data fed into it. Since we're sharing the packet with the
    // PCAP output queues, they can end up writing a modified version
    // of the packet. What we see especially is zero length TCP packets
    // at the first data packet in a transaction. So copy the packet before
    // feeding the copy into the stream follower.
    Tins::Packet pkt(ip_pdu, NoCopyPacket::tsToTins(pkt_data.timestamp));
    tcp_stream_follower_.process_packet(pkt);
}

void PacketStream::icmp_packet(Tins::ICMP* icmp, Tins::PDU* ip_pdu,
                               PktData& pkt_data)
{
    AddressEvent::EventType event_type;

    switch (icmp->type())
    {
    case Tins::ICMP::TIME_EXCEEDED:
        event_type = AddressEvent::EventType::ICMP_TIME_EXCEEDED;
        break;

    case Tins::ICMP::DEST_UNREACHABLE:
        event_type = AddressEvent::EventType::ICMP_DEST_UNREACHABLE;
        break;

    default:
        throw unhandled_packet();
    }

    // Is the inner PDU long enough to contain the original destination address?
    // Is so, use that. If not, use the ICMP source address.
    IPAddress event_address;
    Tins::PDU* inner = icmp->inner_pdu();
    if ( !inner || inner->pdu_type() != Tins::PDU::RAW )
        throw malformed_packet();
    if ( inner->size() >= 20 )
    {
        try
        {
            Tins::RawPDU* raw_pdu = reinterpret_cast<Tins::RawPDU*>(inner);
            const Tins::IP inner_ip = raw_pdu->to<Tins::IP>();
            event_address = IPAddress(inner_ip.dst_addr());
        }
        catch (Tins::malformed_packet&)
        {
            event_address = pkt_data.srcIP;
        }
    }
    else
        event_address = pkt_data.srcIP;

    std::shared_ptr<AddressEvent> ae =
        std::make_shared<AddressEvent>(event_type, event_address, icmp->code());
    address_event_sink_(ae);
}

void PacketStream::icmpv6_packet(Tins::ICMPv6* icmp, Tins::PDU* ip_pdu,
                                 PktData& pkt_data)
{
    AddressEvent::EventType event_type;

    switch (icmp->type())
    {
    case Tins::ICMPv6::TIME_EXCEEDED:
        event_type = AddressEvent::EventType::ICMPv6_TIME_EXCEEDED;
        break;

    case Tins::ICMPv6::DEST_UNREACHABLE:
        event_type = AddressEvent::EventType::ICMPv6_DEST_UNREACHABLE;
        break;

    case Tins::ICMPv6::PACKET_TOOBIG:
        event_type = AddressEvent::EventType::ICMPv6_PACKET_TOO_BIG;
        break;

    default:
        throw unhandled_packet();
    }

    // Is the inner PDU long enough to contain the original destination address?
    // Is so, use that. If not, use the ICMP source address.
    IPAddress event_address;
    Tins::PDU* inner = icmp->inner_pdu();
    if ( !inner || inner->pdu_type() != Tins::PDU::RAW )
        throw malformed_packet();
    if ( inner->size() >= 40 )
    {
        try
        {
            Tins::RawPDU* raw_pdu = reinterpret_cast<Tins::RawPDU*>(inner);
            const Tins::IPv6 inner_ip = raw_pdu->to<Tins::IPv6>();
            event_address = IPAddress(inner_ip.dst_addr());
        }
        catch (Tins::malformed_packet&)
        {
            event_address = pkt_data.srcIP;
        }
    }
    else
        event_address = pkt_data.srcIP;

    std::shared_ptr<AddressEvent> ae =
        std::make_shared<AddressEvent>(event_type, event_address, icmp->code());
    address_event_sink_(ae);
}

void PacketStream::dispatch_dns(Tins::RawPDU* pdu, PktData& pkt_data)
{
    auto dns =
        make_unique<DNSMessage>(*pdu,
                                pkt_data.timestamp,
                                pkt_data.srcIP, pkt_data.dstIP,
                                pkt_data.srcPort, pkt_data.dstPort,
                                pkt_data.hoplimit, pkt_data.transport_type);
    dns_sink_(dns);
}

void PacketStream::process_packet(std::shared_ptr<PcapItem>& pcap)
{
    Tins::PDU* pdu = pcap->pdu.get();
    std::unique_ptr<Tins::IP> ip;
    std::unique_ptr<Tins::IPv6> ipv6;

    if ( pdu->pdu_type() == Tins::PDU::RAW )
    {
        Tins::RawPDU* raw_pdu = reinterpret_cast<Tins::RawPDU*>(pdu);
        try
        {
            switch(raw_pdu->payload()[0] >> 4)
            {
            case 4:
                ip = make_unique<Tins::IP>(raw_pdu->payload().data(), raw_pdu->payload_size());
                pdu = ip.get();
                break;

            case 6:
                ipv6 = make_unique<Tins::IPv6>(raw_pdu->payload().data(), raw_pdu->payload_size());
                pdu = ipv6.get();
                break;

            default:
                pdu = nullptr;
                break;
            }
        }
        catch (Tins::malformed_packet&)
        {
            pdu = nullptr;
        }
    }
    else
        pdu = find_ip_pdu(pdu);

    if ( !pdu )
        return;

    struct PacketStream::PktData pkt_data;
    pkt_data.timestamp = pcap->timestamp;

    Tins::PDU* ip_pdu = pdu;

    try
    {
        switch (pdu->pdu_type())
        {
        case Tins::PDU::IP:
            pdu = ipv4_packet(reinterpret_cast<Tins::IP*>(pdu), pkt_data);
            break;

        case Tins::PDU::IPv6:
            pdu = ipv6_packet(reinterpret_cast<Tins::IPv6*>(pdu), pkt_data);
            break;

        default:
            throw unhandled_packet();
        }

        if ( !pdu )
            return;

        switch (pdu->pdu_type())
        {
        case Tins::PDU::UDP:
            udp_packet(reinterpret_cast<Tins::UDP*>(pdu), pkt_data);
            break;

        case Tins::PDU::TCP:
            tcp_packet(reinterpret_cast<Tins::TCP*>(pdu), ip_pdu, pkt_data);
            break;

        case Tins::PDU::ICMP:
            icmp_packet(reinterpret_cast<Tins::ICMP*>(pdu), ip_pdu, pkt_data);
            break;

        case Tins::PDU::ICMPv6:
            icmpv6_packet(reinterpret_cast<Tins::ICMPv6*>(pdu), ip_pdu, pkt_data);
            break;

        default:
            throw unhandled_packet();
        }
    }
    catch (const Tins::pdu_not_found& e)
    {
        throw malformed_packet();
    }
}
