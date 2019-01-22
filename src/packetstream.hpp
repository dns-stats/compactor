/*
 * Copyright 2016-2018 Internet Corporation for Assigned Names and Numbers.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Developed by Sinodun IT (www.sinodun.com)
 */

#ifndef PACKETSTREAM_HPP
#define PACKETSTREAM_HPP

#include <chrono>
#include <exception>
#include <memory>

#include <tins/tins.h>
#include <tins/tcp_ip/stream_follower.h>

#include "addressevent.hpp"
#include "channel.hpp"
#include "configuration.hpp"
#include "matcher.hpp"
#include "sniffers.hpp"

/**
 ** Packet processing exceptions.
 **/

/**
 * \exception unhandled_packet
 * \brief Signals an unhandled packet.
 *
 * Signals that a packet was not handled for some reason. Currently this
 * indicates that the packet was:
 * - To/From ports other than 53.
 * - Fragmented.
 * - TCP.
 * - Not able to be decoded as well-formed DNS messages.
 */
class unhandled_packet : public std::runtime_error
{
public:
    /**
     * \brief Default construtor.
     */
    unhandled_packet()
        : std::runtime_error("Unhandled packet"){};
};

/**
 * \exception malformed_packet
 * \brief Signals a malformed packet.
 *
 * Signals that a packet was not able to be decoded as a well-formed
 * message.
 */
class malformed_packet : public std::runtime_error
{
public:
    /**
     * \brief Default construtor.
     */
    malformed_packet()
        : std::runtime_error("Malformed packet"){};
};

/**
 ** Processing a stream of packets.
 **/

/**
 * \struct PcapItem
 * \brief A packet, with timestamp and taking ownership of the data.
 */
struct PcapItem
{
    /**
     * \brief Constructor
     *
     * \param pkt a packet from the underlying library.
     */
    explicit PcapItem(Tins::Packet& pkt)
        : timestamp(std::chrono::microseconds(pkt.timestamp())),
          pdu(pkt.release_pdu())
    {
    }

    /**
     * \brief the packet timestamp.
     */
    std::chrono::system_clock::time_point timestamp;

    /**
     * \brief the packet data.
     */
    std::unique_ptr<Tins::PDU> pdu;
};

/**
 * \class PacketStream
 * \brief Machinery for processing a stream of packets.
 */
class PacketStream
{
public:
    /**
     * \typedef DNSSink
     * \brief Sink function for DNS messages.
     */
    using DNSSink = std::function<void (std::unique_ptr<DNSMessage>&)>;

    /**
     * \typedef AddressEventSink
     * \brief Sink function for address events.
     */
    using AddressEventSink = std::function<void (std::shared_ptr<AddressEvent>&)>;

    /**
     * \brief Constructor.
     *
     * \param config             configuration information.
     * \param dns_sink           sink for DNS messages.
     * \param address_event_sink sink for Address Event messages.
     */
    PacketStream(const Configuration& config, DNSSink dns_sink, AddressEventSink address_event_sink);

    /**
     * \brief Process an incoming packet.
     *
     * \param pcap  the incoming packet.
     * \throws unhandled_packet if the packet is not a DNS packet.
     * \throws malformed_packet if the packet cannot be decoded.
     */
    void process_packet(std::shared_ptr<PcapItem>& pcap);

protected:
    /**
     * \struct PktData
     * \brief Transport data on a packet.
     */
    struct PktData
    {
        /**
         * \brief Packet timestamp.
         */
        std::chrono::system_clock::time_point timestamp;

        /**
         * \brief Packet source address.
         */
        IPAddress srcIP;

        /**
         * \brief Packet destination address.
         */
        IPAddress dstIP;

        /**
         * \brief Packet source port.
         */
        uint16_t srcPort;

        /**
         * \brief Packet destination port.
         */
        uint16_t dstPort;

        /**
         * \brief Packet hop limit.
         */
        uint8_t hoplimit;

        /**
         * \brief `true` if packet arrived via TCP.
         */
        bool tcp;
    };

    /**
     * \brief Callback when a new TCP stream is created.
     *
     * \param stream the new stream.
     */
    void on_new_stream(Tins::TCPIP::Stream& stream);

    /**
     * \brief Callback when a TCP stream has fresh data.
     *
     * \param stream the stream.
     */
    void on_new_client_data(Tins::TCPIP::Stream& stream);

    /**
     * \brief Callback when a TCP stream has fresh data.
     *
     * \param stream the stream.
     */
    void on_new_server_data(Tins::TCPIP::Stream& stream);

    /**
     * \brief Callback when a TCP stream has fresh data.
     *
     * \param payload the stream data payload.
     */
    void on_new_stream_data(Tins::TCPIP::Stream::payload_type& payload);

    /**
     * \brief Find the IP or IPv6 PDU in the packet.
     *
     * \param pdu the incoming PDU.
     * \returns pointer to IP or IPv6 packet, `null` if ignored VLAN.
     * \throws unhandled_packet if no IP/IPv6 PDU found.
     */
    Tins::PDU* find_ip_pdu(Tins::PDU* pdu);

    /**
     * \brief Process IPv4 packet.
     *
     * Extract the source and destination addresses and hoplimit.
     *
     * \param pdu      IPv4 PDU.
     * \param pkt_data the packet data.
     * \returns inner PDU or `null` if nothing to process.
     * \throws malformed_packet if there is no inner PDU.
     */
    Tins::PDU* ipv4_packet(Tins::IP* pdu, PktData& pkt_data);

    /**
     * \brief Process IPv6 packet.
     *
     * Extract the source and destination addresses and hoplimit.
     *
     * \param pdu      IPv6 PDU.
     * \param pkt_data the packet data.
     * \returns inner PDU or `null` if nothing to process.
     * \throws malformed_packet if there is no inner PDU.
     */
    Tins::PDU* ipv6_packet(Tins::IPv6* pdu, PktData& pkt_data);

    /**
     * \brief Process UDP packet contents.
     *
     * \param udp      UDP packet.
     * \param pkt_data basic packet data so far.
     * \throws malformed_packet if no data PDU found.
     * \throws unhandled_packet if packet sent to port other than 53.
     */
    void udp_packet(Tins::UDP* udp, PktData& pkt_data);

    /**
     * \brief Process TCP packet contents.
     *
     * \param tcp      TCP packet.
     * \param ip       Enclosing IP/IPv6 packet.
     * \param pkt_data basic packet data so far.
     * \throws malformed_packet if no data PDU found.
     * \throws unhandled_packet if packet sent to port other than 53.
     */
    void tcp_packet(Tins::TCP* tcp, Tins::PDU* ip, PktData& pkt_data);

    /**
     * \brief Process ICMP packet contents.
     *
     * \param icmp     ICMP packet.
     * \param ip       Enclosing IP packet.
     * \param pkt_data basic packet data so far.
     * \throws malformed_packet if no data PDU found.
     */
    void icmp_packet(Tins::ICMP* icmp, Tins::PDU* ip, PktData& pkt_data);

    /**
     * \brief Process ICMPv6 packet contents.
     *
     * \param icmp     ICMPv6 packet.
     * \param ip       Enclosing IPv6 packet.
     * \param pkt_data basic packet data so far.
     * \throws malformed_packet if no data PDU found.
     */
    void icmpv6_packet(Tins::ICMPv6* icmp, Tins::PDU* ip, PktData& pkt_data);

    /**
     * \brief Dispatch a DNS message.
     *
     * \param pdu   the message data.
     * \param pkt_data basic packet data so far.
     */
    void dispatch_dns(Tins::RawPDU* pdu, PktData& pkt_data);

    /**
     * \brief Inspect the packet for IP message data.
     *
     * \param pcap     the incoming packet.
     * \param msg_data put message data here.
     * \returns `true` if message data found.
     * \throws unhandled_packet if no IP/IPv6/UDP/TCP/data PDU found
     * or packet sent to port other than 53.
     * \throws malformed_packet if the packet cannot be decoded.
     */
    bool find_message_data(std::shared_ptr<PcapItem>& pcap,
                           struct MsgData& msg_data);

private:
    /**
     * \brief the capture configuration.
     */
    const Configuration& config_;

    /**
     * \brief sink function for completed DNS packets.
     */
    DNSSink dns_sink_;

    /**
     * \brief sink function for address events.
     */
    AddressEventSink address_event_sink_;

    /**
     * \brief IPv4 fragment reassembly.
     */
    Tins::IPv4Reassembler reassembler_ipv4_;

    /**
     * \brief TCP stream follower.
     */
    Tins::TCPIP::StreamFollower tcp_stream_follower_;

    /**
     * \brief last seen TCP hop limit.
     */
    PktData* last_tcp_packet_data_;
};

#endif
