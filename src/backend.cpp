/*
 * Copyright 2018-2019 Internet Corporation for Assigned Names and Numbers, Sinodun IT.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <sstream>
#include <utility>

#include <boost/filesystem.hpp>

#include "config.h"

#include "bytestring.hpp"
#include "capturedns.hpp"
#include "pcapwriter.hpp"
#include "streamwriter.hpp"

#include "backend.hpp"

/**
 ** OutputBackend
 **/

std::string OutputBackend::output_name(const std::string& name)
{
    if ( name == StreamWriter::STDOUT_FILE_NAME )
        return name;

    std::string basename;

    if ( baseopts_.xz_output )
        basename = name + XzStreamWriter::suggested_extension();
    else if ( baseopts_.gzip_output )
        basename = name + GzipStreamWriter::suggested_extension();
    else
        basename = name + StreamWriter::suggested_extension();

    // Now, does it exist - if so, add counter.
    int count = 0;
    for(;;)
    {
        std::ostringstream oss;
        oss << basename;
        if ( count > 0 )
            oss << "-" << count;
        if ( !boost::filesystem::exists(oss.str()) )
            return oss.str();
        count++;
    }
}

/**
 ** PcapBackend
 **/

PcapBackend::PcapBackend(const PcapBackendOptions& opts, const std::string& fname)
    : OutputBackend(opts.baseopts), opts_(opts),
      auto_compression_(opts.auto_compression), bad_response_wire_size_count_(0)
{
    using_compression_ = ( CaptureDNS::name_compression() != CaptureDNS::NONE );

    output_path_ = output_name(fname);

    if ( opts.baseopts.xz_output )
        writer_ = make_unique<PcapWriter<XzStreamWriter>>(output_path_, opts.baseopts.xz_preset, 65535);
    else if ( opts.baseopts.gzip_output )
        writer_ = make_unique<PcapWriter<GzipStreamWriter>>(output_path_, opts.baseopts.gzip_level, 65535);
    else
        writer_ = make_unique<PcapWriter<StreamWriter>>(output_path_, 0, 65535);
}

PcapBackend::~PcapBackend()
{
}

void PcapBackend::output(std::shared_ptr<QueryResponse>& qr, const Configuration& config)
{
    if ( using_compression_ &&
         config.output_options_responses == Configuration::ALL &&
         qr->has_response() &&
         qr->response().wire_size != qr->response().dns.size() )
    {
        if ( auto_compression_ )
        {
            // See if Knot works better. If it does, stick with it.
            CaptureDNS::set_name_compression(CaptureDNS::KNOT_1_6);
            qr->response().dns.clear_cached_size();
            if ( qr->response().wire_size != qr->response().dns.size() )
            {
                CaptureDNS::set_name_compression(CaptureDNS::DEFAULT);
                bad_response_wire_size_count_++;
            }
            auto_compression_ = false;
        }
        else
            bad_response_wire_size_count_++;
    }

    if ( !opts_.baseopts.write_output)
        return;

    if ( ( qr->has_query() && qr->query().tcp ) ||
         ( qr->has_response() && qr->response().tcp ) )
        write_qr_tcp(qr);
    else
        write_qr_udp(qr);
}

void PcapBackend::report(std::ostream& os)
{
    if ( bad_response_wire_size_count_ > 0 )
        os <<
            "====================\n\n"
            "REGENERATION ERRORS:\n"
            "  Incorrect wire size: "
           << bad_response_wire_size_count_ << " packets\n\n";
}

std::string PcapBackend::output_file()
{
    if ( output_path_ == StreamWriter::STDOUT_FILE_NAME )
        return "";
    return output_path_;
}

void PcapBackend::write_qr_tcp(std::shared_ptr<QueryResponse> qr)
{
    IPAddress client_address, server_address;
    uint16_t client_port, server_port;
    uint8_t client_hoplimit, server_hoplimit;
    std::chrono::system_clock::time_point query_timestamp, response_timestamp;

    if ( qr->has_query() )
    {
        client_address = qr->query().clientIP;
        server_address = qr->query().serverIP;
        client_port = qr->query().clientPort;
        server_port = qr->query().serverPort;
        client_hoplimit = qr->query().hoplimit;
        query_timestamp = qr->query().timestamp;
        if ( qr->has_response() )
        {
            server_hoplimit = qr->response().hoplimit;
            response_timestamp = qr->response().timestamp;
        }
        else
        {
            server_hoplimit = client_hoplimit;
            response_timestamp = query_timestamp;
        }
    }
    else
    {
        client_address = qr->response().clientIP;
        server_address = qr->response().serverIP;
        client_port = qr->response().clientPort;
        server_port = qr->response().serverPort;
        client_hoplimit = qr->response().hoplimit;
        server_hoplimit = client_hoplimit;
        query_timestamp = qr->response().timestamp;
        response_timestamp = query_timestamp;
    }

    // Client SYN -> server.
    Tins::TCP ctcp(server_port, client_port);
    ctcp.set_flag(Tins::TCP::SYN, 1);
    write_packet(&ctcp, client_address, server_address, client_hoplimit, query_timestamp);
    ctcp.set_flag(Tins::TCP::SYN, 0);
    ctcp.seq(ctcp.seq() + 1);

    // Server ACK -> client.
    Tins::TCP stcp(client_port, server_port);
    stcp.set_flag(Tins::TCP::SYN, 1);
    stcp.set_flag(Tins::TCP::ACK, 1);
    stcp.ack_seq(ctcp.seq());
    write_packet(&stcp, server_address, client_address, server_hoplimit, query_timestamp);
    stcp.set_flag(Tins::TCP::SYN, 0);
    stcp.seq(stcp.seq() + 1);

    // Client SYN/ACK -> server.
    ctcp.set_flag(Tins::TCP::ACK, 1);
    ctcp.ack_seq(stcp.seq());
    write_packet(&ctcp, client_address, server_address, client_hoplimit, query_timestamp);

    // Client Query -> server.
    if ( qr->has_query() )
    {
        CaptureDNS dnsmsg = qr->query().dns;
        uint32_t dnssize = dnsmsg.size();
        Tins::PDU::serialization_type dnsbuf = dnsmsg.serialize();
        byte_string buf(dnsbuf.data(), dnssize);
        buf.reserve(dnssize + 2);
        buf.insert(buf.begin(), dnssize & 0xff);
        buf.insert(buf.begin(), (dnssize >> 8) & 0xff);
        Tins::RawPDU raw_pdu(buf.data(), buf.size());
        ctcp.inner_pdu(raw_pdu);
        ctcp.set_flag(Tins::TCP::PSH, 1);
        write_packet(&ctcp, client_address, server_address, client_hoplimit, query_timestamp);
        ctcp.set_flag(Tins::TCP::PSH, 0);
        ctcp.seq(ctcp.seq() + buf.size());
        ctcp.inner_pdu(nullptr);

        stcp.ack_seq(ctcp.seq());
        write_packet(&stcp, server_address, client_address, server_hoplimit, query_timestamp);
    }

    // Server Response -> client.
    if ( qr->has_response() && !opts_.query_only )
    {
        CaptureDNS dnsmsg = qr->response().dns;
        uint32_t dnssize = dnsmsg.size();
        Tins::PDU::serialization_type dnsbuf = dnsmsg.serialize();
        byte_string buf(dnsbuf.data(), dnssize);
        buf.reserve(dnssize + 2);
        buf.insert(buf.begin(), dnssize & 0xff);
        buf.insert(buf.begin(), (dnssize >> 8) & 0xff);
        Tins::RawPDU raw_pdu(buf.data(), buf.size());
        stcp.inner_pdu(raw_pdu);
        stcp.set_flag(Tins::TCP::PSH, 1);
        write_packet(&stcp, server_address, client_address, server_hoplimit, response_timestamp);
        stcp.set_flag(Tins::TCP::PSH, 0);
        stcp.seq(stcp.seq() + buf.size());
        stcp.inner_pdu(nullptr);

        ctcp.ack_seq(stcp.seq());
        write_packet(&ctcp, client_address, server_address, client_hoplimit, response_timestamp);
    }

    // Client FIN -> server.
    ctcp.set_flag(Tins::TCP::FIN, 1);
    ctcp.ack_seq(stcp.seq());
    write_packet(&ctcp, client_address, server_address, client_hoplimit, response_timestamp);
    ctcp.seq(ctcp.seq() + 1);

    // Server FIN -> client.
    stcp.set_flag(Tins::TCP::FIN, 1);
    stcp.ack_seq(ctcp.seq());
    write_packet(&stcp, server_address, client_address, server_hoplimit, response_timestamp);
    stcp.seq(stcp.seq() + 1);

    // Client ACK -> server.
    ctcp.set_flag(Tins::TCP::FIN, 0);
    ctcp.ack_seq(stcp.seq());
    write_packet(&ctcp, client_address, server_address, client_hoplimit, response_timestamp);
}

void PcapBackend::write_qr_udp(std::shared_ptr<QueryResponse> qr)
{
    if ( qr->has_query() )
        write_udp_packet(qr->query());
    if ( qr->has_response() && !opts_.query_only )
        write_udp_packet(qr->response());
}

void PcapBackend::write_udp_packet(const DNSMessage& dns)
{
    IPAddress clientIP = dns.clientIP;
    IPAddress serverIP = dns.serverIP;
    uint16_t clientPort = dns.clientPort;
    uint16_t serverPort = dns.serverPort;

    if ( dns.dns.type() == CaptureDNS::RESPONSE )
    {
        std::swap(clientIP, serverIP);
        std::swap(clientPort, serverPort);
    }

    Tins::UDP udp;
    udp.sport(clientPort);
    udp.dport(serverPort);
    udp.inner_pdu(dns.dns);

    write_packet(&udp, clientIP, serverIP, dns.hoplimit, dns.timestamp);
}

void PcapBackend::write_packet(Tins::PDU* pdu,
                               const IPAddress& src,
                               const IPAddress& dst,
                               uint8_t hoplimit,
                               const std::chrono::system_clock::time_point& timestamp)
{
    Tins::EthernetII ethernet;

    if ( src.is_ipv6() )
    {
        Tins::IPv6 ipv6(dst, src);
        ipv6.hop_limit(hoplimit);
        ipv6.inner_pdu(*pdu);
        ethernet.inner_pdu(ipv6);
    }
    else
    {
        Tins::IP ip(dst, src);
        ip.ttl(hoplimit);
        ip.inner_pdu(*pdu);
        ethernet.inner_pdu(ip);
    }

    writer_->write_packet(ethernet, timestamp);
}
