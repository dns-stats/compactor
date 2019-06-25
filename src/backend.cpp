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

void PcapBackend::output(const QueryResponseData& qrd, const Configuration& config)
{
    std::unique_ptr<QueryResponse> qr{convert_to_wire(qrd)};

    if ( using_compression_ &&
         !config.exclude_hints.query_question_section &&
         !config.exclude_hints.response_answer_section &&
         !config.exclude_hints.response_authority_section &&
         !config.exclude_hints.response_additional_section &&
         qr->has_response() && qrd.response_size )
    {
        if ( *qrd.response_size != qr->response().dns.size() )
            if ( auto_compression_ )
            {
                // See if Knot works better. If it does, stick with it.
                CaptureDNS::set_name_compression(CaptureDNS::KNOT_1_6);
                qr->response().dns.clear_cached_size();
                if ( *qrd.response_size != qr->response().dns.size() )
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

std::unique_ptr<QueryResponse> PcapBackend::convert_to_wire(const QueryResponseData& qrd)
{
    std::unique_ptr<DNSMessage> query, response;

    if ( qrd.qr_flags & block_cbor::QUERY_ONLY )
    {
        query = make_unique<DNSMessage>();
        query->timestamp = *qrd.timestamp;
        query->tcp = *qrd.qr_transport_flags & block_cbor::TCP;
        query->clientIP = *qrd.client_address;
        query->serverIP = *qrd.server_address;
        query->clientPort = *qrd.client_port;
        query->serverPort = *qrd.server_port;
        query->hoplimit = *qrd.hoplimit;
        query->dns.type(CaptureDNS::QRType::QUERY);
        query->dns.id(*qrd.id);
        query->dns.opcode(*qrd.query_opcode);
        query->dns.rcode(*qrd.query_rcode);
        // Used, if present, in output() to evaluate label compression scheme usage.
        if ( qrd.query_size )
            query->wire_size = *qrd.query_size;
        block_cbor::set_dns_flags(*query, *qrd.dns_flags, true);

        if ( qrd.qr_flags & block_cbor::QR_HAS_QUESTION )
            query->dns.add_query(CaptureDNS::query(*qrd.qname, *qrd.query_type, *qrd.query_class));

        add_extra_sections(*query,
                           qrd.query_questions,
                           qrd.query_answers,
                           qrd.query_authorities,
                           qrd.query_additionals);

        if ( qrd.qr_flags & block_cbor::QUERY_HAS_OPT )
        {
            uint32_t ttl = ((*qrd.query_rcode >> 4) &0xff);
            ttl <<= 8;
            ttl |= (*qrd.query_edns_version & 0xff);
            ttl <<= 16;
            if ( *qrd.dns_flags & block_cbor::QUERY_DO )
                ttl |= 0x8000;
            query->dns.add_additional(
                CaptureDNS::resource(
                    "",
                    *qrd.query_opt_rdata,
                    CaptureDNS::OPT,
                    static_cast<CaptureDNS::QueryClass>(*qrd.query_edns_payload_size),
                    ttl));
        }
    }

    if ( qrd.qr_flags & block_cbor::RESPONSE_ONLY )
    {
        response = make_unique<DNSMessage>();
        response->timestamp = *qrd.timestamp;
        // If there is no query, the timestamp is the response timestamp.
        if ( ( qrd.qr_flags & block_cbor::QUERY_ONLY ) && qrd.response_delay )
            response->timestamp += *qrd.response_delay;
        response->tcp = *qrd.qr_transport_flags & block_cbor::TCP;
        response->clientIP = *qrd.client_address;
        response->serverIP = *qrd.server_address;
        response->clientPort = *qrd.client_port;
        response->serverPort = *qrd.server_port;
        response->dns.type(CaptureDNS::QRType::RESPONSE);
        response->dns.id(*qrd.id);
        response->dns.opcode(*qrd.query_opcode);
        response->dns.rcode(*qrd.response_rcode);
        // Used, if present, in output() to evaluate label compression scheme usage.
        if ( qrd.response_size )
            response->wire_size = *qrd.response_size;
        block_cbor::set_dns_flags(*response, *qrd.dns_flags, false);

        if ( ( qrd.qr_flags & block_cbor::QR_HAS_QUESTION ) &&
             ! ( qrd.qr_flags & block_cbor::RESPONSE_HAS_NO_QUESTION ) )
            response->dns.add_query(CaptureDNS::query(*qrd.qname, *qrd.query_type, *qrd.query_class));

        add_extra_sections(*response,
                           qrd.response_questions,
                           qrd.response_answers,
                           qrd.response_authorities,
                           qrd.response_additionals);
    }

    std::unique_ptr<QueryResponse> res;

    if ( query )
    {
        res = make_unique<QueryResponse>(std::move(query));
        if ( response )
            res->set_response(std::move(response));
    }
    else
    {
        res = make_unique<QueryResponse>(std::move(response), false);
    }

    return res;
}

void PcapBackend::add_extra_sections(DNSMessage& dns,
                                     const boost::optional<std::vector<QueryResponseData::Question>>& questions,
                                     const boost::optional<std::vector<QueryResponseData::RR>>& answers,
                                     const boost::optional<std::vector<QueryResponseData::RR>>& authorities,
                                     const boost::optional<std::vector<QueryResponseData::RR>>& additionals)
{
    if ( questions )
        for ( const auto& q: *questions )
            dns.dns.add_query(CaptureDNS::query(*q.qname, *q.qtype, *q.qclass));

    if ( answers )
        for ( const auto& rr: *answers )
            dns.dns.add_answer(CaptureDNS::resource(*rr.name, *rr.rdata, *rr.rtype, *rr.rclass, *rr.ttl));

    if ( authorities )
        for ( const auto& rr: *authorities )
            dns.dns.add_authority(CaptureDNS::resource(*rr.name, *rr.rdata, *rr.rtype, *rr.rclass, *rr.ttl));

    if ( additionals )
        for ( const auto& rr: *additionals )
            dns.dns.add_additional(CaptureDNS::resource(*rr.name, *rr.rdata, *rr.rtype, *rr.rclass, *rr.ttl));
}

void PcapBackend::write_qr_tcp(const std::unique_ptr<QueryResponse>& qr)
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

void PcapBackend::write_qr_udp(const std::unique_ptr<QueryResponse>& qr)
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

void PcapBackend::check_exclude_hints(const HintsExcluded& exclude_hints)
{
    std::vector<std::string> missing;

    if ( !opts_.defaults.time_offset )
        missing.push_back("time-offset");
    if ( !opts_.defaults.client_address )
        missing.push_back("client-address");
    if ( !opts_.defaults.client_port )
        missing.push_back("client-port");
    if ( !opts_.defaults.client_hoplimit )
        missing.push_back("client-hoplimit");
    if ( !opts_.defaults.server_address )
        missing.push_back("server-address");
    if ( !opts_.defaults.server_port )
        missing.push_back("server-port");
    if ( !opts_.defaults.transport )
        missing.push_back("qr-transport-flags");

    if ( !opts_.defaults.transaction_id )
        missing.push_back("transaction-id");
    if ( !opts_.defaults.query_opcode )
        missing.push_back("query-opcode");
    if ( !opts_.defaults.dns_flags )
        missing.push_back("dns-flags");
    if ( !opts_.defaults.query_rcode )
        missing.push_back("query-rcode");
    if ( !opts_.defaults.query_name )
        missing.push_back("query-name");
    if ( exclude_hints.query_class_type )
    {
        if ( !opts_.defaults.query_class )
            missing.push_back("query-class");
        if ( !opts_.defaults.query_type )
            missing.push_back("query-type");
    }
    if ( !opts_.defaults.query_udp_size )
        missing.push_back("query-udp-size");
    if ( !opts_.defaults.query_edns_version )
        missing.push_back("query-edns-version");
    if ( !opts_.defaults.response_delay )
        missing.push_back("response-delay");
    if ( !opts_.defaults.response_rcode )
        missing.push_back("response-rcode");

    if ( !opts_.defaults.rr_ttl )
        missing.push_back("rr-ttl");

    if ( !missing.empty() )
    {
        std::string report;
        bool comma = false;

        for ( const auto& a : missing )
        {
            if ( comma )
                report.append(", ");
            report.append(a);
            comma = true;
        }

        throw pcap_defaults_backend_error(report);
    }
}
