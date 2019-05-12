/*
 * Copyright 2016-2019 Internet Corporation for Assigned Names and Numbers.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Developed by Sinodun IT (www.sinodun.com)
 */

#include <chrono>
#include <stdexcept>

#include <limits.h>
#include <unistd.h>

#include "config.h"

#include "capturedns.hpp"
#include "cborencoder.hpp"
#include "dnsmessage.hpp"
#include "makeunique.hpp"
#include "blockcbor.hpp"
#include "blockcbordata.hpp"
#include "blockcborwriter.hpp"

BlockCborWriter::BlockCborWriter(const Configuration& config,
                                     std::unique_ptr<CborBaseStreamFileEncoder> enc)
    : BaseOutputWriter(config),
      output_pattern_(config.output_pattern + enc->suggested_extension(),
                      std::chrono::seconds(config.rotation_period)),
      enc_(std::move(enc)), data_(make_unique<block_cbor::BlockData>(config.max_block_items)),
      query_response_(), ext_rr_(nullptr), ext_group_(nullptr),
      last_end_block_statistics_()
{
}

BlockCborWriter::~BlockCborWriter()
{
    close();
}

void BlockCborWriter::close()
{
    if ( enc_->is_open() )
    {
        writeBlock();
        writeFileFooter();
        enc_->close();
    }
}

void BlockCborWriter::writeAE(const std::shared_ptr<AddressEvent>& ae,
                                const PacketStatistics& stats)
{
    data_->count_address_event(*ae);
    last_end_block_statistics_ = stats;
}

void BlockCborWriter::checkForRotation(const std::chrono::system_clock::time_point& timestamp)
{
    if ( !enc_->is_open() ||
         ( config_.max_output_size.size > 0 &&
           enc_->bytes_written() >= config_.max_output_size.size ) ||
         output_pattern_.need_rotate(timestamp, config_) )
    {
        close();
        filename_ = output_pattern_.filename(timestamp, config_);
        enc_->open(filename_);
        writeFileHeader();
    }
}

void BlockCborWriter::startRecord(const std::shared_ptr<QueryResponse>&)
{
    if ( data_->is_full() )
        writeBlock();
    query_response_.clear();
    clear_in_progress_extra_info();
}

void BlockCborWriter::endRecord(const std::shared_ptr<QueryResponse>&)
{
    data_->query_response_items.push_back(std::move(query_response_));
    query_response_.clear();
}

void BlockCborWriter::writeBasic(const std::shared_ptr<QueryResponse>& qr,
                                   const PacketStatistics& stats)
{
    const DNSMessage &d(qr->has_query() ? qr->query() : qr->response());
    block_cbor::QueryResponseItem& qri = query_response_;
    block_cbor::QueryResponseSignature qs;

    qri.qr_flags = 0;

    // If we're the first record in the block, note the time & stats.
    if ( data_->query_response_items.size() == 0 )
    {
        data_->earliest_time = d.timestamp;
        data_->start_packet_statistics = last_end_block_statistics_;
    } else if ( d.timestamp < data_->earliest_time )
         data_->earliest_time = d.timestamp;
    last_end_block_statistics_ = stats;

    // Basic query signature info.
    qs.server_address = data_->add_address(d.serverIP);
    qs.server_port = d.serverPort;
    qs.qr_transport_flags = transportFlags(qr);
    qs.dns_flags = dnsFlags(qr);

    // Basic query/response info.
    qri.tstamp = d.timestamp;
    qri.client_address = data_->add_address(d.clientIP);
    qri.client_port = d.clientPort;
    qri.id = d.dns.id();
    qs.qdcount = d.dns.questions_count();

    // Get first query info.
    for ( const auto& query : d.dns.queries() )
    {
        block_cbor::ClassType ct;
        ct.qtype = query.query_type();
        ct.qclass = query.query_class();
        qs.query_classtype = data_->add_classtype(ct);
        qri.qname = data_->add_name_rdata(query.dname());
        qri.qr_flags |= block_cbor::QR_HAS_QUESTION;
        break;
    }

    if ( qr->has_query() )
    {
        const DNSMessage &q(qr->query());

        qri.qr_flags |= block_cbor::QUERY_ONLY;
        qri.query_size = q.wire_size;
        qri.hoplimit = q.hoplimit;
        qs.query_opcode = q.dns.opcode();
        qs.query_rcode = q.dns.rcode();
        qs.query_ancount = q.dns.answers_count();
        qs.query_nscount = q.dns.authority_count();
        qs.query_arcount = q.dns.additional_count();

        auto edns0 = q.dns.edns0();
        if ( edns0 )
        {
            qs.query_rcode += edns0->extended_rcode() << 4;
            qri.qr_flags |= block_cbor::QUERY_HAS_OPT;
            qs.query_edns_payload_size = edns0->udp_payload_size();
            qs.query_edns_version = edns0->edns_version();
            qs.query_opt_rdata = data_->add_name_rdata(edns0->rr().data());
        }
    }

    if ( qr->has_response() )
    {
        const DNSMessage &r(qr->response());

        qri.qr_flags |= block_cbor::RESPONSE_ONLY;
        qri.response_size = r.wire_size;
        qs.response_rcode = r.dns.rcode();

        auto edns0 = r.dns.edns0();
        if ( edns0 )
        {
            qs.response_rcode += edns0->extended_rcode() << 4;
            qri.qr_flags |= block_cbor::RESPONSE_HAS_OPT;
        }

        if ( r.dns.questions_count() == 0 )
            qri.qr_flags |= block_cbor::RESPONSE_HAS_NO_QUESTION;
    }

    if ( qr->has_query() && qr->has_response() )
        qri.response_delay = std::chrono::duration_cast<std::chrono::microseconds>(qr->response().timestamp - qr->query().timestamp);

    qs.qr_flags = qri.qr_flags;
    qri.signature = data_->add_query_response_signature(qs);
}

void BlockCborWriter::startExtendedQueryGroup()
{
    if ( !query_response_.query_extra_info )
        query_response_.query_extra_info = make_unique<block_cbor::QueryResponseExtraInfo>();
    ext_group_ = query_response_.query_extra_info.get();
}

void BlockCborWriter::startExtendedResponseGroup()
{
    if ( !query_response_.response_extra_info )
        query_response_.response_extra_info = make_unique<block_cbor::QueryResponseExtraInfo>();
    ext_group_ = query_response_.response_extra_info.get();
}

void BlockCborWriter::endExtendedGroup()
{
    if ( extra_questions_.size() > 0 )
        ext_group_->questions_list = data_->add_questions_list(extra_questions_);
    if ( extra_answers_.size() > 0 )
        ext_group_->answers_list = data_->add_rrs_list(extra_answers_);
    if ( extra_authority_.size() > 0 )
        ext_group_->authority_list = data_->add_rrs_list(extra_authority_);
    if ( extra_additional_.size() > 0 )
        ext_group_->additional_list = data_->add_rrs_list(extra_additional_);

    clear_in_progress_extra_info();
}

void BlockCborWriter::startQuestionsSection()
{
}

void BlockCborWriter::writeQuestionRecord(const CaptureDNS::query& question)
{
    block_cbor::ClassType ct;
    block_cbor::Question q;

    q.qname = data_->add_name_rdata(question.dname());
    ct.qtype = question.query_type();
    ct.qclass = question.query_class();
    q.classtype = data_->add_classtype(ct);
    extra_questions_.push_back(data_->add_question(q));
}

void BlockCborWriter::endSection()
{
}

void BlockCborWriter::startAnswersSection()
{
    ext_rr_ = &extra_answers_;
}

void BlockCborWriter::writeResourceRecord(const CaptureDNS::resource& resource)
{
    block_cbor::ClassType ct;
    block_cbor::ResourceRecord rr;

    rr.name = data_->add_name_rdata(resource.dname());
    ct.qtype = resource.query_type();
    ct.qclass = resource.query_class();
    rr.classtype = data_->add_classtype(ct);
    rr.ttl = resource.ttl();
    rr.rdata = data_->add_name_rdata(resource.data());
    ext_rr_->push_back(data_->add_resource_record(rr));
}

void BlockCborWriter::startAuthoritySection()
{
    ext_rr_ = &extra_authority_;
}

void BlockCborWriter::startAdditionalSection()
{
    ext_rr_ = &extra_additional_;
}

void BlockCborWriter::writeFileHeader()
{
    constexpr int major_format_index = block_cbor::find_file_preamble_index(block_cbor::FilePreambleField::major_format_version);
    constexpr int minor_format_index = block_cbor::find_file_preamble_index(block_cbor::FilePreambleField::minor_format_version);
    constexpr int private_format_index = block_cbor::find_file_preamble_index(block_cbor::FilePreambleField::private_version);
    constexpr int block_parameters_index = block_cbor::find_file_preamble_index(block_cbor::FilePreambleField::block_parameters);

    enc_->writeArrayHeader(3);
    enc_->write(block_cbor::FILE_FORMAT_ID);

    // File preamble.
    enc_->writeMapHeader(4);
    enc_->write(major_format_index);
    enc_->write(block_cbor::FILE_FORMAT_10_MAJOR_VERSION);
    enc_->write(minor_format_index);
    enc_->write(block_cbor::FILE_FORMAT_10_MINOR_VERSION);
    enc_->write(private_format_index);
    enc_->write(block_cbor::FILE_FORMAT_10_PRIVATE_VERSION);

    enc_->write(block_parameters_index);
    writeBlockParameters();

    // Write file header: Start of file blocks.
    enc_->writeArrayHeader();
}

void BlockCborWriter::writeBlockParameters()
{
    block_cbor::BlockParameters block_parameters;
    block_cbor::StorageParameters& sp = block_parameters.storage_parameters;
    block_cbor::StorageHints& sh = sp.storage_hints;
    block_cbor::CollectionParameters& cp = block_parameters.collection_parameters;

    // Set storage parameter values from configuration.
    sp.max_block_items = config_.max_block_items;

    // Query response hints. Compactor always gives time_offset to
    // response size inclusive. It does not currently give response
    // processing data.
    sh.query_response_hints = block_cbor::QueryResponseHintFlags(
        0x3ff |
        config_.output_options_queries << 11 |
        (config_.output_options_responses & 0xe) << 14);
    // Query response signature hints. Compactor always writes everything
    // except qr-type, where it has no data.
    sh.query_response_signature_hints =
        block_cbor::QueryResponseSignatureHintFlags(0x1f7);
    // RR hints. Compactor always writes everything.
    sh.rr_hints = block_cbor::RRHintFlags(0x3);
    // Other data hints. Compactor always writes address event hints,
    // but does not currently write malformed messages.
    sh.other_data_hints = block_cbor::OtherDataHintFlags(0x2);

    // List of opcodes recorded. Currently compactor doesn't
    // filter on opcodes, so set this to all current opcodes.
    for ( const auto op : CaptureDNS::OPCODES )
        sp.opcodes.push_back(op);

    // List of RR types recorded.
    for ( const auto rr : CaptureDNS::QUERYTYPES )
        if ( outputRRType(rr) )
            sp.rr_types.push_back(rr);

    // Compactor currently doesn't support anonymisation,
    // sampling or name normalisation, so we don't give
    // storage flags or sampling or anonymisation methods.
    // Set collection parameter items from configuration.

    // Compactor currently doesn't support client or server address
    // prefix length setting, so we don't give that parameter.

    // Set collection parameter items from configuration.
    cp.query_timeout = config_.query_timeout;
    cp.skew_timeout = config_.skew_timeout;
    cp.snaplen = config_.snaplen;
    cp.promisc = config_.promisc_mode;

    for ( const auto& s : config_.network_interfaces )
        cp.interfaces.push_back(s);

    for ( const auto& a : config_.server_addresses )
        cp.server_addresses.push_back(a);

    for ( const auto& v : config_.vlan_ids )
        cp.vlan_ids.push_back(v);

    cp.filter = config_.filter;

    if ( !config_.omit_sysid )
    {
        cp.generator_id = PACKAGE_STRING;

        if ( !config_.omit_hostid )
        {
            char buf[_POSIX_HOST_NAME_MAX];
            gethostname(buf, sizeof(buf));
            buf[_POSIX_HOST_NAME_MAX - 1] = '\0';
            cp.host_id = buf;
        }
    }

    // Currently we only write one block parameter item.
    enc_->writeArrayHeader(1);
    block_parameters.writeCbor(*enc_);
}

void BlockCborWriter::writeFileFooter()
{
    enc_->writeBreak();
}

void BlockCborWriter::writeBlock()
{
    data_->last_packet_statistics = last_end_block_statistics_;
    data_->writeCbor(*enc_);
    data_->clear();
}
