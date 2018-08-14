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
      enc_(std::move(enc)), data_(make_unique<block_cbor::BlockData>(config.max_block_qr_items)),
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
         output_pattern_.need_rotate(timestamp,
                                     config_,
                                     config_.max_blocks_in_file > 0 &&
                                     blocks_in_file_ >= config_.max_blocks_in_file) )
    {
        close();
        filename_ = output_pattern_.filename(timestamp, config_);
        enc_->open(filename_);
        writeFileHeader();
        blocks_in_file_ = 0;
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
    block_cbor::QuerySignature qs;

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
    qs.transport_flags = transportFlags(qr);
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
    qri.signature = data_->add_query_signature(qs);
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
    constexpr unsigned major_format_index = block_cbor::find_file_preamble_index(block_cbor::FilePreambleField::major_format_version);
    constexpr unsigned minor_format_index = block_cbor::find_file_preamble_index(block_cbor::FilePreambleField::minor_format_version);
    constexpr unsigned configuration_index = block_cbor::find_file_preamble_index(block_cbor::FilePreambleField::configuration);
    constexpr unsigned generator_index = block_cbor::find_file_preamble_index(block_cbor::FilePreambleField::generator_id);
    constexpr unsigned host_index = block_cbor::find_file_preamble_index(block_cbor::FilePreambleField::host_id);

    enc_->writeArrayHeader(3);
    enc_->write(block_cbor::FILE_FORMAT_ID);

    // File preamble.
    enc_->writeMapHeader();
    enc_->write(major_format_index);
    enc_->write(block_cbor::FILE_FORMAT_MAJOR_VERSION);
    enc_->write(minor_format_index);
    enc_->write(block_cbor::FILE_FORMAT_MINOR_VERSION);

    enc_->write(configuration_index);
    writeConfiguration();

    if ( !config_.omit_sysid )
    {
        enc_->write(generator_index);
        enc_->write(PACKAGE_STRING);

        char buf[_POSIX_HOST_NAME_MAX];
        gethostname(buf, sizeof(buf));
        buf[_POSIX_HOST_NAME_MAX - 1] = '\0';
        enc_->write(host_index);
        enc_->write(std::string(buf));
    }
    enc_->writeBreak(); // End of preamble

    // Write file header: Start of file blocks.
    enc_->writeArrayHeader();
}

void BlockCborWriter::writeConfiguration()
{
    constexpr unsigned query_timeout_index = block_cbor::find_configuration_index(block_cbor::ConfigurationField::query_timeout);
    constexpr unsigned skew_timeout_index = block_cbor::find_configuration_index(block_cbor::ConfigurationField::skew_timeout);
    constexpr unsigned snaplen_index = block_cbor::find_configuration_index(block_cbor::ConfigurationField::snaplen);
    constexpr unsigned promisc_index = block_cbor::find_configuration_index(block_cbor::ConfigurationField::promisc);
    constexpr unsigned interfaces_index = block_cbor::find_configuration_index(block_cbor::ConfigurationField::interfaces);
    constexpr unsigned server_addresses_index = block_cbor::find_configuration_index(block_cbor::ConfigurationField::server_addresses);
    constexpr unsigned vlan_ids_index = block_cbor::find_configuration_index(block_cbor::ConfigurationField::vlan_ids);
    constexpr unsigned filter_index = block_cbor::find_configuration_index(block_cbor::ConfigurationField::filter);
    constexpr unsigned query_options_index = block_cbor::find_configuration_index(block_cbor::ConfigurationField::query_options);
    constexpr unsigned response_options_index = block_cbor::find_configuration_index(block_cbor::ConfigurationField::response_options);
    constexpr unsigned accept_rr_types_index = block_cbor::find_configuration_index(block_cbor::ConfigurationField::accept_rr_types);
    constexpr unsigned ignore_rr_types_index = block_cbor::find_configuration_index(block_cbor::ConfigurationField::ignore_rr_types);
    constexpr unsigned max_block_qr_items_index = block_cbor::find_configuration_index(block_cbor::ConfigurationField::max_block_qr_items);

    enc_->writeMapHeader();

    enc_->write(query_timeout_index);
    enc_->write(config_.query_timeout);
    enc_->write(skew_timeout_index);
    enc_->write(config_.skew_timeout);
    enc_->write(snaplen_index);
    enc_->write(config_.snaplen);
    enc_->write(promisc_index);
    enc_->write(config_.promisc_mode);
    enc_->write(interfaces_index);
    enc_->writeArrayHeader();
    for ( const auto& s : config_.network_interfaces )
        enc_->write(s);
    enc_->writeBreak();
    enc_->write(server_addresses_index);
    enc_->writeArrayHeader();
    for ( const auto& s : config_.server_addresses )
        enc_->write(s.asNetworkBinary());
    enc_->writeBreak();
    enc_->write(vlan_ids_index);
    enc_->writeArrayHeader();
    for ( const auto& id : config_.vlan_ids )
        enc_->write(id);
    enc_->writeBreak();
    enc_->write(filter_index);
    enc_->write(config_.filter);
    enc_->write(query_options_index);
    enc_->write(config_.output_options_queries);
    enc_->write(response_options_index);
    enc_->write(config_.output_options_responses);
    enc_->write(accept_rr_types_index);
    enc_->writeArrayHeader();
    for ( const auto&a_rr : config_.accept_rr_types )
        enc_->write(a_rr);
    enc_->writeBreak();
    enc_->write(ignore_rr_types_index);
    enc_->writeArrayHeader();
    for ( const auto& i_rr : config_.ignore_rr_types )
        enc_->write(i_rr);
    enc_->writeBreak();
    enc_->write(max_block_qr_items_index);
    enc_->write(config_.max_block_qr_items);

    enc_->writeBreak(); // End of config info
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
    blocks_in_file_++;
}
