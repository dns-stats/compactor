/*
 * Copyright 2016-2020 Internet Corporation for Assigned Names and Numbers.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Developed by Sinodun IT (www.sinodun.com)
 */

#include <algorithm>
#include <iomanip>
#include <vector>

#include "config.h"

#include "baseoutputwriter.hpp"
#include "blockcbor.hpp"
#include "bytestring.hpp"
#include "makeunique.hpp"
#include "dnsmessage.hpp"

#include "blockcborreader.hpp"

namespace
{
    void output_duration(std::ostream& output, const std::chrono::microseconds duration)
    {
        output << duration.count() / 1000000 << "s"
               << duration.count() % 1000000 << "us";
    }

    void output_time_point(std::ostream& output, const std::chrono::system_clock::time_point timepoint)
    {
        std::time_t t = std::chrono::system_clock::to_time_t(timepoint);
        std::tm tm = *std::gmtime(&t);
        char buf[40];
        std::strftime(buf, sizeof(buf), "%Y-%m-%d %Hh%Mm%Ss", &tm);
        double us = std::chrono::duration_cast<std::chrono::microseconds>(timepoint.time_since_epoch()).count() % 1000000;
        output << buf << us << "us UTC";
    }
}

BlockCborReader::BlockCborReader(CborBaseDecoder& dec,
                                 Configuration& config,
                                 const Defaults& defaults,
                                 boost::optional<PseudoAnonymise> pseudo_anon)
    : dec_(dec),
      defaults_(defaults),
      next_item_(0),
      need_block_(true),
      file_format_version_(block_cbor::FileFormatVersion::format_10),
      current_block_num_(0),
      pseudo_anon_(pseudo_anon)
{
    readFileHeader(config);
    block_ = make_unique<block_cbor::BlockData>(block_parameters_, file_format_version_);
}

void BlockCborReader::readFileHeader(Configuration& config)
{
    try
    {
        bool old_no_header_format = true;

        // Initial array header.
        bool indef;
        uint64_t n_elems = dec_.readArrayHeader(indef);
        if ( dec_.type() == CborBaseDecoder::TYPE_STRING )
            old_no_header_format = false;

        if ( !old_no_header_format )
        {
            if ( n_elems != 3 )
                throw cbor_file_format_error("Unexpected initial array length");

            std::string file_type_id = dec_.read_string();
            if ( file_type_id == block_cbor::FILE_FORMAT_ID )
                readFilePreamble(config, block_cbor::FileFormatVersion::format_10);
            else if ( file_type_id == block_cbor::FILE_FORMAT_02_ID )
                readFilePreamble(config, block_cbor::FileFormatVersion::format_02);
            else
                throw cbor_file_format_error("This is not a C-DNS file");

            // Finally, the start of the block array.
            nblocks_ = dec_.readArrayHeader(blocks_indef_);
        }
        else
        {
            nblocks_ = n_elems;
            blocks_indef_ = indef;
            fields_ = make_unique<block_cbor::FileVersionFields>(0, block_cbor::FILE_FORMAT_02_VERSION, 0);
        }
    }
    catch (const std::logic_error& e)
    {
        throw cbor_file_format_error("Unexpected item reading header");
    }
}

void BlockCborReader::readFilePreamble(Configuration& config, block_cbor::FileFormatVersion header_version)
{
    unsigned major_version = 0;
    unsigned minor_version = 0;
    unsigned private_version = 0;
    bool indef;
    uint64_t n_elems = dec_.readMapHeader(indef);
    while ( indef || n_elems-- > 0 )
    {
        if ( indef && dec_.type() == CborBaseDecoder::TYPE_BREAK )
        {
            dec_.readBreak();
            break;
        }

        switch(block_cbor::file_preamble_field(dec_.read_unsigned(), header_version))
        {
        case block_cbor::FilePreambleField::major_format_version:
            if ( header_version != block_cbor::FileFormatVersion::format_10 )
                throw cbor_file_format_error("Unexpected version item reading header");
            major_version = dec_.read_unsigned();
            break;

        case block_cbor::FilePreambleField::minor_format_version:
            if ( header_version != block_cbor::FileFormatVersion::format_10 )
                throw cbor_file_format_error("Unexpected version item reading header");
            minor_version = dec_.read_unsigned();
            break;

        case block_cbor::FilePreambleField::private_version:
            if ( header_version != block_cbor::FileFormatVersion::format_10 )
                throw cbor_file_format_error("Unexpected version item reading header");
            private_version = dec_.read_unsigned();
            break;

            // This may be either format 1.0 block parameters,
            // format 0.5 configuration or format 0.2 configuration.
            // Now we can distinguish format 1.0 and format 0.5, and
            // at last set up the field mapper.
        case block_cbor::FilePreambleField::block_parameters:
        case block_cbor::FilePreambleField::configuration:
            if ( header_version == block_cbor::FileFormatVersion::format_10 &&
                 major_version == block_cbor::FILE_FORMAT_05_MAJOR_VERSION &&
                 minor_version == block_cbor::FILE_FORMAT_05_MINOR_VERSION )
            {
                header_version = block_cbor::FileFormatVersion::format_05;
                file_format_version_ = header_version;
            }

            if ( fields_ )
                throw cbor_file_format_error("Unexpected configuration reading header");
            fields_ = make_unique<block_cbor::FileVersionFields>(major_version, minor_version, private_version);

            switch(header_version)
            {
            case block_cbor::FileFormatVersion::format_10:
                readBlockParameters(config);
                break;

            case block_cbor::FileFormatVersion::format_05:
            case block_cbor::FileFormatVersion::format_02:
                readConfiguration(config);
                break;

            default:
                throw cbor_file_format_error("Unexpected version item reading header");
                break;
            }
            break;

        // Obsolete items format 0.5
        case block_cbor::FilePreambleField::generator_id:
            generator_id_ = dec_.read_string();
            break;

        case block_cbor::FilePreambleField::host_id:
            host_id_ = dec_.read_string();
#if ENABLE_PSEUDOANONYMISATION
            if ( pseudo_anon_ )
                host_id_.clear();
#endif
            break;

        // Obsolete items format 0.2
        case block_cbor::FilePreambleField::format_version:
            if ( header_version != block_cbor::FileFormatVersion::format_02 )
                throw cbor_file_format_error("Unexpected version item reading header");
            minor_version = dec_.read_unsigned();
            if ( minor_version != block_cbor::FILE_FORMAT_02_VERSION )
                throw cbor_file_format_error("Wrong file format version");
            file_format_version_ = header_version;
            break;

        default:
            // Unknown item, skip.
            dec_.skip();
            break;
        }
    }

    if ( !fields_ )
        throw cbor_file_format_error("File preamble missing version information");
}

void BlockCborReader::readConfiguration(Configuration& config)
{
    bool indef;
    uint64_t n_elems = dec_.readMapHeader(indef);
    while ( indef || n_elems-- > 0 )
    {
        bool arr_indef;
        uint64_t arr_elems;

        if ( indef && dec_.type() == CborBaseDecoder::TYPE_BREAK )
        {
            dec_.readBreak();
            break;
        }

        switch(fields_->configuration_field(dec_.read_unsigned()))
        {
        case block_cbor::ConfigurationField::query_timeout:
            config.query_timeout = std::chrono::milliseconds(dec_.read_unsigned());
            break;

        case block_cbor::ConfigurationField::skew_timeout:
            config.skew_timeout = std::chrono::microseconds(dec_.read_unsigned());
            break;

        case block_cbor::ConfigurationField::snaplen:
            config.snaplen = dec_.read_unsigned();
            break;

        case block_cbor::ConfigurationField::promisc:
            config.promisc_mode = dec_.read_bool();
            break;

        case block_cbor::ConfigurationField::interfaces:
            config.network_interfaces.clear();
            arr_elems = dec_.readArrayHeader(arr_indef);
            while ( arr_indef || arr_elems-- > 0 )
            {
                if ( arr_indef && dec_.type() == CborBaseDecoder::TYPE_BREAK )
                {
                    dec_.readBreak();
                    break;
                }

                config.network_interfaces.push_back(dec_.read_string());
            }
            break;

        case block_cbor::ConfigurationField::filter:
            config.filter = dec_.read_string();
#if ENABLE_PSEUDOANONYMISATION
            if ( pseudo_anon_ )
                config.filter.clear();
#endif
            break;

        case block_cbor::ConfigurationField::query_options:
            config.output_options_queries = dec_.read_unsigned();
            break;

        case block_cbor::ConfigurationField::response_options:
            config.output_options_responses = dec_.read_unsigned();
            break;

        case block_cbor::ConfigurationField::vlan_ids:
            config.vlan_ids.clear();
            arr_elems = dec_.readArrayHeader(arr_indef);
            while ( arr_indef || arr_elems-- > 0 )
            {
                if ( arr_indef && dec_.type() == CborBaseDecoder::TYPE_BREAK )
                {
                    dec_.readBreak();
                    break;
                }

                config.vlan_ids.push_back(dec_.read_unsigned());
            }
            break;

        case block_cbor::ConfigurationField::accept_rr_types:
            config.accept_rr_types.clear();
            arr_elems = dec_.readArrayHeader(arr_indef);
            while ( arr_indef || arr_elems-- > 0 )
            {
                if ( arr_indef && dec_.type() == CborBaseDecoder::TYPE_BREAK )
                {
                    dec_.readBreak();
                    break;
                }

                config.accept_rr_types.push_back(dec_.read_unsigned());
            }
            break;

        case block_cbor::ConfigurationField::ignore_rr_types:
            config.ignore_rr_types.clear();
            arr_elems = dec_.readArrayHeader(arr_indef);
            while ( arr_indef || arr_elems-- > 0 )
            {
                if ( arr_indef && dec_.type() == CborBaseDecoder::TYPE_BREAK )
                {
                    dec_.readBreak();
                    break;
                }

                config.ignore_rr_types.push_back(dec_.read_unsigned());
            }
            break;

        case block_cbor::ConfigurationField::server_addresses:
            config.server_addresses.clear();
            arr_elems = dec_.readArrayHeader(arr_indef);
            while ( arr_indef || arr_elems-- > 0 )
            {
                if ( arr_indef && dec_.type() == CborBaseDecoder::TYPE_BREAK )
                {
                    dec_.readBreak();
                    break;
                }

                IPAddress addr(dec_.read_binary());
#if ENABLE_PSEUDOANONYMISATION
                if ( pseudo_anon_ )
                    addr = pseudo_anon_->address(addr);
#endif
                config.server_addresses.push_back(addr);
            }
            break;

        case block_cbor::ConfigurationField::max_block_qr_items:
            config.max_block_items = dec_.read_unsigned();
            break;

        default:
            // Unknown item, skip.
            dec_.skip();
            break;
        }
    }

    // Generate a suitable instance of block parameters from this configuration.
    block_cbor::BlockParameters block_parameters;

    config.populate_block_parameters(block_parameters);
    block_parameters_.push_back(block_parameters);
}

void BlockCborReader::readBlockParameters(Configuration& config)
{
    bool first_bp = true;
    bool indef;
    uint64_t n_elems = dec_.readArrayHeader(indef);
    if ( !indef )
        block_parameters_.reserve(n_elems);
    while ( indef || n_elems-- > 0 )
    {
        if ( indef && dec_.type() == CborBaseDecoder::TYPE_BREAK )
        {
            dec_.readBreak();
            break;
        }
        block_cbor::BlockParameters bp;
        bp.readCbor(dec_, *fields_);
#if ENABLE_PSEUDOANONYMISATION
        if ( pseudo_anon_ )
        {
            bp.collection_parameters.host_id.clear();
            bp.collection_parameters.filter.clear();
            for ( auto& a : bp.collection_parameters.server_addresses )
                a = pseudo_anon_->address(a);
        }
#endif

        if ( first_bp )
        {
            config.set_from_block_parameters(bp);
            generator_id_ = bp.collection_parameters.generator_id;
            host_id_ = bp.collection_parameters.host_id;

            first_bp = false;
        }

        block_parameters_.push_back(bp);
    }
}

bool BlockCborReader::readBlock()
{
    if ( blocks_indef_ )
    {
        if ( dec_.type() == CborBaseDecoder::TYPE_BREAK )
        {
            dec_.readBreak();
            return false;
        }
    }
    else if ( nblocks_-- == 0 )
        return false;

    block_->clear();
    block_->readCbor(dec_, *fields_);

    end_time_ = block_->end_time;

    // Accumulate address events counts.
    for ( auto& aeci : block_->address_event_counts )
    {
        // Check we have all address event info required. If not, ignore this one.
        if ( !aeci.first.address || !aeci.first.type || !aeci.first.code )
            continue;

        IPAddress addr = get_client_address(*aeci.first.address, aeci.first.transport_flags);
        AddressEvent ae(*aeci.first.type, addr, *aeci.first.code);

        if ( address_events_read_.find(ae) != address_events_read_.end() )
            address_events_read_[ae] += aeci.second;
        else
            address_events_read_[ae] = aeci.second;
    }

    next_item_ = 0;
    need_block_ = (block_->query_response_items.size() == next_item_);
    current_block_num_++;
    return true;
}

QueryResponseData BlockCborReader::readQRData(bool& eof)
{
    QueryResponseData res;

    eof = false;
    while ( need_block_ )
        if ( !readBlock() )
        {
            eof = true;
            return res;
        }

    const block_cbor::QueryResponseItem& qri = block_->query_response_items[next_item_];
    need_block_ = (block_->query_response_items.size() == ++next_item_);

    const block_cbor::QueryResponseSignature* sig;
    std::unique_ptr<block_cbor::QueryResponseSignature> empty_sig;

    if ( qri.signature )
        sig = &block_->query_response_signatures[*qri.signature];
    else
    {
        empty_sig = make_unique<block_cbor::QueryResponseSignature>();
        sig = empty_sig.get();
    }

    if ( sig->qr_flags )
        res.qr_flags = block_cbor::convert_qr_flags(*sig->qr_flags, file_format_version_);
    else
        res.qr_flags = synthesise_qr_flags(qri, *sig);

    boost::optional<uint8_t> transport_flags;
    if ( sig->qr_transport_flags )
        transport_flags = block_cbor::convert_transport_flags(*sig->qr_transport_flags, file_format_version_);
    else
        transport_flags = defaults_.transport;

    res.timestamp =
        ( qri.tstamp )
        ? qri.tstamp
        : block_->earliest_time + std::chrono::duration_cast<std::chrono::system_clock::duration>(*defaults_.time_offset);
    if ( !earliest_time_ || *earliest_time_ > res.timestamp )
        earliest_time_ = res.timestamp;
    if ( !latest_time_ || *latest_time_ < res.timestamp )
        latest_time_ = res.timestamp;

    if ( qri.client_address )
        res.client_address = get_client_address(*qri.client_address, transport_flags);
    else
        res.client_address = defaults_.client_address;
    res.client_port = ( qri.client_port ) ? qri.client_port : defaults_.client_port;
    res.hoplimit = ( qri.hoplimit ) ? qri.hoplimit : defaults_.client_hoplimit;
    if ( sig->server_address )
        res.server_address = get_server_address(*sig->server_address, transport_flags);
    else
        res.server_address = defaults_.server_address;
    res.server_port = ( sig->server_port ) ? sig->server_port : defaults_.server_port;
    res.id = ( qri.id ) ? qri.id : defaults_.transaction_id;
    if ( qri.qname )
        res.qname = block_->names_rdatas[*qri.qname].str;
    else
        res.qname = defaults_.query_name;
    res.qr_transport_flags = transport_flags;

    if ( sig->dns_flags )
        res.dns_flags = block_cbor::convert_dns_flags(*sig->dns_flags, file_format_version_);
    else
        res.dns_flags = defaults_.dns_flags;
    if ( sig->query_classtype )
    {
        const block_cbor::ClassType& ct = block_->class_types[*sig->query_classtype];
        res.query_class = ct.qclass;
        res.query_type = ct.qtype;
    }
    else
    {
        res.query_class = defaults_.query_class;
        res.query_type = defaults_.query_type;
    }
    res.query_qdcount = ( sig->qdcount ) ? sig->qdcount : defaults_.query_qdcount;
    res.query_ancount = ( sig->query_ancount ) ? sig->query_ancount : defaults_.query_ancount;
    res.query_arcount = ( sig->query_arcount ) ? sig->query_arcount : defaults_.query_arcount;
    res.query_nscount = ( sig->query_nscount ) ? sig->query_nscount : defaults_.query_nscount;
    res.query_opcode = ( sig->query_opcode ) ? sig->query_opcode : defaults_.query_opcode;
    res.query_rcode = ( sig->query_rcode ) ? sig->query_rcode : defaults_.query_rcode;
    res.query_edns_version = ( sig->query_edns_version ) ? sig->query_edns_version : defaults_.query_edns_version;
    res.query_edns_payload_size = ( sig->query_edns_payload_size ) ? sig->query_edns_payload_size : defaults_.query_udp_size;
    if ( sig->query_opt_rdata )
    {
        res.query_opt_rdata = block_->names_rdatas[*sig->query_opt_rdata].str;
#if ENABLE_PSEUDOANONYMISATION
        if ( pseudo_anon_ )
            res.query_opt_rdata = pseudo_anon_->edns0(block_->names_rdatas[*sig->query_opt_rdata].str);
#endif
    }
    else
        res.query_opt_rdata = defaults_.query_opt_rdata;
    res.query_size = ( qri.query_size ) ? qri.query_size : defaults_.query_size;

    res.response_delay = ( qri.response_delay ) ? qri.response_delay : defaults_.response_delay;
    res.response_rcode = ( sig->response_rcode ) ? sig->response_rcode : defaults_.response_rcode;
    res.response_size = ( qri.response_size ) ? qri.response_size : defaults_.response_size;

    read_extra_info(qri.query_extra_info,
                    res.query_questions, res.query_answers,
                    res.query_authorities, res.query_additionals);
    read_extra_info(qri.response_extra_info,
                    res.response_questions, res.response_answers,
                    res.response_authorities, res.response_additionals);

    return res;
}

void BlockCborReader::read_extra_info(
    const std::unique_ptr<block_cbor::QueryResponseExtraInfo>& extra_info,
    boost::optional<std::vector<QueryResponseData::Question>>& questions,
    boost::optional<std::vector<QueryResponseData::RR>>& answers,
    boost::optional<std::vector<QueryResponseData::RR>>& authorities,
    boost::optional<std::vector<QueryResponseData::RR>>& additionals
    )
{
    if ( !extra_info )
        return;

    if ( extra_info->questions_list )
    {
        std::vector<QueryResponseData::Question> qvec;
        for ( auto& qid : block_->questions_lists[*extra_info->questions_list].vec )
        {
            const block_cbor::Question& q = block_->questions[*qid];
            QueryResponseData::Question newq;

            if ( q.qname )
                newq.qname = block_->names_rdatas[*q.qname].str;
            else
                newq.qname = defaults_.query_name;

            if ( q.classtype )
            {
                const block_cbor::ClassType& ct = block_->class_types[*q.classtype];
                newq.qclass = ct.qclass;
                newq.qtype = ct.qtype;
            }
            else
            {
                newq.qclass = defaults_.query_class;
                newq.qtype = defaults_.query_type;
            }
            qvec.push_back(newq);
        }
        questions = qvec;
    }

    if ( extra_info->answers_list )
        read_rr(extra_info->answers_list, answers);
    if ( extra_info->authority_list )
        read_rr(extra_info->authority_list, authorities);
    if ( extra_info->additional_list )
        read_rr(extra_info->additional_list, additionals);
}

void BlockCborReader::read_rr(block_cbor::index_t index, boost::optional<std::vector<QueryResponseData::RR>>& res)
{
    if ( index )
    {
        std::vector<QueryResponseData::RR> rrvec;
        for ( auto& rrid : block_->rrs_lists[*index].vec )
        {
            const block_cbor::ResourceRecord& rr = block_->resource_records[*rrid];
            QueryResponseData::RR newrr;

            if ( rr.name )
                newrr.name = block_->names_rdatas[*rr.name].str;
            else
                newrr.name = defaults_.query_name;

            if ( rr.classtype )
            {
                const block_cbor::ClassType& ct = block_->class_types[*rr.classtype];
                newrr.rclass = ct.qclass;
                newrr.rtype = ct.qtype;
            }
            else
            {
                newrr.rclass = defaults_.query_class;
                newrr.rtype = defaults_.query_type;
            }

            newrr.ttl = ( rr.ttl ) ? rr.ttl : defaults_.rr_ttl;

            if ( rr.rdata )
                newrr.rdata = block_->names_rdatas[*rr.rdata].str;
            else
                newrr.rdata = defaults_.rr_rdata;

            rrvec.push_back(newrr);
        }
        res = rrvec;
    }
}

IPAddress BlockCborReader::string_to_addr(const byte_string& str, bool is_ipv6)
{
    IPAddress res;
    byte_string b = str;

    // Storing transport flags is optional if full addresses are stored.
    // If the address is more than 4 bytes long, it's definitely IPv6,
    // whatever is_ipv6 may think.
    if ( is_ipv6 || str.size() > 4 )
    {
        if ( str.size() < 16 )
            b.resize(16, 0);
    }
    else
    {
        if ( str.size() < 4 )
            b.resize(4, 0);
    }

    res = IPAddress(b);

#if ENABLE_PSEUDOANONYMISATION
    if ( pseudo_anon_ )
        res = pseudo_anon_->address(res);
#endif

    return res;
}

bool BlockCborReader::is_ipv4_client_full_address(const byte_string& b) const
{
    const block_cbor::BlockParameters& bp = block_parameters_[block_->block_parameters_index];
    const block_cbor::StorageParameters& sp = bp.storage_parameters;

    return ( sp.client_address_prefix_ipv4 == 32 && b.length() == 4 );
}

bool BlockCborReader::is_ipv6_client_full_address(const byte_string& b) const
{
    const block_cbor::BlockParameters& bp = block_parameters_[block_->block_parameters_index];
    const block_cbor::StorageParameters& sp = bp.storage_parameters;

    return ( sp.client_address_prefix_ipv6 == 128 && b.length() == 16 );
}

IPAddress BlockCborReader::get_client_address(std::size_t index, boost::optional<uint8_t> transport_flags)
{
    bool ipv6;
    const byte_string& addr_b = block_->ip_addresses[index].str;

    if ( is_ipv4_client_full_address(addr_b) )
        ipv6 = false;
    else if ( is_ipv6_client_full_address(addr_b) )
        ipv6 = true;
    else
        ipv6 = (*transport_flags & block_cbor::IPV6);

    return string_to_addr(addr_b, ipv6);
}

bool BlockCborReader::is_ipv4_server_full_address(const byte_string& b) const
{
    const block_cbor::BlockParameters& bp = block_parameters_[block_->block_parameters_index];
    const block_cbor::StorageParameters& sp = bp.storage_parameters;

    return ( sp.server_address_prefix_ipv4 == 32 && b.length() == 4 );
}

bool BlockCborReader::is_ipv6_server_full_address(const byte_string& b) const
{
    const block_cbor::BlockParameters& bp = block_parameters_[block_->block_parameters_index];
    const block_cbor::StorageParameters& sp = bp.storage_parameters;

    return ( sp.server_address_prefix_ipv4 == 128 && b.length() == 16 );
}

IPAddress BlockCborReader::get_server_address(std::size_t index, boost::optional<uint8_t> transport_flags)
{
    bool ipv6;
    const byte_string& addr_b = block_->ip_addresses[index].str;

    if ( is_ipv4_server_full_address(addr_b) )
        ipv6 = false;
    else if ( is_ipv6_server_full_address(addr_b) )
        ipv6 = true;
    else
        ipv6 = (*transport_flags & block_cbor::IPV6);

    return string_to_addr(addr_b, ipv6);
}

uint8_t BlockCborReader::synthesise_qr_flags(const block_cbor::QueryResponseItem& qri,
                                             const block_cbor::QueryResponseSignature& sig)
{
    uint8_t res = 0;

    if ( qri.hoplimit ||
         qri.response_delay ||
         sig.query_opcode ||
         sig.query_rcode ||
         sig.qdcount ||
         sig.query_ancount ||
         sig.query_nscount ||
         sig.query_arcount ||
         qri.query_size )
        res |= block_cbor::HAS_QUERY;

    if ( qri.response_delay ||
         sig.response_rcode ||
         qri.response_size )
        res |= block_cbor::HAS_RESPONSE;

    if ( sig.query_edns_version ||
         sig.query_edns_payload_size ||
         sig.query_opt_rdata )
        res |= (block_cbor::HAS_QUERY | block_cbor::QUERY_HAS_OPT);

    if ( sig.dns_flags )
    {
        if ( *sig.dns_flags &
             (block_cbor::QUERY_CD | block_cbor::QUERY_AD |
              block_cbor::QUERY_Z | block_cbor::QUERY_RA |
              block_cbor::QUERY_RD | block_cbor::QUERY_TC |
              block_cbor::QUERY_AA | block_cbor::QUERY_DO) )
            res |= block_cbor::HAS_QUERY;
        if ( *sig.dns_flags &
             (block_cbor::RESPONSE_CD | block_cbor::RESPONSE_AD |
              block_cbor::RESPONSE_Z | block_cbor::RESPONSE_RA |
              block_cbor::RESPONSE_RD | block_cbor::RESPONSE_TC |
              block_cbor::RESPONSE_AA) )
            res |= block_cbor::HAS_RESPONSE;
    }

    if ( !(res & block_cbor::QUERY_HAS_OPT) &&
         qri.query_extra_info &&
         qri.query_extra_info->additional_list )
    {
        for ( const auto& rr : block_->rrs_lists[*(qri.query_extra_info->additional_list)].vec )
        {
            block_cbor::index_t ctindex = block_->resource_records[*rr].classtype;
            if ( ctindex )
            {
                boost::optional<CaptureDNS::QueryType> qt = block_->class_types[*ctindex].qtype;
                if ( qt && *qt == CaptureDNS::OPT )
                {
                    res |= (block_cbor::HAS_QUERY |block_cbor::QUERY_HAS_OPT);
                    break;
                }
            }
        }
    }
    if ( qri.response_extra_info &&
         qri.response_extra_info->additional_list )
    {
        for ( const auto& rr : block_->rrs_lists[*(qri.response_extra_info->additional_list)].vec )
        {
            block_cbor::index_t ctindex = block_->resource_records[*rr].classtype;
            if ( ctindex )
            {
                boost::optional<CaptureDNS::QueryType> qt = block_->class_types[*ctindex].qtype;
                if ( qt && *qt == CaptureDNS::OPT )
                {
                    res |= (block_cbor::HAS_RESPONSE | block_cbor::RESPONSE_HAS_OPT);
                    break;
                }
            }
        }
    }

    // In absence of any indication, default to query only.
    if ( !res )
        res |= block_cbor::HAS_QUERY;

    if ( !qri.qname && !sig.query_classtype )
    {
        const block_cbor::BlockParameters& bp = block_parameters_[block_->block_parameters_index];
        const block_cbor::StorageParameters& sp = bp.storage_parameters;

        if ( !(sp.storage_hints.query_response_hints & block_cbor::QUERY_NAME_INDEX) ||
             !(sp.storage_hints.query_response_signature_hints & block_cbor::QUERY_CLASS_TYPE) )
        {
            if ( res & block_cbor::HAS_QUERY )
                res |= block_cbor::QUERY_HAS_NO_QUESTION;
            if ( res & block_cbor::HAS_RESPONSE )
                res |= block_cbor::RESPONSE_HAS_NO_QUESTION;
        }
    }

    if ( sig.response_rcode && *sig.response_rcode == CaptureDNS::FORMERR )
        res |= block_cbor::RESPONSE_HAS_NO_QUESTION;

    return res;
}

void BlockCborReader::dump_collector(std::ostream& os)
{
    os << "\nCOLLECTOR:"
       << "\n  Collector ID         : " << generator_id_
       << "\n  Collection host ID   : " << host_id_
       << "\n";
}

void BlockCborReader::dump_times(std::ostream& os)
{
    if ( !earliest_time_ && ! latest_time_ && !end_time_ )
        return;

    os << "\nTIMES:\n";

    if ( earliest_time_ )
    {
        os << "  Earliest data        : ";
        output_time_point(os, *earliest_time_);
        os << "\n";
    }
    if ( latest_time_ )
    {
        os << "  Latest data          : ";
        output_time_point(os, *latest_time_);
        os << "\n";
    }
    if ( end_time_ )
    {
        os << "  Collection ended     : ";
        output_time_point(os, *end_time_);
        os << "\n";
    }

    if ( earliest_time_ && latest_time_ )
    {
        os << "  Data range           : ";
        output_duration(os, std::chrono::duration_cast<std::chrono::microseconds>(*latest_time_ - *earliest_time_));
        os << "\n";
    }

    if ( earliest_time_ && end_time_ )
    {
        os << "  File duration        : ";
        output_duration(os, std::chrono::duration_cast<std::chrono::microseconds>(*end_time_ - *earliest_time_));
        os << "\n";
    }
}

void BlockCborReader::dump_address_events(std::ostream& os)
{
    for ( unsigned event_type = AddressEvent::EventType::TCP_RESET;
          event_type <= AddressEvent::EventType::ICMPv6_PACKET_TOO_BIG;
          ++event_type )
    {
        bool ignore_code = false, seen_one = false;
        std::string title;
        switch (event_type)
        {
        case AddressEvent::EventType::TCP_RESET:
            title = "TCP RESETS";
            ignore_code = true;
            break;

        case AddressEvent::EventType::ICMP_TIME_EXCEEDED:
            title = "ICMP TIME EXCEEDED";
            break;

        case AddressEvent::EventType::ICMP_DEST_UNREACHABLE:
            title = "ICMP DEST UNREACHABLE";
            break;

        case AddressEvent::EventType::ICMPv6_TIME_EXCEEDED:
            title = "ICMPv6 TIME EXCEEDED";
            break;

        case AddressEvent::EventType::ICMPv6_DEST_UNREACHABLE:
            title = "ICMPv6 DEST UNREACHABLE";
            break;

        case AddressEvent::EventType::ICMPv6_PACKET_TOO_BIG:
            title = "ICMPv6 PACKET TOO BIG";
            break;
        }

        struct AEInfo
        {
            AEInfo(const AddressEvent& ae, unsigned count)
                : ae_(ae), count_(count) {}

            bool operator<(const AEInfo& rhs) const
            {
                if ( ae_.code() < rhs.ae_.code() )
                    return true;
                else if ( ae_.code() == rhs.ae_.code() )
                {
                    if ( count_ < rhs.count_ )
                        return true;
                    else if ( count_ == rhs.count_ )
                        return ( ae_.address() < rhs.ae_.address() );
                }
                return false;
            }

            AddressEvent ae_;
            unsigned count_;
        };

        std::vector<AEInfo> aeinfo;

        for ( auto& ae : address_events_read_ )
        {
            if ( ae.first.type() == event_type )
                aeinfo.emplace_back(ae.first, ae.second);
        }

        std::sort(aeinfo.begin(), aeinfo.end());

        for ( auto& aei : aeinfo )
        {
            if ( !seen_one )
            {
                os << title << ":\n";
                seen_one = true;
            }

            if ( !ignore_code )
                os << "  Code: " << std::setw(2) << aei.ae_.code();
            os << "  Count: " << std::setw(5) << aei.count_;
            os << "  Address: " << aei.ae_.address() << "\n";
        }

        if ( seen_one )
            os << "\n";
    }
}

std::ostream& operator<<(std::ostream& output, const QueryResponseData& qr)
{
    const char* transport = NULL;
    unsigned count;

    if ( qr.qr_transport_flags )
    {
        switch ((*qr.qr_transport_flags >> 1) & 0xf)
        {
        case 0: transport = "UDP"; break;
        case 1: transport = "TCP"; break;
        case 2: transport = "TLS"; break;
        case 3: transport = "DTLS"; break;
        case 4: transport = "DOH"; break;
        default: transport = "Unknown"; break;
        }
    }

    output << "Query/Response:\n";
    if ( qr.qr_flags & block_cbor::HAS_QUERY )
    {
        output << "Query: ";
        if ( qr.timestamp )
            output_time_point(output, *qr.timestamp);
        if ( qr.client_address )
            output << "\n\tClient IP: " << *qr.client_address;
        if ( qr.server_address )
            output << "\n\tServer IP: " << *qr.server_address;
        if ( transport )
            output << "\n\tTransport: " << transport;
        if ( qr.client_port )
            output << "\n\tClient port: " << *qr.client_port;
        if ( qr.server_port )
            output << "\n\tServer port: " << *qr.server_port;
        if ( qr.hoplimit )
            output << "\n\tHop limit: " << +*qr.hoplimit;
        output << "\n\tDNS QR: Query";
        if ( qr.id )
            output << "\n\tID: " << *qr.id;
        if ( qr.query_opcode )
            output << "\n\tOpcode: " << static_cast<unsigned>(*qr.query_opcode);
        if ( qr.query_rcode )
            output << "\n\tRcode: " << static_cast<unsigned>(*qr.query_rcode);
        if ( qr.dns_flags )
        {
            output << "\n\tFlags: ";
            if ( *qr.dns_flags & block_cbor::QUERY_AA )
                output << "AA ";
            if ( *qr.dns_flags & block_cbor::QUERY_TC )
                output << "TC ";
            if ( *qr.dns_flags & block_cbor::QUERY_RD )
                output << "RD ";
            if ( *qr.dns_flags & block_cbor::QUERY_RA )
                output << "RA ";
            if ( *qr.dns_flags & block_cbor::QUERY_AD )
                output << "AD ";
            if ( *qr.dns_flags & block_cbor::QUERY_CD )
                output << "CD ";
        }
        count = (qr.query_questions) ? (*qr.query_questions).size() : 0;
        if ( !(qr.qr_flags & block_cbor::QUERY_HAS_NO_QUESTION) )
            count += 1;
        output << "\n\tQdCount: " << count;
        count = ( qr.query_answers ) ? (*qr.query_answers).size() : 0;
        output << "\n\tAnCount: " << count;
        count = ( qr.query_authorities ) ? (*qr.query_authorities).size() : 0;
        output << "\n\tNsCount: " << count;
        count = ( qr.query_additionals ) ? (*qr.query_additionals).size() : 0;
        if ( qr.qr_flags & block_cbor::QUERY_HAS_OPT )
            count += 1;
        output << "\n\tArCount: " << count;

        if ( qr.qname )
            output << "\n\tName: " << CaptureDNS::decode_domain_name(*qr.qname);
        if ( qr.query_type )
            output << "\n\tType: " << static_cast<unsigned>(*qr.query_type);
        if ( qr.query_class )
            output << "\n\tClass: " << static_cast<unsigned>(*qr.query_class);

        if ( qr.query_questions )
            for ( const auto& q : *qr.query_questions )
            {
                if ( q.qname )
                    output << "\n\tName: " << CaptureDNS::decode_domain_name(*q.qname);
                if ( q.qtype )
                    output << "\n\tType: " << static_cast<unsigned>(*q.qtype);
                if ( q.qclass )
                    output << "\n\tClass: " << static_cast<unsigned>(*q.qclass);
            }

        output << "\n";
    }
    else
        output << "No Query\n";

    if ( qr.qr_flags & block_cbor::HAS_RESPONSE )
    {
        output << "Response: ";
        if ( qr.timestamp && qr.response_delay )
            output_time_point(output, *qr.timestamp + std::chrono::duration_cast<std::chrono::system_clock::duration>(*qr.response_delay));
        if ( qr.client_address )
            output << "\n\tClient IP: " << *qr.client_address;
        if ( qr.server_address )
            output << "\n\tServer IP: " << *qr.server_address;
        if ( transport )
            output << "\n\tTransport: " << transport;
        if ( qr.client_port )
            output << "\n\tClient port: " << *qr.client_port;
        if ( qr.server_port )
            output << "\n\tServer port: " << *qr.server_port;
        if ( qr.hoplimit )
            output << "\n\tHop limit: 64\n\tDNS QR: Response";
        if ( qr.id )
            output << "\n\tID: " << *qr.id;
        if ( qr.query_opcode )
            output << "\n\tOpcode: " << static_cast<unsigned>(*qr.query_opcode);
        if ( qr.response_rcode )
            output << "\n\tRcode: " << static_cast<unsigned>(*qr.response_rcode);
        if ( qr.dns_flags )
        {
            output << "\n\tFlags: ";
            if ( *qr.dns_flags & block_cbor::RESPONSE_AA )
                output << "AA ";
            if ( *qr.dns_flags & block_cbor::RESPONSE_TC )
                output << "TC ";
            if ( *qr.dns_flags & block_cbor::RESPONSE_RD )
                output << "RD ";
            if ( *qr.dns_flags & block_cbor::RESPONSE_RA )
                output << "RA ";
            if ( *qr.dns_flags & block_cbor::RESPONSE_AD )
                output << "AD ";
            if ( *qr.dns_flags & block_cbor::RESPONSE_CD )
                output << "CD ";
        }
        count = 0;
        if ( !(qr.qr_flags & block_cbor::QUERY_HAS_NO_QUESTION) )
            count = 1;
        if ( qr.response_questions )
            count += (*qr.response_questions).size();
        output << "\n\tQdCount: " << count;
        count = ( qr.response_answers ) ? (*qr.response_answers).size() : 0;
        output << "\n\tAnCount: " << count;
        count = ( qr.response_authorities ) ? (*qr.response_authorities).size() : 0;
        output << "\n\tNsCount: " << count;
        count = ( qr.response_additionals ) ? (*qr.response_additionals).size() : 0;
        output << "\n\tArCount: " << count;

        if ( qr.qname )
            output << "\n\tName: " << CaptureDNS::decode_domain_name(*qr.qname);
        if ( qr.query_type )
            output << "\n\tType: " << static_cast<unsigned>(*qr.query_type);
        if ( qr.query_class )
            output << "\n\tClass: " << static_cast<unsigned>(*qr.query_class);

        if ( qr.response_questions )
            for ( const auto& q : *qr.response_questions )
            {
                if ( q.qname )
                    output << "\n\tName: " << CaptureDNS::decode_domain_name(*q.qname);
                if ( q.qtype )
                    output << "\n\tType: " << static_cast<unsigned>(*q.qtype);
                if ( q.qclass )
                    output << "\n\tClass: " << static_cast<unsigned>(*q.qclass);
            }

        output << "\n";
    }
    else
        output << "No Response\n";

    return output;
}
