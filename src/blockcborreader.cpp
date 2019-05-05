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

BlockCborReader::BlockCborReader(CborBaseDecoder& dec, Configuration &config,
                                 boost::optional<PseudoAnonymise> pseudo_anon)
    : dec_(dec), next_item_(0), need_block_(true),
      block_(config.max_block_qr_items), current_block_num_(0),
      pseudo_anon_(pseudo_anon)
{
    readFileHeader(config);
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
                readFilePreamble(config, false);
            else if ( file_type_id == block_cbor::FILE_FORMAT_02_ID )
                readFilePreamble(config, true);
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

void BlockCborReader::readFilePreamble(Configuration& config, bool old)
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

        block_cbor::FilePreambleField key = block_cbor::file_preamble_field(dec_.read_unsigned(), old);

        if ( !fields_ && key >= block_cbor::FilePreambleField::configuration )
            fields_ = make_unique<block_cbor::FileVersionFields>(major_version, minor_version, private_version);

        switch(key)
        {
        case block_cbor::FilePreambleField::format_version:
            if ( !old )
                throw cbor_file_format_error("Unexpected version item reading header");
            minor_version = dec_.read_unsigned();
            if ( minor_version != block_cbor::FILE_FORMAT_02_VERSION )
                throw cbor_file_format_error("Wrong file format version");
            break;

        case block_cbor::FilePreambleField::major_format_version:
            if ( old )
                throw cbor_file_format_error("Unexpected version item reading header");
            major_version = dec_.read_unsigned();
            break;

        case block_cbor::FilePreambleField::minor_format_version:
            if ( old )
                throw cbor_file_format_error("Unexpected version item reading header");
            minor_version = dec_.read_unsigned();
            break;

        case block_cbor::FilePreambleField::private_version:
            if ( old )
                throw cbor_file_format_error("Unexpected version item reading header");
            private_version = dec_.read_unsigned();
            break;

        case block_cbor::FilePreambleField::configuration:
            readConfiguration(config);
            break;

        case block_cbor::FilePreambleField::generator_id:
            generator_id_ = dec_.read_string();
            break;

        case block_cbor::FilePreambleField::host_id:
            host_id_ = dec_.read_string();
#if ENABLE_PSEUDOANONYMISATION
            if ( pseudo_anon_ )
                host_id_ = "";
#endif
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
            config.query_timeout = dec_.read_unsigned();
            break;

        case block_cbor::ConfigurationField::skew_timeout:
            config.skew_timeout = dec_.read_unsigned();
            break;

        case block_cbor::ConfigurationField::snaplen:
            config.snaplen = dec_.read_unsigned();
            break;

        case block_cbor::ConfigurationField::promisc:
            config.promisc_mode = ( dec_.read_unsigned() != 0 );
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
                config.filter = "";
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
            config.max_block_qr_items = dec_.read_unsigned();
            break;

        default:
            // Unknown item, skip.
            dec_.skip();
            break;
        }
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

    block_.clear();
    block_.readCbor(dec_, *fields_);

#if ENABLE_PSEUDOANONYMISATION
    if ( pseudo_anon_ )
        for ( auto& a : block_.ip_addresses )
            a.addr = pseudo_anon_->address(a.addr);
#endif

    // Accumulate address events counts.
    for ( auto& aeci : block_.address_event_counts )
    {
        IPAddress addr = block_.ip_addresses[aeci.first.address].addr;

        AddressEvent ae(aeci.first.type, addr, aeci.first.code);
        if ( address_events_read_.find(ae) != address_events_read_.end() )
            address_events_read_[ae] += aeci.second;
        else
            address_events_read_[ae] = aeci.second;
    }

    next_item_ = 0;
    need_block_ = (block_.query_response_items.size() == next_item_);
    current_block_num_++;
    return true;
}

std::shared_ptr<QueryResponse> BlockCborReader::readQR()
{
    std::shared_ptr<QueryResponse> res;
    std::unique_ptr<DNSMessage> query, response;

    while ( need_block_ )
        if ( !readBlock() )
            return res;

    const block_cbor::QueryResponseItem& qri = block_.query_response_items[next_item_];
    need_block_ = (block_.query_response_items.size() == ++next_item_);

    const block_cbor::QuerySignature& sig = block_.query_signatures[qri.signature];
    if ( sig.qr_flags & block_cbor::QUERY_ONLY )
    {
        query = make_unique<DNSMessage>();
        query->timestamp = qri.tstamp;
        query->clientIP = block_.ip_addresses[qri.client_address].addr;
        query->serverIP = block_.ip_addresses[sig.server_address].addr;
        query->clientPort = qri.client_port;
        query->serverPort = sig.server_port;
        query->hoplimit = qri.hoplimit;
        query->tcp = sig.transport_flags & BaseOutputWriter::TCP;
        query->dns.type(CaptureDNS::QRType::QUERY);
        query->dns.id(qri.id);
        query->dns.opcode(sig.query_opcode);
        query->dns.rcode(sig.query_rcode);
        query->wire_size = qri.query_size;

        BaseOutputWriter::setDnsFlags(*query, sig.dns_flags, true);

        if ( qri.query_extra_info )
            readExtraInfo(*query, *(qri.query_extra_info));

        if ( sig.qr_flags & block_cbor::QUERY_HAS_OPT )
        {
            byte_string opt_rdata = block_.names_rdatas[sig.query_opt_rdata].str;
#if ENABLE_PSEUDOANONYMISATION
            if ( pseudo_anon_ )
            {
                CaptureDNS::EDNS0 edns0(CaptureDNS::INTERNET,
                                        0,
                                        opt_rdata);
                edns0 = pseudo_anon_->edns0(edns0);
                opt_rdata = edns0.rr().data();
            }
#endif

            uint32_t ttl = ((sig.query_rcode >> 4) &0xff);
            ttl <<= 8;
            ttl |= (sig.query_edns_version & 0xff);
            ttl <<= 16;
            if ( sig.dns_flags & BaseOutputWriter::QUERY_DO )
                ttl |= 0x8000;
            query->dns.add_additional(
                CaptureDNS::resource(
                    "",
                    opt_rdata,
                    CaptureDNS::OPT,
                    static_cast<CaptureDNS::QueryClass>(sig.query_edns_payload_size),
                    ttl));
        }
    }

    if ( sig.qr_flags & block_cbor::RESPONSE_ONLY )
    {
        response = make_unique<DNSMessage>();
        response->timestamp = qri.tstamp + qri.response_delay;
        response->clientIP = block_.ip_addresses[qri.client_address].addr;
        response->serverIP = block_.ip_addresses[sig.server_address].addr;
        response->clientPort = qri.client_port;
        response->serverPort = sig.server_port;
        response->tcp = sig.transport_flags & BaseOutputWriter::TCP;
        response->dns.type(CaptureDNS::QRType::RESPONSE);
        response->dns.id(qri.id);
        response->dns.opcode(sig.query_opcode);
        response->dns.rcode(sig.response_rcode);
        response->wire_size = qri.response_size;

        BaseOutputWriter::setDnsFlags(*response, sig.dns_flags, false);

        if ( qri.response_extra_info )
            readExtraInfo(*response, *(qri.response_extra_info));
    }

    if ( sig.qr_flags & block_cbor::QR_HAS_QUESTION )
    {
        CaptureDNS::query q = makeQuery(qri.qname, sig.query_classtype);
        if ( query )
            query->dns.add_query(q);
        if ( response && !( sig.qr_flags & block_cbor::RESPONSE_HAS_NO_QUESTION ) ) {
            response->dns.add_query(q);
        }
    }

    if ( query )
    {
        res = std::make_shared<QueryResponse>(std::move(query));
        if ( response )
            res->set_response(std::move(response));
    }
    else
    {
        res = std::make_shared<QueryResponse>(std::move(response), false);
    }

    return res;
}

void BlockCborReader::readExtraInfo(DNSMessage& dns, const block_cbor::QueryResponseExtraInfo& extra) const
{
    if ( extra.questions_list )
        for ( auto& q_id : block_.questions_lists[extra.questions_list].vec )
        {
            const block_cbor::Question& q = block_.questions[q_id];
            dns.dns.add_query(makeQuery(q.qname, q.classtype));
        }

    if ( extra.answers_list )
        for ( auto& rr_id : block_.rrs_lists[extra.answers_list].vec )
            dns.dns.add_answer(makeResource(block_.resource_records[rr_id]));

    if ( extra.authority_list )
        for ( auto& rr_id : block_.rrs_lists[extra.authority_list].vec )
            dns.dns.add_authority(makeResource(block_.resource_records[rr_id]));

    if ( extra.additional_list )
        for ( auto& rr_id : block_.rrs_lists[extra.additional_list].vec )
            dns.dns.add_additional(makeResource(block_.resource_records[rr_id]));
}

CaptureDNS::query BlockCborReader::makeQuery(block_cbor::index_t qname_id, block_cbor::index_t class_type_id) const
{
    byte_string qname = block_.names_rdatas[qname_id].str;
    const block_cbor::ClassType& ct = block_.class_types[class_type_id];
    return CaptureDNS::query(qname,
                            static_cast<CaptureDNS::QueryType>(ct.qtype),
                            static_cast<CaptureDNS::QueryClass>(ct.qclass));
}

CaptureDNS::resource BlockCborReader::makeResource(const block_cbor::ResourceRecord& rr) const
{
    byte_string name = block_.names_rdatas[rr.name].str;
    const block_cbor::ClassType& ct = block_.class_types[rr.classtype];
    byte_string rdata = block_.names_rdatas[rr.rdata].str;

    CaptureDNS::resource res(name,
                             rdata,
                             static_cast<CaptureDNS::QueryType>(ct.qtype),
                             static_cast<CaptureDNS::QueryClass>(ct.qclass),
                             rr.ttl);

#if ENABLE_PSEUDOANONYMISATION
    if ( ct.qtype == CaptureDNS::OPT && pseudo_anon_ )
    {
        CaptureDNS::EDNS0 edns0(res);
        edns0 = pseudo_anon_->edns0(edns0);
        res = edns0.rr();
    }
#endif

    return res;
}

void BlockCborReader::dump_collector(std::ostream& os)
{
    os << "\nCOLLECTOR:"
       << "\n  Collector ID         : " << generator_id_
       << "\n  Collection host ID   : " << host_id_
       << "\n";
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
