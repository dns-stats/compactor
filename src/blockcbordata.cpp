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

#include <type_traits>

#include "configuration.hpp"
#include "blockcbordata.hpp"

namespace block_cbor {

    template<typename T, typename D>
    void add_vector_item(std::vector<T>& vec, const D& item, typename std::enable_if<std::is_same<T, D>::value>::type* = 0)
    {
        vec.push_back(item);
    }

    template<typename T, typename D>
    void add_vector_item(std::vector<T>& vec, const D& item, typename std::enable_if<!std::is_same<T, D>::value>::type* = 0)
    {
        vec.push_back(T(item));
    }

    template<typename T, typename D>
    void read_vector(std::vector<T>& vec, CborBaseDecoder& dec, const FileVersionFields&)
    {
        bool indef;
        uint64_t n_elems = dec.readArrayHeader(indef);
        if ( !indef )
            vec.reserve(n_elems);
        while ( indef || n_elems-- > 0 )
        {
            if ( indef && dec.type() == CborBaseDecoder::TYPE_BREAK )
            {
                dec.readBreak();
                break;
            }
            D item;
            dec.read(item);
            add_vector_item<T, D>(vec, item);
        }
    }

    template<typename T>
    void write_vector(const std::vector<T>& vec, CborBaseEncoder& enc)
    {
        enc.writeArrayHeader(vec.size());
        for ( auto& i : vec )
            enc.write(i);
    }

    void Timestamp::readCbor(CborBaseDecoder& dec)
    {
        try
        {
            bool indef;
            unsigned item = 0;
            uint64_t n_elems = dec.readArrayHeader(indef);
            while ( indef || n_elems-- > 0 )
            {
                if ( indef && dec.type() == CborBaseDecoder::TYPE_BREAK )
                {
                    dec.readBreak();
                    break;
                }

                switch(item++)
                {
                case 0:
                    secs = dec.read_unsigned();
                    break;

                case 1:
                    ticks = dec.read_unsigned();
                    break;

                default:
                    throw cbor_file_format_unexpected_item_error("Timestamp");
                    break;
                }
            }
        }
        catch (const std::logic_error& e)
        {
            throw cbor_file_format_unexpected_item_error("Timestamp");
        }
    }

    void Timestamp::writeCbor(CborBaseEncoder& enc)
    {
        enc.writeArrayHeader(2);
        enc.write(secs);
        enc.write(ticks);
    }

    void Timestamp::setFromTimePoint(const std::chrono::system_clock::time_point& t,
                                     uint64_t ticks_per_second)
    {
        std::chrono::seconds s(std::chrono::duration_cast<std::chrono::seconds>(t.time_since_epoch()));
        std::chrono::nanoseconds ns(std::chrono::duration_cast<std::chrono::nanoseconds>(t.time_since_epoch()));

        secs = s.count();
        ticks = (ns.count() % 1000000000) * ticks_per_second / 1000000000;
    }

    std::chrono::system_clock::time_point Timestamp::getTimePoint(uint64_t ticks_per_second)
    {
        std::chrono::seconds s(secs);
        std::chrono::nanoseconds ns(ticks * 1000000000 / ticks_per_second);
        return std::chrono::system_clock::time_point(s + ns);
    }

    void StorageHints::readCbor(CborBaseDecoder& dec, const FileVersionFields& fields)
    {
        try
        {
            bool indef;
            uint64_t n_elems = dec.readMapHeader(indef);
            while ( indef || n_elems-- > 0 )
            {
                if ( indef && dec.type() == CborBaseDecoder::TYPE_BREAK )
                {
                    dec.readBreak();
                    break;
                }

                switch(fields.storage_hints_field(dec.read_unsigned()))
                {
                case StorageHintsField::query_response_hints:
                    query_response_hints = QueryResponseHintFlags(dec.read_unsigned());
                    break;

                case StorageHintsField::query_response_signature_hints:
                    query_response_signature_hints = QueryResponseSignatureHintFlags(dec.read_unsigned());
                    break;

                case StorageHintsField::rr_hints:
                    rr_hints = RRHintFlags(dec.read_unsigned());
                    break;

                case StorageHintsField::other_data_hints:
                    other_data_hints = OtherDataHintFlags(dec.read_unsigned());
                    break;

                default:
                    // Unknown item, skip.
                    dec.skip();
                    break;
                }
            }
        }
        catch (const std::logic_error& e)
        {
            throw cbor_file_format_unexpected_item_error("StorageHints");
        }
    }

    void StorageHints::writeCbor(CborBaseEncoder& enc)
    {
        constexpr int query_response_hints_index = find_storage_hints_index(StorageHintsField::query_response_hints);
        constexpr int query_response_signature_hints_index = find_storage_hints_index(StorageHintsField::query_response_signature_hints);
        constexpr int rr_hints_index = find_storage_hints_index(StorageHintsField::rr_hints);
        constexpr int other_data_hints_index = find_storage_hints_index(StorageHintsField::other_data_hints);

        enc.writeMapHeader(4);
        enc.write(query_response_hints_index);
        enc.write(query_response_hints);
        enc.write(query_response_signature_hints_index);
        enc.write(query_response_signature_hints);
        enc.write(rr_hints_index);
        enc.write(rr_hints);
        enc.write(other_data_hints_index);
        enc.write(other_data_hints);
    }

    void StorageParameters::readCbor(CborBaseDecoder& dec, const FileVersionFields& fields)
    {
        try
        {
            bool indef;
            uint64_t n_elems = dec.readMapHeader(indef);
            while ( indef || n_elems-- > 0 )
            {
                if ( indef && dec.type() == CborBaseDecoder::TYPE_BREAK )
                {
                    dec.readBreak();
                    break;
                }

                switch(fields.storage_parameters_field(dec.read_unsigned()))
                {
                case StorageParametersField::ticks_per_second:
                    ticks_per_second = dec.read_unsigned();
                    break;

                case StorageParametersField::max_block_items:
                    max_block_items = dec.read_unsigned();
                    break;

                case StorageParametersField::storage_hints:
                    storage_hints.readCbor(dec, fields);
                    break;

                case StorageParametersField::opcodes:
                    read_vector<unsigned, unsigned>(opcodes, dec, fields);
                    break;

                case StorageParametersField::rr_types:
                    read_vector<unsigned, unsigned>(rr_types, dec, fields);
                    break;

                case StorageParametersField::storage_flags:
                    storage_flags = StorageFlags(dec.read_unsigned());
                    break;

                case StorageParametersField::client_address_prefix_ipv4:
                    client_address_prefix_ipv4 = dec.read_unsigned();
                    break;

                case StorageParametersField::client_address_prefix_ipv6:
                    client_address_prefix_ipv6 = dec.read_unsigned();
                    break;

                case StorageParametersField::server_address_prefix_ipv4:
                    server_address_prefix_ipv4 = dec.read_unsigned();
                    break;

                case StorageParametersField::server_address_prefix_ipv6:
                    server_address_prefix_ipv6 = dec.read_unsigned();
                    break;

                case StorageParametersField::sampling_method:
                    sampling_method = dec.read_string();
                    break;

                case StorageParametersField::anonymisation_method:
                    anonymisation_method = dec.read_string();
                    break;

                default:
                    // Unknown item, skip.
                    dec.skip();
                    break;
                }
            }
        }
        catch (const std::logic_error& e)
        {
            throw cbor_file_format_unexpected_item_error("StorageParameters");
        }
    }

    void StorageParameters::writeCbor(CborBaseEncoder& enc)
    {
        constexpr int ticks_per_second_index = find_storage_parameters_index(StorageParametersField::ticks_per_second);
        constexpr int max_block_items_index = find_storage_parameters_index(StorageParametersField::max_block_items);
        constexpr int storage_hints_index = find_storage_parameters_index(StorageParametersField::storage_hints);
        constexpr int opcodes_index = find_storage_parameters_index(StorageParametersField::opcodes);
        constexpr int rr_types_index = find_storage_parameters_index(StorageParametersField::rr_types);
        constexpr int storage_flags_index = find_storage_parameters_index(StorageParametersField::storage_flags);
        constexpr int client_address_prefix_ipv4_index = find_storage_parameters_index(StorageParametersField::client_address_prefix_ipv4);
        constexpr int client_address_prefix_ipv6_index = find_storage_parameters_index(StorageParametersField::client_address_prefix_ipv6);
        constexpr int server_address_prefix_ipv4_index = find_storage_parameters_index(StorageParametersField::server_address_prefix_ipv4);
        constexpr int server_address_prefix_ipv6_index = find_storage_parameters_index(StorageParametersField::server_address_prefix_ipv6);
        constexpr int sampling_method_index = find_storage_parameters_index(StorageParametersField::sampling_method);
        constexpr int anonymisation_method_index = find_storage_parameters_index(StorageParametersField::anonymisation_method);

        enc.writeMapHeader();
        enc.write(ticks_per_second_index);
        enc.write(ticks_per_second);
        enc.write(max_block_items_index);
        enc.write(max_block_items);
        enc.write(storage_hints_index);
        storage_hints.writeCbor(enc);
        enc.write(opcodes_index);
        write_vector(opcodes, enc);
        enc.write(rr_types_index);
        write_vector(rr_types, enc);
        if ( storage_flags )
        {
            enc.write(storage_flags_index);
            enc.write(storage_flags);
        }
        if ( client_address_prefix_ipv4 != DEFAULT_IPV4_PREFIX_LENGTH )
        {
            enc.write(client_address_prefix_ipv4_index);
            enc.write(client_address_prefix_ipv4);
        }
        if ( client_address_prefix_ipv6 != DEFAULT_IPV6_PREFIX_LENGTH )
        {
            enc.write(client_address_prefix_ipv6_index);
            enc.write(client_address_prefix_ipv6);
        }
        if ( server_address_prefix_ipv4 != DEFAULT_IPV4_PREFIX_LENGTH )
        {
            enc.write(server_address_prefix_ipv4_index);
            enc.write(server_address_prefix_ipv4);
        }
        if ( server_address_prefix_ipv6 != DEFAULT_IPV6_PREFIX_LENGTH )
        {
            enc.write(server_address_prefix_ipv6_index);
            enc.write(server_address_prefix_ipv6);
        }
        if ( !sampling_method.empty() )
        {
            enc.write(sampling_method_index);
            enc.write(sampling_method);
        }
        if ( !anonymisation_method.empty() )
        {
            enc.write(anonymisation_method_index);
            enc.write(anonymisation_method);
        }
        enc.writeBreak();
    }

    void CollectionParameters::readCbor(CborBaseDecoder& dec, const FileVersionFields& fields)
    {
        try
        {
            bool indef;
            uint64_t n_elems = dec.readMapHeader(indef);
            while ( indef || n_elems-- > 0 )
            {
                if ( indef && dec.type() == CborBaseDecoder::TYPE_BREAK )
                {
                    dec.readBreak();
                    break;
                }

                switch(fields.collection_parameters_field(dec.read_unsigned()))
                {
                case CollectionParametersField::query_timeout:
                    query_timeout = dec.read_unsigned();
                    break;

                case CollectionParametersField::skew_timeout:
                    skew_timeout = dec.read_unsigned();
                    break;

                case CollectionParametersField::snaplen:
                    snaplen = dec.read_unsigned();
                    break;

                case CollectionParametersField::promisc:
                    promisc = dec.read_bool();
                    break;

                case CollectionParametersField::interfaces:
                    read_vector<std::string, std::string>(interfaces, dec, fields);
                    break;

                case CollectionParametersField::server_addresses:
                    read_vector<IPAddress, byte_string>(server_addresses, dec, fields);
                    break;

                case CollectionParametersField::vlan_ids:
                    read_vector<unsigned, unsigned>(vlan_ids, dec, fields);
                    break;

                case CollectionParametersField::filter:
                    filter = dec.read_string();
                    break;

                case CollectionParametersField::generator_id:
                    generator_id = dec.read_string();
                    break;

                case CollectionParametersField::host_id:
                    host_id = dec.read_string();
                    break;

                default:
                    // Unknown item, skip.
                    dec.skip();
                    break;
                }
            }
        }
        catch (const std::logic_error& e)
        {
            throw cbor_file_format_unexpected_item_error("CollectionParameters");
        }
    }

    void CollectionParameters::writeCbor(CborBaseEncoder& enc)
    {
        constexpr int query_timeout_index = find_collection_parameters_index(CollectionParametersField::query_timeout);
        constexpr int skew_timeout_index = find_collection_parameters_index(CollectionParametersField::skew_timeout);
        constexpr int snaplen_index = find_collection_parameters_index(CollectionParametersField::snaplen);
        constexpr int promisc_index = find_collection_parameters_index(CollectionParametersField::promisc);
        constexpr int interfaces_index = find_collection_parameters_index(CollectionParametersField::interfaces);
        constexpr int server_addresses_index = find_collection_parameters_index(CollectionParametersField::server_addresses);
        constexpr int vlan_ids_index = find_collection_parameters_index(CollectionParametersField::vlan_ids);
        constexpr int filter_index = find_collection_parameters_index(CollectionParametersField::filter);
        constexpr int generator_id_index = find_collection_parameters_index(CollectionParametersField::generator_id);
        constexpr int host_id_index = find_collection_parameters_index(CollectionParametersField::host_id);

        enc.writeMapHeader();
        enc.write(query_timeout_index);
        enc.write(query_timeout);
        enc.write(skew_timeout_index);
        enc.write(skew_timeout);
        enc.write(snaplen_index);
        enc.write(snaplen);
        enc.write(promisc_index);
        enc.write(promisc);
        if ( !interfaces.empty() )
        {
            enc.write(interfaces_index);
            write_vector(interfaces, enc);
        }
        if ( !server_addresses.empty() )
        {
            enc.write(server_addresses_index);
            enc.writeArrayHeader(server_addresses.size());
            for ( auto& i : server_addresses )
                enc.write(i.asNetworkBinary());
        }
        if ( !vlan_ids.empty() )
        {
            enc.write(vlan_ids_index);
            write_vector(vlan_ids, enc);
        }
        if ( !filter.empty() )
        {
            enc.write(filter_index);
            enc.write(filter);
        }
        if ( !generator_id.empty() )
        {
            enc.write(generator_id_index);
            enc.write(generator_id);
        }
        if ( !host_id.empty() )
        {
            enc.write(host_id_index);
            enc.write(host_id);
        }
        enc.writeBreak();
    }

    void BlockParameters::readCbor(CborBaseDecoder& dec, const FileVersionFields& fields)
    {
        try
        {
            bool indef;
            uint64_t n_elems = dec.readMapHeader(indef);
            while ( indef || n_elems-- > 0 )
            {
                if ( indef && dec.type() == CborBaseDecoder::TYPE_BREAK )
                {
                    dec.readBreak();
                    break;
                }

                switch(fields.block_parameters_field(dec.read_unsigned()))
                {
                case BlockParametersField::storage_parameters:
                    storage_parameters.readCbor(dec, fields);
                    break;

                case BlockParametersField::collection_parameters:
                    collection_parameters.readCbor(dec, fields);
                    break;

                default:
                    // Unknown item, skip.
                    dec.skip();
                    break;
                }
            }
        }
        catch (const std::logic_error& e)
        {
            throw cbor_file_format_unexpected_item_error("BlockParameters");
        }
    }

    void BlockParameters::writeCbor(CborBaseEncoder& enc)
    {
        constexpr int storage_parameters_index = find_block_parameters_index(BlockParametersField::storage_parameters);
        constexpr int collection_parameters_index = find_block_parameters_index(BlockParametersField::collection_parameters);

        enc.writeMapHeader(2);
        enc.write(storage_parameters_index);
        storage_parameters.writeCbor(enc);
        enc.write(collection_parameters_index);
        collection_parameters.writeCbor(enc);
    }

    void IndexVectorItem::readCbor(CborBaseDecoder& dec,
                                   const FileVersionFields& fields,
                                   const Defaults& defaults)
    {
        try
        {
            read_vector<index_t, index_t>(vec, dec, fields);
        }
        catch (const std::logic_error& e)
        {
            throw cbor_file_format_unexpected_item_error("IndexVectorItem");
        }
    }

    void IndexVectorItem::writeCbor(CborBaseEncoder& enc, const HintsExcluded&)
    {
        write_vector(vec, enc);
    }

    void ByteStringItem::readCbor(CborBaseDecoder& dec,
                                  const FileVersionFields&,
                                  const Defaults&)
    {
        try
        {
            str = dec.read_binary();
        }
        catch (const std::logic_error& e)
        {
            throw cbor_file_format_unexpected_item_error("binary string");
        }
    }

    void ByteStringItem::writeCbor(CborBaseEncoder& enc, const HintsExcluded&)
    {
        enc.write(str);
    }

    void ClassType::readCbor(CborBaseDecoder& dec,
                             const FileVersionFields& fields,
                             const Defaults& defaults)
    {
        qtype = defaults.query_type;
        qclass = defaults.query_class;

        try
        {
            bool indef;
            uint64_t n_elems = dec.readMapHeader(indef);
            while ( indef || n_elems-- > 0 )
            {
                if ( indef && dec.type() == CborBaseDecoder::TYPE_BREAK )
                {
                    dec.readBreak();
                    break;
                }

                switch(fields.class_type_field(dec.read_unsigned()))
                {
                case ClassTypeField::type_id:
                    qtype = CaptureDNS::QueryType(dec.read_unsigned());
                    break;

                case ClassTypeField::class_id:
                    qclass = CaptureDNS::QueryClass(dec.read_unsigned());
                    break;

                default:
                    // Unknown item, skip.
                    dec.skip();
                    break;
                }
            }
        }
        catch (const std::logic_error& e)
        {
            throw cbor_file_format_unexpected_item_error("ClassType");
        }
    }

    void ClassType::writeCbor(CborBaseEncoder& enc, const HintsExcluded&)
    {
        constexpr int type_index = find_class_type_index(ClassTypeField::type_id);
        constexpr int class_index = find_class_type_index(ClassTypeField::class_id);

        enc.writeMapHeader(2);
        enc.write(type_index);
        enc.write(qtype);
        enc.write(class_index);
        enc.write(qclass);
    }

    std::size_t hash_value(const ClassType &ct)
    {
        std::size_t seed = boost::hash_value(ct.qclass);
        boost::hash_combine(seed, ct.qtype);
        return seed;
    }

    void Question::readCbor(CborBaseDecoder& dec,
                            const FileVersionFields& fields,
                            const Defaults& defaults)
    {
        qname = classtype = boost::none;

        try
        {
            bool indef;
            uint64_t n_elems = dec.readMapHeader(indef);
            while ( indef || n_elems-- > 0 )
            {
                if ( indef && dec.type() == CborBaseDecoder::TYPE_BREAK )
                {
                    dec.readBreak();
                    break;
                }

                switch(fields.question_field(dec.read_unsigned()))
                {
                case QuestionField::name_index:
                    qname = dec.read_unsigned();
                    break;

                case QuestionField::classtype_index:
                    classtype = dec.read_unsigned();
                    break;

                default:
                    // Unknown item, skip.
                    dec.skip();
                    break;
                }
            }
        }
        catch (const std::logic_error& e)
        {
            throw cbor_file_format_unexpected_item_error("Question");
        }
    }

    void Question::writeCbor(CborBaseEncoder& enc, const HintsExcluded&)
    {
        constexpr int qname_index = find_question_index(QuestionField::name_index);
        constexpr int classtype_index = find_question_index(QuestionField::classtype_index);

        int nitems = !!qname + !!classtype;
        enc.writeMapHeader(nitems);
        enc.write(qname_index, qname);
        enc.write(classtype_index, classtype);
    }

    std::size_t hash_value(const Question& q)
    {
        std::size_t seed = boost::hash_value(q.qname);
        boost::hash_combine(seed, q.classtype);
        return seed;
    }

    void ResourceRecord::readCbor(CborBaseDecoder& dec,
                                  const FileVersionFields& fields,
                                  const Defaults& defaults)
    {
        name = classtype = rdata = boost::none;
        ttl = defaults.rr_ttl;

        try
        {
            bool indef;
            uint64_t n_elems = dec.readMapHeader(indef);
            while ( indef || n_elems-- > 0 )
            {
                if ( indef && dec.type() == CborBaseDecoder::TYPE_BREAK )
                {
                    dec.readBreak();
                    break;
                }

                switch(fields.rr_field(dec.read_unsigned()))
                {
                case RRField::name_index:
                    name = dec.read_unsigned();
                    break;

                case RRField::classtype_index:
                    classtype = dec.read_unsigned();
                    break;

                case RRField::ttl:
                    ttl = dec.read_unsigned();
                    break;

                case RRField::rdata_index:
                    rdata = dec.read_unsigned();
                    break;

                default:
                    // Unknown item, skip.
                    dec.skip();
                    break;
                }
            }
        }
        catch (const std::logic_error& e)
        {
            throw cbor_file_format_unexpected_item_error("ResourceRecord");
        }
    }

    void ResourceRecord::writeCbor(CborBaseEncoder& enc, const HintsExcluded&)
    {
        constexpr int name_index = find_rr_index(RRField::name_index);
        constexpr int classtype_index = find_rr_index(RRField::classtype_index);
        constexpr int ttl_index = find_rr_index(RRField::ttl);
        constexpr int rdata_index = find_rr_index(RRField::rdata_index);

        int nitems = !!name + !!classtype + !!ttl + !!rdata;

        enc.writeMapHeader(nitems);
        enc.write(name_index, name);
        enc.write(classtype_index, classtype);
        enc.write(ttl_index, ttl);
        enc.write(rdata_index, rdata);
    }

    std::size_t hash_value(const ResourceRecord& rr)
    {
        std::size_t seed = boost::hash_value(rr.name);
        boost::hash_combine(seed, rr.classtype);
        boost::hash_combine(seed, rr.ttl);
        boost::hash_combine(seed, rr.rdata);
        return seed;
    }

    void QueryResponseSignature::readCbor(CborBaseDecoder& dec,
                                          const FileVersionFields& fields,
                                          const Defaults& defaults)
    {
        bool got_qr_sig_flags = false;

        server_address = query_opt_rdata = query_classtype = boost::none;
        server_port = defaults.server_port;
        qr_transport_flags = defaults.transport;
        query_rcode = defaults.query_rcode;
        response_rcode = defaults.response_rcode;
        query_opcode = defaults.query_opcode;
        query_edns_version = defaults.query_edns_version;
        query_edns_payload_size = defaults.query_udp_size;
        dns_flags = defaults.dns_flags;
        qdcount = defaults.query_qdcount;
        query_ancount = defaults.query_ancount;
        query_arcount = defaults.query_arcount;
        query_nscount = defaults.query_nscount;

        try
        {
            bool indef;
            uint64_t n_elems = dec.readMapHeader(indef);
            while ( indef || n_elems-- > 0 )
            {
                if ( indef && dec.type() == CborBaseDecoder::TYPE_BREAK )
                {
                    dec.readBreak();
                    break;
                }

                switch(fields.query_response_signature_field(dec.read_unsigned()))
                {
                case QueryResponseSignatureField::server_address_index:
                    server_address = dec.read_unsigned();
                    break;

                case QueryResponseSignatureField::server_port:
                    server_port = dec.read_unsigned();
                    break;

                case QueryResponseSignatureField::qr_transport_flags:
                    qr_transport_flags = dec.read_unsigned();
                    break;

                case QueryResponseSignatureField::qr_dns_flags:
                    dns_flags = dec.read_unsigned();
                    break;

                case QueryResponseSignatureField::qr_sig_flags:
                    qr_flags = dec.read_unsigned();
                    got_qr_sig_flags = true;
                    break;

                case QueryResponseSignatureField::query_qd_count:
                    qdcount = dec.read_unsigned();
                    break;

                case QueryResponseSignatureField::query_classtype_index:
                    query_classtype = dec.read_unsigned();
                    break;

                case QueryResponseSignatureField::query_rcode:
                    query_rcode = dec.read_unsigned();
                    break;

                case QueryResponseSignatureField::query_opcode:
                    query_opcode = CaptureDNS::Opcode(dec.read_unsigned());
                    break;

                case QueryResponseSignatureField::query_an_count:
                    query_ancount = dec.read_unsigned();
                    break;

                case QueryResponseSignatureField::query_ar_count:
                    query_arcount = dec.read_unsigned();
                    break;

                case QueryResponseSignatureField::query_ns_count:
                    query_nscount = dec.read_unsigned();
                    break;

                case QueryResponseSignatureField::edns_version:
                    query_edns_version = dec.read_unsigned();
                    break;

                case QueryResponseSignatureField::udp_buf_size:
                    query_edns_payload_size = dec.read_unsigned();
                    break;

                case QueryResponseSignatureField::opt_rdata_index:
                    query_opt_rdata = dec.read_unsigned();
                    break;

                case QueryResponseSignatureField::response_rcode:
                    response_rcode = dec.read_unsigned();
                    break;

                default:
                    // Unknown item, skip.
                    dec.skip();
                    break;
                }
            }
        }
        catch (const std::logic_error& e)
        {
            throw cbor_file_format_unexpected_item_error("QueryResponseSignature");
        }

        if ( !got_qr_sig_flags )
            throw cbor_file_format_error("QueryResponseSignature missing qr-sig_flags");
    }

    void QueryResponseSignature::writeCbor(CborBaseEncoder& enc, const HintsExcluded&)
    {
        constexpr int server_address_index = find_query_response_signature_index(QueryResponseSignatureField::server_address_index);
        constexpr int server_port_index = find_query_response_signature_index(QueryResponseSignatureField::server_port);
        constexpr int qr_transport_flags_index = find_query_response_signature_index(QueryResponseSignatureField::qr_transport_flags);
        constexpr int qr_sig_flags_index = find_query_response_signature_index(QueryResponseSignatureField::qr_sig_flags);
        constexpr int query_opcode_index = find_query_response_signature_index(QueryResponseSignatureField::query_opcode);
        constexpr int qr_dns_flags_index = find_query_response_signature_index(QueryResponseSignatureField::qr_dns_flags);
        constexpr int query_rcode_index = find_query_response_signature_index(QueryResponseSignatureField::query_rcode);
        constexpr int query_classtype_index = find_query_response_signature_index(QueryResponseSignatureField::query_classtype_index);
        constexpr int query_qd_index = find_query_response_signature_index(QueryResponseSignatureField::query_qd_count);
        constexpr int query_an_index = find_query_response_signature_index(QueryResponseSignatureField::query_an_count);
        constexpr int query_ar_index = find_query_response_signature_index(QueryResponseSignatureField::query_ar_count);
        constexpr int query_ns_index = find_query_response_signature_index(QueryResponseSignatureField::query_ns_count);
        constexpr int edns_version_index = find_query_response_signature_index(QueryResponseSignatureField::edns_version);
        constexpr int udp_buf_size_index = find_query_response_signature_index(QueryResponseSignatureField::udp_buf_size);
        constexpr int opt_rdata_index = find_query_response_signature_index(QueryResponseSignatureField::opt_rdata_index);
        constexpr int response_rcode_index = find_query_response_signature_index(QueryResponseSignatureField::response_rcode);

        int nitems =
            !!server_address + !!server_port + !!qr_transport_flags +
            !!dns_flags + 1 + !!qdcount + !!query_classtype + !!query_rcode +
            !!query_opcode + !!query_ancount + !!query_arcount +
            !!query_nscount + !!query_edns_version + !!query_edns_payload_size +
            !!query_opt_rdata + !!response_rcode;

        enc.writeMapHeader(nitems);
        enc.write(server_address_index, server_address);
        enc.write(server_port_index, server_port);
        enc.write(qr_transport_flags_index, qr_transport_flags);
        enc.write(qr_dns_flags_index, dns_flags);
        enc.write(qr_sig_flags_index, qr_flags);
        enc.write(query_qd_index, qdcount);
        enc.write(query_classtype_index, query_classtype);
        enc.write(query_rcode_index, query_rcode);
        enc.write(query_opcode_index, query_opcode);
        enc.write(query_an_index, query_ancount);
        enc.write(query_ar_index, query_arcount);
        enc.write(query_ns_index, query_nscount);
        enc.write(edns_version_index, query_edns_version);
        enc.write(udp_buf_size_index, query_edns_payload_size);
        enc.write(opt_rdata_index, query_opt_rdata);
        enc.write(response_rcode_index, response_rcode);
    }

    std::size_t hash_value(const QueryResponseSignature& qs)
    {
        std::size_t seed = boost::hash_value(qs.server_address);
        boost::hash_combine(seed, qs.server_port);
        boost::hash_combine(seed, qs.qr_transport_flags);
        boost::hash_combine(seed, qs.dns_flags);
        boost::hash_combine(seed, qs.qr_flags);
        boost::hash_combine(seed, qs.qdcount);
        if ( qs.qr_flags & QR_HAS_QUESTION )
            boost::hash_combine(seed, qs.query_classtype);
        if ( qs.qr_flags & QUERY_ONLY )
        {
            boost::hash_combine(seed, qs.query_rcode);
            boost::hash_combine(seed, qs.query_opcode);
            boost::hash_combine(seed, qs.query_ancount);
            boost::hash_combine(seed, qs.query_nscount);
            boost::hash_combine(seed, qs.query_arcount);
        }
        if ( qs.qr_flags & RESPONSE_ONLY )
            boost::hash_combine(seed, qs.response_rcode);
        if ( qs.qr_flags & QUERY_HAS_OPT )
        {
            boost::hash_combine(seed, qs.query_edns_version);
            boost::hash_combine(seed, qs.query_edns_payload_size);
            boost::hash_combine(seed, qs.query_opt_rdata);
        }
        return seed;
    }

    namespace {
        /**
         * \brief Read a `QueryResponseExtraInfo` from CBOR.
         *
         * \param dec    CBOR stream to read from.
         * \param fields translate map keys to internal values.
         * \throws cbor_file_format_error on unexpected CBOR content.
         * \throws cbor_decode_error on malformed CBOR items.
         * \throws cbor_end_of_input on end of CBOR file.
         */
        std::unique_ptr<QueryResponseExtraInfo> readExtraInfo(CborBaseDecoder& dec, const FileVersionFields& fields)
        {
            std::unique_ptr<QueryResponseExtraInfo> res = make_unique<QueryResponseExtraInfo>();
            res->questions_list = res->answers_list =
                res->authority_list = res->additional_list = boost::none;

            bool indef;
            uint64_t n_elems = dec.readMapHeader(indef);
            while ( indef || n_elems-- > 0 )
            {
                if ( indef && dec.type() == CborBaseDecoder::TYPE_BREAK )
                {
                    dec.readBreak();
                    break;
                }

                switch(fields.query_response_extended_field(dec.read_unsigned()))
                {
                case QueryResponseExtendedField::question_index:
                    res->questions_list = dec.read_unsigned();
                    break;

                case QueryResponseExtendedField::answer_index:
                    res->answers_list = dec.read_unsigned();
                    break;

                case QueryResponseExtendedField::authority_index:
                    res->authority_list = dec.read_unsigned();
                    break;

                case QueryResponseExtendedField::additional_index:
                    res->additional_list = dec.read_unsigned();
                    break;

                default:
                    dec.skip();
                    break;
                }
            }
            return res;
        }

        /**
         * \brief Write `QueryResponseExtraInfo` contents to CBOR.
         *
         * \param enc CBOR stream to write to.
         * \param id  the CBOR item identifier.
         * \param ei  the extra info to write.
         */
        void writeExtraInfo(CborBaseEncoder& enc, int id,
                            const QueryResponseExtraInfo& ei)
        {
            constexpr int questions_index = find_query_response_extended_index(QueryResponseExtendedField::question_index);
            constexpr int answer_index = find_query_response_extended_index(QueryResponseExtendedField::answer_index);
            constexpr int authority_index = find_query_response_extended_index(QueryResponseExtendedField::authority_index);
            constexpr int additional_index = find_query_response_extended_index(QueryResponseExtendedField::additional_index);

            enc.write(id);
            enc.writeMapHeader();
            if ( ei.questions_list )
            {
                enc.write(questions_index);
                enc.write(*ei.questions_list);
            }
            if ( ei.answers_list )
            {
                enc.write(answer_index);
                enc.write(*ei.answers_list);
            }
            if ( ei.authority_list )
            {
                enc.write(authority_index);
                enc.write(*ei.authority_list);
            }
            if ( ei.additional_list )
            {
                enc.write(additional_index);
                enc.write(*ei.additional_list);
            }
            enc.writeBreak();
        }
    }

    void QueryResponseItem::clear()
    {
        qr_flags = 0;
        client_address = qname = signature = boost::none;
        client_port = id = boost::none;
        hoplimit = boost::none;
        tstamp = boost::none;
        response_delay = boost::none;
        query_size = response_size = boost::none;
        query_extra_info.release();
        response_extra_info.release();
    }

    void QueryResponseItem::readCbor(CborBaseDecoder& dec,
                                     const std::chrono::system_clock::time_point& earliest_time,
                                     const BlockParameters& block_parameters,
                                     const FileVersionFields& fields,
                                     const Defaults& defaults)
    {
        try
        {
            client_address = qname = signature = boost::none;
            client_port = defaults.client_port;
            hoplimit = defaults.client_hoplimit;
            id = defaults.transaction_id;
            if ( defaults.time_offset )
                tstamp = earliest_time + *defaults.time_offset;
            response_delay = defaults.response_delay;
            query_size = defaults.query_size;
            response_size = defaults.response_size;

            bool indef;
            uint64_t n_elems = dec.readMapHeader(indef);
            while ( indef || n_elems-- > 0 )
            {
                if ( indef && dec.type() == CborBaseDecoder::TYPE_BREAK )
                {
                    dec.readBreak();
                    break;
                }

                switch(fields.query_response_field(dec.read_unsigned()))
                {
                case QueryResponseField::time_offset:
                    tstamp = earliest_time + std::chrono::microseconds(dec.read_signed() * 1000000 / block_parameters.storage_parameters.ticks_per_second);
                    break;

                case QueryResponseField::client_address_index:
                    client_address = dec.read_unsigned();
                    break;

                case QueryResponseField::client_port:
                    client_port = dec.read_unsigned();
                    break;

                case QueryResponseField::transaction_id:
                    id = dec.read_unsigned();
                    break;

                case QueryResponseField::qr_signature_index:
                    signature = dec.read_unsigned();
                    break;

                case QueryResponseField::client_hoplimit:
                    hoplimit = dec.read_unsigned();
                    break;

                case QueryResponseField::response_delay:
                    response_delay = std::chrono::microseconds(dec.read_signed() * 1000000 / block_parameters.storage_parameters.ticks_per_second);
                    break;

                case QueryResponseField::query_name_index:
                    qname = dec.read_unsigned();
                    break;

                case QueryResponseField::query_size:
                    query_size = dec.read_unsigned();
                    break;

                case QueryResponseField::response_size:
                    response_size = dec.read_unsigned();
                    break;

                case QueryResponseField::query_extended:
                    query_extra_info = readExtraInfo(dec, fields);
                    break;

                case QueryResponseField::response_extended:
                    response_extra_info = readExtraInfo(dec, fields);
                    break;

                default:
                    // Unknown item, skip.
                    dec.skip();
                    break;
                }
            }
        }
        catch (const std::logic_error& e)
        {
            throw cbor_file_format_unexpected_item_error("QueryResponseItem");
        }
    }

    void QueryResponseItem::writeCbor(CborBaseEncoder& enc,
                                      const std::chrono::system_clock::time_point& earliest_time,
                                      const BlockParameters& block_parameters,
                                      const HintsExcluded& exclude)
    {
        constexpr int time_index = find_query_response_index(QueryResponseField::time_offset);
        constexpr int client_address_index = find_query_response_index(QueryResponseField::client_address_index);
        constexpr int client_port_index = find_query_response_index(QueryResponseField::client_port);
        constexpr int transaction_id_index = find_query_response_index(QueryResponseField::transaction_id);
        constexpr int qr_signature_index = find_query_response_index(QueryResponseField::qr_signature_index);
        constexpr int client_hoplimit_index = find_query_response_index(QueryResponseField::client_hoplimit);
        constexpr int delay_index = find_query_response_index(QueryResponseField::response_delay);
        constexpr int query_name_index = find_query_response_index(QueryResponseField::query_name_index);
        constexpr int query_size_index = find_query_response_index(QueryResponseField::query_size);
        constexpr int response_size_index = find_query_response_index(QueryResponseField::response_size);
        constexpr int query_extended_index = find_query_response_index(QueryResponseField::query_extended);
        constexpr int response_extended_index = find_query_response_index(QueryResponseField::response_extended);

        enc.writeMapHeader();
        if ( !exclude.timestamp )
        {
            enc.write(time_index);
            enc.write(std::chrono::duration_cast<std::chrono::nanoseconds>(*tstamp - earliest_time).count() * block_parameters.storage_parameters.ticks_per_second / 1000000000);
        }
        if ( !exclude.client_address )
        {
            enc.write(client_address_index);
            enc.write(client_address);
        }
        if ( !exclude.client_port )
        {
            enc.write(client_port_index);
            enc.write(client_port);
        }
        if ( !exclude.transaction_id )
        {
            enc.write(transaction_id_index);
            enc.write(id);
        }
        enc.write(qr_signature_index);
        enc.write(signature);

        if ( ( qr_flags & QUERY_ONLY ) && !exclude.client_hoplimit )
        {
            enc.write(client_hoplimit_index);
            enc.write(hoplimit);
        }

        if ( ( qr_flags & RESPONSE_ONLY ) &&
             !exclude.response_delay &&
            response_delay )
        {
            enc.write(delay_index);
            enc.write((*response_delay).count() * block_parameters.storage_parameters.ticks_per_second / 1000000000);
        }

        if ( ( qr_flags & QR_HAS_QUESTION ) && !exclude.query_name )
        {
            enc.write(query_name_index);
            enc.write(qname);
        }

        if ( ( qr_flags & QUERY_ONLY ) && !exclude.query_size )
        {
            enc.write(query_size_index);
            enc.write(query_size);
        }

        if ( ( qr_flags & RESPONSE_ONLY ) && !exclude.response_size )
        {
            enc.write(response_size_index);
            enc.write(response_size);
        }

        if ( query_extra_info )
            writeExtraInfo(enc, query_extended_index, *query_extra_info);

        if ( response_extra_info )
            writeExtraInfo(enc, response_extended_index, *response_extra_info);

        enc.writeBreak();
    }

    std::size_t hash_value(const AddressEventItem& aei)
    {
        std::size_t seed = boost::hash_value(aei.type);
        boost::hash_combine(seed, aei.code);
        boost::hash_combine(seed, aei.address);
        boost::hash_combine(seed, aei.transport_flags);
        return seed;
    }

    void AddressEventCount::readCbor(CborBaseDecoder& dec,
                                     const FileVersionFields& fields,
                                     const Defaults& defaults)
    {
        bool seen_count = false;

        aei.code = defaults.ae_code;
        aei.type = defaults.ae_type;
        aei.address = boost::none;
        aei.transport_flags = boost::none;

        try
        {
            bool indef;
            uint64_t n_elems = dec.readMapHeader(indef);
            while ( indef || n_elems-- > 0 )
            {
                if ( indef && dec.type() == CborBaseDecoder::TYPE_BREAK )
                {
                    dec.readBreak();
                    break;
                }

                switch(fields.address_event_count_field(dec.read_unsigned()))
                {
                case AddressEventCountField::ae_type:
                    aei.type = static_cast<AddressEvent::EventType>(dec.read_unsigned());
                    break;

                case AddressEventCountField::ae_code:
                    aei.code = dec.read_unsigned();
                    break;

                case AddressEventCountField::ae_address_index:
                    aei.address = dec.read_unsigned();
                    break;

                case AddressEventCountField::ae_transport_flags:
                    aei.transport_flags = dec.read_unsigned();
                    break;

                case AddressEventCountField::ae_count:
                    count = dec.read_unsigned();
                    seen_count = true;
                    break;

                default:
                    // Unknown item, skip.
                    dec.skip();
                    break;
                }
            }
        }
        catch (const std::logic_error& e)
        {
            throw cbor_file_format_unexpected_item_error("AddressEvent");
        }

        if ( !seen_count )
            throw cbor_file_format_error("No count in AddressEventCount");
    }

    void AddressEventCount::writeCbor(CborBaseEncoder& enc)
    {
        constexpr int type_index = find_address_event_count_index(AddressEventCountField::ae_type);
        constexpr int code_index = find_address_event_count_index(AddressEventCountField::ae_code);
        constexpr int address_index = find_address_event_count_index(AddressEventCountField::ae_address_index);
        constexpr int transport_flags_index = find_address_event_count_index(AddressEventCountField::ae_transport_flags);
        constexpr int count_index = find_address_event_count_index(AddressEventCountField::ae_count);

        enc.writeMapHeader();
        enc.write(type_index);
        enc.write(aei.type);
        if ( aei.code )
        {
            enc.write(code_index);
            enc.write(aei.code);
        }
        enc.write(address_index);
        enc.write(aei.address);
        enc.write(transport_flags_index);
        enc.write(aei.transport_flags);
        enc.write(count_index);
        enc.write(count);
        enc.writeBreak();
    }

    std::size_t hash_value(const MalformedMessageData& mmd)
    {
        std::size_t seed = boost::hash_value(mmd.server_address);
        boost::hash_combine(seed, mmd.server_port);
        boost::hash_combine(seed, mmd.mm_transport_flags);
        boost::hash_combine(seed, mmd.mm_payload);
        return seed;
    }

    void MalformedMessageData::readCbor(CborBaseDecoder& dec,
                                        const FileVersionFields& fields,
                                        const Defaults& defaults)
    {
        try
        {
            // No necessarily present, default to 0 on repeated read.
            mm_transport_flags = boost::none;
            server_address = boost::none;
            server_port = boost::none;
            mm_payload = boost::none;

            bool indef;
            uint64_t n_elems = dec.readMapHeader(indef);
            while ( indef || n_elems-- > 0 )
            {
                if ( indef && dec.type() == CborBaseDecoder::TYPE_BREAK )
                {
                    dec.readBreak();
                    break;
                }

                switch(fields.malformed_message_data_field(dec.read_unsigned()))
                {
                case MalformedMessageDataField::server_address_index:
                    server_address = dec.read_unsigned();
                    break;

                case MalformedMessageDataField::server_port:
                    server_port = dec.read_unsigned();
                    break;

                case MalformedMessageDataField::mm_transport_flags:
                    mm_transport_flags = dec.read_unsigned();
                    break;

                case MalformedMessageDataField::mm_payload:
                    mm_payload = dec.read_binary();
                    break;

                default:
                    // Unknown item, skip.
                    dec.skip();
                    break;
                }
            }
        }
        catch (const std::logic_error& e)
        {
            throw cbor_file_format_unexpected_item_error("MalformedMessageData");
        }
    }

    void MalformedMessageData::writeCbor(CborBaseEncoder& enc)
    {
        constexpr int server_address_index_index = find_malformed_message_data_index(MalformedMessageDataField::server_address_index);
        constexpr int server_port_index = find_malformed_message_data_index(MalformedMessageDataField::server_port);
        constexpr int mm_transport_flags_index = find_malformed_message_data_index(MalformedMessageDataField::mm_transport_flags);
        constexpr int mm_payload_index = find_malformed_message_data_index(MalformedMessageDataField::mm_payload);

        enc.writeMapHeader(4);
        enc.write(server_address_index_index);
        enc.write(server_address);
        enc.write(server_port_index);
        enc.write(server_port);
        enc.write(mm_transport_flags_index);
        enc.write(mm_transport_flags);
        enc.write(mm_payload_index);
        enc.write(mm_payload);
    }

    void MalformedMessageItem::clear()
    {
        tstamp = boost::none;
        client_address = message_data = boost::none;
        client_port = boost::none;
    }

    void MalformedMessageItem::readCbor(CborBaseDecoder& dec,
                                        const std::chrono::system_clock::time_point& earliest_time,
                                        const BlockParameters& block_parameters,
                                        const FileVersionFields& fields)
    {
        tstamp = boost::none;
        client_address = message_data = boost::none;
        client_port = boost::none;

        try
        {
            bool indef;
            uint64_t n_elems = dec.readMapHeader(indef);
            while ( indef || n_elems-- > 0 )
            {
                if ( indef && dec.type() == CborBaseDecoder::TYPE_BREAK )
                {
                    dec.readBreak();
                    break;
                }

                switch(fields.malformed_message_field(dec.read_unsigned()))
                {
                case MalformedMessageField::time_offset:
                    tstamp = earliest_time + std::chrono::microseconds(dec.read_signed() * 1000000 / block_parameters.storage_parameters.ticks_per_second);
                    break;
                    break;

                case MalformedMessageField::client_address_index:
                    client_address = dec.read_unsigned();
                    break;

                case MalformedMessageField::client_port:
                    client_port = dec.read_unsigned();
                    break;

                case MalformedMessageField::message_data_index:
                    message_data = dec.read_unsigned();
                    break;

                default:
                    // Unknown item, skip.
                    dec.skip();
                    break;
                }
            }
        }
        catch (const std::logic_error& e)
        {
            throw cbor_file_format_unexpected_item_error("MalformedMessage");
        }
    }

    void MalformedMessageItem::writeCbor(CborBaseEncoder& enc,
                                     const std::chrono::system_clock::time_point& earliest_time,
                                     const BlockParameters& block_parameters)
    {
        constexpr int time_offset_index = find_malformed_message_index(MalformedMessageField::time_offset);
        constexpr int client_address_index_index = find_malformed_message_index(MalformedMessageField::client_address_index);
        constexpr int client_port_index = find_malformed_message_index(MalformedMessageField::client_port);
        constexpr int message_data_index_index = find_malformed_message_index(MalformedMessageField::message_data_index);

        enc.writeMapHeader(4);
        enc.write(time_offset_index);
        enc.write(std::chrono::duration_cast<std::chrono::nanoseconds>(*tstamp - earliest_time).count() * block_parameters.storage_parameters.ticks_per_second / 1000000000);
        enc.write(client_address_index_index);
        enc.write(client_address);
        enc.write(client_port_index);
        enc.write(client_port);
        enc.write(message_data_index_index);
        enc.write(message_data);
    }

    void BlockData::readCbor(CborBaseDecoder& dec,
                             const FileVersionFields& fields,
                             const Defaults& defaults)
    {
        bool indef;
        uint64_t n_elems = dec.readMapHeader(indef);
        while ( indef || n_elems-- > 0 )
        {
            if ( indef && dec.type() == CborBaseDecoder::TYPE_BREAK )
            {
                dec.readBreak();
                break;
            }

            switch(fields.block_field(dec.read_unsigned()))
            {
            case BlockField::preamble:
                readBlockPreamble(dec, fields);
                break;

            case BlockField::tables:
                readHeaders(dec, fields, defaults);
                break;

            case BlockField::statistics:
                readStats(dec, fields);
                break;

            case BlockField::queries:
                readItems(dec, fields, defaults);
                break;

            case BlockField::address_event_counts:
                readAddressEventCounts(dec, fields, defaults);
                break;

            default:
                dec.skip();
                break;
            }
        }
    }

    void BlockData::readBlockPreamble(CborBaseDecoder& dec, const FileVersionFields& fields)
    {
        uint64_t ticks_per_second = block_parameters_[block_parameters_index].storage_parameters.ticks_per_second;
        Timestamp ts;
        bool indef;
        uint64_t n_elems = dec.readMapHeader(indef);
        block_parameters_index = 0; // Default value if not read.
        while ( indef || n_elems-- > 0 )
        {
            if ( indef && dec.type() == CborBaseDecoder::TYPE_BREAK )
            {
                dec.readBreak();
                break;
            }

            switch(fields.block_preamble_field(dec.read_unsigned()))
            {
            case BlockPreambleField::earliest_time:
                ts.readCbor(dec);
                earliest_time = ts.getTimePoint(ticks_per_second);
                break;

            case BlockPreambleField::block_parameters_index:
                block_parameters_index = dec.read_unsigned();
                break;

            default:
                dec.skip();
                break;
            }
        }
    }

    void BlockData::readHeaders(CborBaseDecoder& dec,
                                const FileVersionFields& fields,
                                const Defaults& defaults)
    {
        bool indef;
        uint64_t n_elems = dec.readMapHeader(indef);
        while ( indef || n_elems-- > 0 )
        {
            if ( indef && dec.type() == CborBaseDecoder::TYPE_BREAK )
            {
                dec.readBreak();
                break;
            }

            switch(fields.block_tables_field(dec.read_unsigned()))
            {
            case BlockTablesField::ip_address:
                ip_addresses.readCbor(dec, fields, defaults);
                break;

            case BlockTablesField::classtype:
                class_types.readCbor(dec, fields, defaults);
                break;

            case BlockTablesField::name_rdata:
                names_rdatas.readCbor(dec, fields, defaults);
                break;

            case BlockTablesField::query_response_signature:
                query_response_signatures.readCbor(dec, fields, defaults);
                break;

            case BlockTablesField::question_list:
                questions_lists.readCbor(dec, fields, defaults);
                break;

            case BlockTablesField::question_rr:
                questions.readCbor(dec, fields, defaults);
                break;

            case BlockTablesField::rr_list:
                rrs_lists.readCbor(dec, fields,  defaults);
                break;

            case BlockTablesField::rr:
                resource_records.readCbor(dec, fields,  defaults);
                break;

            case BlockTablesField::malformed_message_data:
                malformed_message_data.readCbor(dec, fields,  defaults);
                break;

            default:
                dec.skip();
                break;
            }
        }
    }

    void BlockData::readItems(CborBaseDecoder& dec,
                              const FileVersionFields& fields,
                              const Defaults& defaults)
    {
        const BlockParameters& block_parameters = block_parameters_[block_parameters_index];
        bool indef;
        uint64_t n_elems = dec.readArrayHeader(indef);
        if ( !indef )
            query_response_items.reserve(n_elems);
        while ( indef || n_elems-- > 0 )
        {
            if ( indef && dec.type() == CborBaseDecoder::TYPE_BREAK )
            {
                dec.readBreak();
                break;
            }

            QueryResponseItem qri;
            qri.readCbor(dec, earliest_time, block_parameters, fields, defaults);
            query_response_items.push_back(std::move(qri));
        }
    }

    void BlockData::readStats(CborBaseDecoder& dec, const FileVersionFields& fields)
    {
        start_packet_statistics = {};

        bool indef;
        uint64_t n_elems = dec.readMapHeader(indef);
        while ( indef || n_elems-- > 0 )
        {
            if ( indef && dec.type() == CborBaseDecoder::TYPE_BREAK )
            {
                dec.readBreak();
                break;
            }

            switch(fields.block_statistics_field(dec.read_signed()))
            {
            case BlockStatisticsField::malformed_items:
                last_packet_statistics.malformed_packet_count += dec.read_unsigned();
                break;

            case BlockStatisticsField::compactor_non_dns_packets:
                last_packet_statistics.unhandled_packet_count += dec.read_unsigned();
                break;

            case BlockStatisticsField::compactor_out_of_order_packets:
                last_packet_statistics.out_of_order_packet_count += dec.read_unsigned();
                break;

            case BlockStatisticsField::processed_messages:
                last_packet_statistics.raw_packet_count += dec.read_unsigned();
                break;

            case BlockStatisticsField::compactor_missing_pairs:
                last_packet_statistics.output_cbor_drop_count += dec.read_unsigned();
                break;

            case BlockStatisticsField::unmatched_queries:
                last_packet_statistics.query_without_response_count += dec.read_unsigned();
                break;

            case BlockStatisticsField::unmatched_responses:
                last_packet_statistics.response_without_query_count += dec.read_unsigned();
                break;

            case BlockStatisticsField::qr_data_items:
                last_packet_statistics.qr_pair_count += dec.read_unsigned();
                break;

            case BlockStatisticsField::compactor_missing_packets:
                last_packet_statistics.output_raw_pcap_drop_count += dec.read_unsigned();
                break;

            case BlockStatisticsField::compactor_missing_non_dns:
                last_packet_statistics.output_ignored_pcap_drop_count += dec.read_unsigned();
                break;

            default:
                dec.skip();
                break;
            }
        }
    }

    void BlockData::readAddressEventCounts(CborBaseDecoder& dec,
                                           const FileVersionFields& fields,
                                           const Defaults& defaults)
    {
        bool indef;
        uint64_t n_elems = dec.readArrayHeader(indef);
        while ( indef || n_elems-- > 0 )
        {
            if ( indef && dec.type() == CborBaseDecoder::TYPE_BREAK )
            {
                dec.readBreak();
                break;
            }

            AddressEventCount aec = {};
            aec.readCbor(dec, fields, defaults);
            address_event_counts[aec.aei] = aec.count;
        }
    }

    void BlockData::readMalformedMessageItems(CborBaseDecoder& dec, const FileVersionFields& fields)
    {
        const BlockParameters& block_parameters = block_parameters_[block_parameters_index];
        bool indef;
        uint64_t n_elems = dec.readArrayHeader(indef);
        if ( !indef )
            malformed_messages.reserve(n_elems);
        while ( indef || n_elems-- > 0 )
        {
            if ( indef && dec.type() == CborBaseDecoder::TYPE_BREAK )
            {
                dec.readBreak();
                break;
            }

            MalformedMessageItem mm;
            mm.readCbor(dec, earliest_time, block_parameters, fields);
            malformed_messages.push_back(std::move(mm));
        }
    }

    void BlockData::writeCbor(CborBaseEncoder& enc, const HintsExcluded& exclude)
    {
        constexpr int preamble_index = find_block_index(BlockField::preamble);
        constexpr int statistics_index = find_block_index(BlockField::statistics);
        constexpr int tables_index = find_block_index(BlockField::tables);
        constexpr int earliest_time_index = find_block_preamble_index(BlockPreambleField::earliest_time);
        constexpr int block_parameters_index_index = find_block_preamble_index(BlockPreambleField::block_parameters_index);

        uint64_t ticks_per_second = block_parameters_[block_parameters_index].storage_parameters.ticks_per_second;

        // Block header.
        enc.writeMapHeader();

        // Block preamble.
        enc.write(preamble_index);
        enc.writeMapHeader(1 + (block_parameters_index > 0));

        enc.write(earliest_time_index);
        Timestamp ts(earliest_time, ticks_per_second);
        ts.writeCbor(enc);

        if ( block_parameters_index > 0 )
        {
            enc.write(block_parameters_index_index);
            enc.write(block_parameters_index);
        }

        // Statistics.
        enc.write(statistics_index);
        writeStats(enc);

        // Header tables.
        enc.write(tables_index);
        writeHeaders(enc, exclude);

        // Block items.
        writeItems(enc, exclude);

        // Address event items.
        if ( !exclude.address_events )
            writeAddressEventCounts(enc);

        // Block terminator.
        enc.writeBreak();
    }

    void BlockData::writeHeaders(CborBaseEncoder& enc, const HintsExcluded& exclude)
    {
        constexpr int ipaddress_index = find_block_tables_index(BlockTablesField::ip_address);
        constexpr int classtype_index = find_block_tables_index(BlockTablesField::classtype);
        constexpr int name_rdata_index = find_block_tables_index(BlockTablesField::name_rdata);
        constexpr int query_response_signature_index = find_block_tables_index(BlockTablesField::query_response_signature);
        constexpr int question_list_index = find_block_tables_index(BlockTablesField::question_list);
        constexpr int question_rr_index = find_block_tables_index(BlockTablesField::question_rr);
        constexpr int rr_list_index = find_block_tables_index(BlockTablesField::rr_list);
        constexpr int rr_index = find_block_tables_index(BlockTablesField::rr);

        enc.writeMapHeader();
        if ( ip_addresses.size() > 0 )
        {
            enc.write(ipaddress_index);
            ip_addresses.writeCbor(enc, exclude);
        }
        if ( class_types.size() > 0 )
        {
            enc.write(classtype_index);
            class_types.writeCbor(enc, exclude);
        }
        if ( names_rdatas.size() > 0 )
        {
            enc.write(name_rdata_index);
            names_rdatas.writeCbor(enc, exclude);
        }
        if ( query_response_signatures.size() > 0 )
        {
            enc.write(query_response_signature_index);
            query_response_signatures.writeCbor(enc, exclude);
        }
        if ( questions_lists.size() > 0 )
        {
            enc.write(question_list_index);
            questions_lists.writeCbor(enc, exclude);
        }
        if ( questions.size() > 0 )
        {
            enc.write(question_rr_index);
            questions.writeCbor(enc, exclude);
        }
        if ( rrs_lists.size() > 0 )
        {
            enc.write(rr_list_index);
            rrs_lists.writeCbor(enc, exclude);
        }
        if ( resource_records.size() > 0 )
        {
            enc.write(rr_index);
            resource_records.writeCbor(enc, exclude);
        }
        enc.writeBreak();
    }

    void BlockData::writeItems(CborBaseEncoder& enc, const HintsExcluded& exclude)
    {
        constexpr int queries_index = find_block_index(BlockField::queries);
        const BlockParameters& block_parameters = block_parameters_[block_parameters_index];

        if ( query_response_items.size() > 0 )
        {
            enc.write(queries_index);
            enc.writeArrayHeader(query_response_items.size());
            for ( auto& qri : query_response_items )
                qri.writeCbor(enc, earliest_time, block_parameters, exclude);
        }
    }

    void BlockData::writeStats(CborBaseEncoder& enc)
    {
        constexpr int processed_messages_index = find_block_statistics_index(BlockStatisticsField::processed_messages);
        constexpr int qr_data_items_index = find_block_statistics_index(BlockStatisticsField::qr_data_items);
        constexpr int unmatched_queries_index = find_block_statistics_index(BlockStatisticsField::unmatched_queries);
        constexpr int unmatched_responses_index = find_block_statistics_index(BlockStatisticsField::unmatched_responses);
        constexpr int malformed_items_index = find_block_statistics_index(BlockStatisticsField::malformed_items);
        constexpr int non_dns_packets_index = find_block_statistics_index(BlockStatisticsField::compactor_non_dns_packets);
        constexpr int out_of_order_packets_index = find_block_statistics_index(BlockStatisticsField::compactor_out_of_order_packets);
        constexpr int missing_pairs_index = find_block_statistics_index(BlockStatisticsField::compactor_missing_pairs);
        constexpr int missing_packets_index = find_block_statistics_index(BlockStatisticsField::compactor_missing_packets);
        constexpr int missing_non_dns_index = find_block_statistics_index(BlockStatisticsField::compactor_missing_non_dns);

        enc.writeMapHeader();
        enc.write(processed_messages_index);
        enc.write(last_packet_statistics.raw_packet_count - start_packet_statistics.raw_packet_count);
        enc.write(qr_data_items_index);
        enc.write(last_packet_statistics.qr_pair_count - start_packet_statistics.qr_pair_count);
        enc.write(unmatched_queries_index);
        enc.write(last_packet_statistics.query_without_response_count - start_packet_statistics.query_without_response_count);
        enc.write(unmatched_responses_index);
        enc.write(last_packet_statistics.response_without_query_count - start_packet_statistics.response_without_query_count);
        enc.write(malformed_items_index);
        enc.write(last_packet_statistics.malformed_packet_count - start_packet_statistics.malformed_packet_count);
        enc.write(non_dns_packets_index);
        enc.write(last_packet_statistics.unhandled_packet_count - start_packet_statistics.unhandled_packet_count);
        enc.write(out_of_order_packets_index);
        enc.write(last_packet_statistics.out_of_order_packet_count - start_packet_statistics.out_of_order_packet_count);
        enc.write(missing_pairs_index);
        enc.write(last_packet_statistics.output_cbor_drop_count - start_packet_statistics.output_cbor_drop_count);
        enc.write(missing_packets_index);
        enc.write(last_packet_statistics.output_raw_pcap_drop_count - start_packet_statistics.output_raw_pcap_drop_count);
        enc.write(missing_non_dns_index);
        enc.write(last_packet_statistics.output_ignored_pcap_drop_count - start_packet_statistics.output_ignored_pcap_drop_count);
        enc.writeBreak();
    }

    void BlockData::writeAddressEventCounts(CborBaseEncoder& enc)
    {
        constexpr int aec_index = find_block_index(BlockField::address_event_counts);

        if ( address_event_counts.size() > 0 )
        {
            enc.write(aec_index);
            enc.writeArrayHeader(address_event_counts.size());
            for ( auto& aeci : address_event_counts )
            {
                AddressEventCount aec;
                aec.aei = aeci.first;
                aec.count = aeci.second;
                aec.writeCbor(enc);
            }
        }
    }

    void BlockData::writeMalformedMessageItems(CborBaseEncoder& enc)
    {
        constexpr int malformed_messages_index = find_block_index(BlockField::malformed_messages);
        const BlockParameters& block_parameters = block_parameters_[block_parameters_index];

        if ( malformed_messages.size() > 0 )
        {
            enc.write(malformed_messages_index);
            enc.writeArrayHeader(malformed_messages.size());
            for ( auto& mm : malformed_messages )
                mm.writeCbor(enc, earliest_time, block_parameters);
        }
    }
}
