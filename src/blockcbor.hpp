/*
 * Copyright 2016-2021 Internet Corporation for Assigned Names and Numbers.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Developed by Sinodun IT (www.sinodun.com)
 */
#ifndef BLOCKCBOR_HPP
#define BLOCKCBOR_HPP

#include <string>
#include <vector>

#include <boost/optional.hpp>

#include "queryresponse.hpp"

/**
 * \exception cbor_file_format_error
 * \brief Signals a CBOR file format error.
 */
class cbor_file_format_error : public std::runtime_error
{
public:
    /**
     * \brief Constructor.
     *
     * \param what message detailing the problem.
     */
    explicit cbor_file_format_error(const std::string& what)
        : std::runtime_error(what) {}

    /**
     * \brief Constructor.
     *
     * \param what message detailing the problem.
     */
    explicit cbor_file_format_error(const char*  what)
        : std::runtime_error(what) {}
};

/**
 * \exception cbor_file_format_unexpected_item_error
 * \brief Signals a CBOR file format 'unexpected CBOR item' error.
 */
class cbor_file_format_unexpected_item_error : public cbor_file_format_error
{
public:
    /**
     * \brief Constructor.
     *
     * \param map containing unexpected item.
     */
    explicit cbor_file_format_unexpected_item_error(const std::string& map)
        : cbor_file_format_error("Unexpected CBOR item reading " + map) {}

    /**
     * \brief Constructor.
     *
     * \param map containing unexpected item.
     */
    explicit cbor_file_format_unexpected_item_error(const char*  map)
        : cbor_file_format_unexpected_item_error(std::string(map)) {}
};

namespace block_cbor {
    /**
     * \brief Output format 05 onwards file format string.
     */
    extern const std::string& FILE_FORMAT_ID;

    /**
     * \brief Current output format major version.
     */
    extern const unsigned FILE_FORMAT_10_MAJOR_VERSION;

    /**
     * \brief Current output format minor version.
     */
    extern const unsigned FILE_FORMAT_10_MINOR_VERSION;

    /**
     * \brief Current output format private version.
     */
    extern const unsigned FILE_FORMAT_10_PRIVATE_VERSION;

    /**
     * \brief Output format 05 major version.
     */
    extern const unsigned FILE_FORMAT_05_MAJOR_VERSION;

    /**
     * \brief Output format 05 minor version.
     */
    extern const unsigned FILE_FORMAT_05_MINOR_VERSION;

    /**
     * \brief Output format 02 file format string.
     */
    extern const std::string& FILE_FORMAT_02_ID;

    /**
     * \brief 0.2 output format version.
     *
     * This is assigned to the format minor version,
     * with a major format version of 0.
     */
    extern const unsigned FILE_FORMAT_02_VERSION;

    /**
     * \brief DNS flags enum.
     *
     * Note that we always store response OPT RRs directly in the file,
     * so there is no need for a response DO in the following.
     */
    enum DNSFlags
    {
        QUERY_CD = (1 << 0),
        QUERY_AD = (1 << 1),
        QUERY_Z = (1 << 2),
        QUERY_RA = (1 << 3),
        QUERY_RD = (1 << 4),
        QUERY_TC = (1 << 5),
        QUERY_AA = (1 << 6),
        QUERY_DO = (1 << 7),
        RESPONSE_CD = (1 << 8),
        RESPONSE_AD = (1 << 9),
        RESPONSE_Z = (1 << 10),
        RESPONSE_RA = (1 << 11),
        RESPONSE_RD = (1 << 12),
        RESPONSE_TC = (1 << 13),
        RESPONSE_AA = (1 << 14),
    };

    /**
     * \brief QueryResponse flags values enum.
     */
    enum QueryResponseFlags
    {
        HAS_QUERY = (1 << 0),
        HAS_RESPONSE = (1 << 1),
        QUERY_AND_RESPONSE = (HAS_QUERY | HAS_RESPONSE),
        QUERY_HAS_OPT = (1 << 2),
        RESPONSE_HAS_OPT = (1 << 3),
        QUERY_HAS_NO_QUESTION = (1 << 4),
        RESPONSE_HAS_NO_QUESTION = (1 << 5),
    };

    /**
     * \brief QueryResponse hint flags values enum.
     */
    enum QueryResponseHintFlags
    {
        TIME_OFFSET = (1 << 0),
        CLIENT_ADDRESS_INDEX = (1 << 1),
        CLIENT_PORT = (1 << 2),
        TRANSACTION_ID = (1 << 3),
        QR_SIGNATURE_INDEX = (1 << 4),
        CLIENT_HOPLIMIT = (1 << 5),
        RESPONSE_DELAY = (1 << 6),
        QUERY_NAME_INDEX = (1 << 7),
        QUERY_SIZE = (1 << 8),
        RESPONSE_SIZE = (1 << 9),
        RESPONSE_PROCESSING_DATA = (1 << 10),
        QUERY_QUESTION_SECTIONS = (1 << 11),
        QUERY_ANSWER_SECTIONS = (1 << 12),
        QUERY_AUTHORITY_SECTIONS = (1 << 13),
        QUERY_ADDITIONAL_SECTIONS = (1 << 14),
        RESPONSE_ANSWER_SECTIONS = (1 << 15),
        RESPONSE_AUTHORITY_SECTIONS = (1 << 16),
        RESPONSE_ADDITIONAL_SECTIONS = (1 << 17)
    };

    /**
     * \brief QueryResponse signature hint flags values enum.
     */
    enum QueryResponseSignatureHintFlags
    {
        SERVER_ADDRESS = (1 << 0),
        SERVER_PORT = (1 << 1),
        QR_TRANSPORT_FLAGS = (1 << 2),
        QR_TYPE = (1 << 3),
        QR_SIG_FLAGS = (1 << 4),
        QUERY_OPCODE = (1 << 5),
        DNS_FLAGS = (1 << 6),
        QUERY_RCODE = (1 << 7),
        QUERY_CLASS_TYPE = (1 << 8),
        QUERY_QDCOUNT = (1 << 9),
        QUERY_ANCOUNT = (1 << 10),
        QUERY_NSCOUNT = (1 << 11),
        QUERY_ARCOUNT = (1 << 12),
        QUERY_EDNS_VERSION = (1 << 13),
        QUERY_UDP_SIZE = (1 << 14),
        QUERY_OPT_RDATA = (1 << 15),
        RESPONSE_RCODE = (1 << 16)
    };

    /**
     * \brief Resource Record hint flags values enum.
     */
    enum RRHintFlags
    {
        TTL = (1 << 0),
        RDATA_INDEX = (1 << 1)
    };

    /**
     * \brief Other data hint flags values enum.
     */
    enum OtherDataHintFlags
    {
        MALFORMED_MESSAGES = (1 << 0),
        ADDRESS_EVENT_COUNTS = (1 << 1)
    };

    /**
     * \brief Storage flags values enum.
     */
    enum StorageFlags
    {
        ANONYMISED_DATA = (1 << 0),
        SAMPLED_DATA = (1 << 1),
        NORMALIZED_NAMES = (1 << 2)
    };

    /**
     * \brief Transport flags enum.
     */
    enum TransportFlags
    {
        IPV6 = (1 << 0),
        UDP = (0 << 1),
        TCP = (1 << 1),
        TLS = (2 << 1),
        DTLS = (3 << 1),
        DOH = (4 << 1),

        QUERY_TRAILINGDATA = (1 << 5),
    };

    /**
     * \brief Transaction types.
     */
    enum QueryResponseType
    {
        STUB = 0,
        CLIENT = 1,
        RESOLVER = 2,
        AUTHORITATIVE = 3,
        FORWARDER = 4,
        TOOL = 5,
        UPDATE = 6,
    };

    /**
     * \brief the known file formats.
     */
    enum class FileFormatVersion
    {
        format_02,
        format_05,
        format_10
    };

    /**
     * \enum Maps
     * \brief The map types in C-DNS.
     */
    enum class Maps
    {
        file_preamble,
        configuration,
        block,
        block_preamble,
        block_statistics,
        block_tables,
        query_response,
        class_type,
        query_response_signature,
        question,
        rr,
        query_response_extended,
        address_event_count,
    };

    /*
     * Map field identifiers for _internal_ use only.
     *
     * The code has these for internal use. They never change.
     *
     * The compactor only ever writes the most up to date file format.
     * It uses find_*_index() functions to map map field values to
     * output values which is sufficiently constexpr for the translation
     * to be done at compile time.
     *
     * The inspector uses the file header to initialise a runtime access
     * object with appropriate translation tables to translate
     * from file to internal values.
     *
     * Each type has a member 'unknown' signifying that there is no
     * corresponding internal value for a given external value.
     */

    /**
     * \enum FilePreambleField
     * \brief Fields in file preamble map.
     */
    enum class FilePreambleField
    {
        // Obsolete format 02 fields.
        format_version,

        // Obsolete format 05 fields.
        configuration,
        generator_id,
        host_id,

        // Current fields.
        major_format_version,
        minor_format_version,
        private_version,
        block_parameters,

        unknown = -1
    };

    /**
     * \enum BlockParametersField
     * \brief Fields in block parameters map.
     */
    enum class BlockParametersField
    {
        storage_parameters,
        collection_parameters,

        unknown = -1
    };

    /**
     * \enum StorageParametersField
     * \brief Fields in storage parameters map.
     */
    enum class StorageParametersField
    {
        ticks_per_second,
        max_block_items,
        storage_hints,
        opcodes,
        rr_types,
        storage_flags,
        client_address_prefix_ipv4,
        client_address_prefix_ipv6,
        server_address_prefix_ipv4,
        server_address_prefix_ipv6,
        sampling_method,
        anonymisation_method,

        unknown = -1
    };

    /**
     * \enum StorageHintsField
     * \brief Fields in storage hints map.
     */
    enum class StorageHintsField
    {
        query_response_hints,
        query_response_signature_hints,
        rr_hints,
        other_data_hints,

        unknown = -1
    };

    /**
     * \enum CollectionParametersField
     * \brief Fields in collection parameters map.
     */
    enum class CollectionParametersField
    {
        query_timeout,
        skew_timeout,
        snaplen,
        promisc,
        interfaces,
        server_addresses,
        vlan_ids,
        filter,
        generator_id,
        host_id,
        dns_port,

        unknown = -1
    };

    /**
     * \enum ConfigurationField
     * \brief Fields in configuration map.
     */
    enum class ConfigurationField
    {
        query_timeout,
        skew_timeout,
        snaplen,
        promisc,
        interfaces,
        server_addresses,
        vlan_ids,
        filter,
        query_options,
        response_options,
        accept_rr_types,
        ignore_rr_types,
        max_block_qr_items,

        unknown = -1
    };

    /**
     * \enum BlockField
     * \brief Fields in block map.
     */
    enum class BlockField
    {
        preamble,
        statistics,
        tables,
        queries,
        address_event_counts,
        malformed_messages,

        unknown = -1
    };

    /**
     * \enum BlockPreambleField
     * \brief Fields in block preamble map.
     */
    enum class BlockPreambleField
    {
        earliest_time,
        block_parameters_index,

        compactor_end_time,
        compactor_start_time,

        unknown = -1
    };

    /**
     * \enum BlockStatisticsField
     * \brief Fields in block statistics map.
     */
    enum class BlockStatisticsField
    {
        processed_messages,
        qr_data_items,
        unmatched_queries,
        unmatched_responses,
        discarded_opcode,
        malformed_items,

        compactor_non_dns_packets,
        compactor_out_of_order_packets,
        compactor_missing_pairs,
        compactor_missing_packets,
        compactor_missing_non_dns,
        compactor_packets,
        compactor_missing_received,
        compactor_discarded_packets,
        compactor_missing_matcher,
        pcap_packets,
        pcap_missing_if,
        pcap_missing_os,

        // Obsolete
        partially_malformed_packets,

        unknown = -1
    };

    /**
     * \enum BlockTablesField
     * \brief Fields in block tables map.
     */
    enum class BlockTablesField
    {
        ip_address,
        classtype,
        name_rdata,
        query_response_signature,
        question_list,
        question_rr,
        rr_list,
        rr,
        malformed_message_data,

        unknown = -1
    };

    /**
     * \enum QueryResponseField
     * \brief Fields in query response map.
     */
    enum class QueryResponseField
    {
        time_offset,
        client_address_index,
        client_port,
        transaction_id,
        qr_signature_index,
        client_hoplimit,
        response_delay,
        query_name_index,
        query_size,
        response_size,
        response_processing_data,
        query_extended,
        response_extended,

        // Obsolete items
        time_pseconds,
        response_delay_pseconds,

        unknown = -1
    };

    /**
     * \enum ClassTypeField
     * \brief Fields in class type map.
     */
    enum class ClassTypeField
    {
        type_id,
        class_id,

        unknown = -1
    };

    /**
     * \enum QueryResponseSignatureField
     * \brief Fields in query response signature map.
     */
    enum class QueryResponseSignatureField
    {
        server_address_index,
        server_port,
        qr_transport_flags,
        qr_type,
        qr_sig_flags,
        query_opcode,
        qr_dns_flags,
        query_rcode,
        query_classtype_index,
        query_qd_count,
        query_an_count,
        query_ns_count,
        query_ar_count,
        edns_version,
        udp_buf_size,
        opt_rdata_index,
        response_rcode,

        unknown = -1
    };

    /**
     * \enum QuestionField
     * \brief Fields in question map.
     */
    enum class QuestionField
    {
        name_index,
        classtype_index,

        unknown = -1
    };

    /**
     * \enum RRField
     * \brief Fields in RR map.
     */
    enum class RRField
    {
        name_index,
        classtype_index,
        ttl,
        rdata_index,

        unknown = -1
    };

    /**
     * \enum QueryResponseExtendedField
     * \brief Fields in query response extended info map.
     */
    enum class QueryResponseExtendedField
    {
        question_index,
        answer_index,
        authority_index,
        additional_index,

        unknown = -1
    };

    /**
     * \enum AddressEventCountField
     * \brief Fields in address event count map.
     */
    enum class AddressEventCountField
    {
        ae_type,
        ae_code,
        ae_address_index,
        ae_transport_flags,
        ae_count,

        unknown = -1
    };

    /**
     * \enum MalformedMessageDataField
     * \brief Fields in malformed message data map.
     */
    enum class MalformedMessageDataField
    {
        server_address_index,
        server_port,
        mm_transport_flags,
        mm_payload,

        unknown = -1
    };

    /**
     * \enum MalformedMessageField
     * \brief Fields in malformed message map.
     */
    enum class MalformedMessageField
    {
        time_offset,
        client_address_index,
        client_port,
        message_data_index,

        unknown = -1
    };

    /**
     * \brief find item in a C array.
     *
     * Compile time searching of a C array.
     *
     * \param arr the C array.
     * \param val value of entry we're looking for.
     * \returns index of matched item.
     * \throws std::logic_error if the item is not in the array.
     */
    template<typename T, std::size_t N, typename V>
    constexpr int find_index(T (&arr)[N], V val, unsigned i = 0)
    {
        return ( i < N )
            ? ( arr[i] == val ) ? i : find_index(arr, val, i + 1)
            : throw std::logic_error("");
    }

    /**
     * \brief find item in 2 C arrays.
     *
     * Compile time searching of 2 C arrays.
     *
     * \param arr1 the first C array.
     * \param arr2 the second C array.
     * \param val value of entry we're looking for.
     * \returns index of matched item if in first array, or -1 - (index
     *          of matched item) if in second array.
     * \throws std::logic_error if the item is not in the array.
     */
    template<typename T, std::size_t N1, std::size_t N2, typename V>
    constexpr int find_index(T (&arr1)[N1], T (&arr2)[N2], V val, unsigned i = 0)
    {
        return ( i < N1 )
            ? ( arr1[i] == val ) ? i : find_index(arr1, arr2, val, i + 1)
            : -1 - find_index(arr2, val);
    }

    /**
     * \brief Map of current file preamble indexes.
     *
     * The index of a entry in the array is the file map value of that entry.
     */
    constexpr FilePreambleField format_10_file_preamble[] = {
        FilePreambleField::major_format_version,
        FilePreambleField::minor_format_version,
        FilePreambleField::private_version,
        FilePreambleField::block_parameters
    };

    /**
     * \brief Map of format 05 file preamble indexes.
     *
     * The index of a entry in the array is the file map value of that entry.
     */
    constexpr FilePreambleField format_05_file_preamble[] = {
        FilePreambleField::major_format_version,
        FilePreambleField::minor_format_version,
        FilePreambleField::private_version,
        FilePreambleField::configuration,
        FilePreambleField::generator_id,
        FilePreambleField::host_id
    };

    /**
     * \brief Map of format 02 file preamble indexes.
     *
     * The index of a entry in the array is the file map value of that entry.
     */
    constexpr FilePreambleField format_02_file_preamble[] = {
        FilePreambleField::format_version,
        FilePreambleField::configuration,
        FilePreambleField::generator_id,
        FilePreambleField::host_id
    };

    /**
     * \brief find map index of preamble fields for current format.
     *
     * \param index the field identifier.
     * \return the field index.
     * \throws std::logic_error if the item isn't specified in the format.
     */
    constexpr int find_file_preamble_index(FilePreambleField index)
    {
        return find_index(format_10_file_preamble, index);
    }

    /**
     * \brief Find preamble field identifier from map index.
     *
     * \param index the map index.
     * \param ver   the format version
     * \returns the field identifier, or <code>unknown</code> if not found.
     */
    FilePreambleField file_preamble_field(unsigned index, FileFormatVersion ver);

    /**
     * \brief Map of current block parameters indexes.
     *
     * The index of a entry in the array is the file map value of that entry.
     */
    constexpr BlockParametersField format_10_block_parameters[] = {
        BlockParametersField::storage_parameters,
        BlockParametersField::collection_parameters
    };

    /**
     * \brief find map index of block parameters fields for current format.
     *
     * \param index the field identifier.
     * \return the field index.
     * \throws std::logic_error if the item isn't specified in the format.
     */
    constexpr int find_block_parameters_index(BlockParametersField index)
    {
        return find_index(format_10_block_parameters, index);
    }

    /**
     * \brief Map of current storage parameters indexes.
     *
     * The index of a entry in the array is the file map value of that entry.
     */
    constexpr StorageParametersField format_10_storage_parameters[] = {
        StorageParametersField::ticks_per_second,
        StorageParametersField::max_block_items,
        StorageParametersField::storage_hints,
        StorageParametersField::opcodes,
        StorageParametersField::rr_types,
        StorageParametersField::storage_flags,
        StorageParametersField::client_address_prefix_ipv4,
        StorageParametersField::client_address_prefix_ipv6,
        StorageParametersField::server_address_prefix_ipv4,
        StorageParametersField::server_address_prefix_ipv6,
        StorageParametersField::sampling_method,
        StorageParametersField::anonymisation_method
    };

    /**
     * \brief find map index of storage parameters fields for current format.
     *
     * \param index the field identifier.
     * \return the field index.
     * \throws std::logic_error if the item isn't specified in the format.
     */
    constexpr int find_storage_parameters_index(StorageParametersField index)
    {
        return find_index(format_10_storage_parameters, index);
    }

    /**
     * \brief Map of current storage hints indexes.
     *
     * The index of a entry in the array is the file map value of that entry.
     */
    constexpr StorageHintsField format_10_storage_hints[] = {
        StorageHintsField::query_response_hints,
        StorageHintsField::query_response_signature_hints,
        StorageHintsField::rr_hints,
        StorageHintsField::other_data_hints
    };

    /**
     * \brief find map index of storage hints fields for current format.
     *
     * \param index the field identifier.
     * \return the field index.
     * \throws std::logic_error if the item isn't specified in the format.
     */
    constexpr int find_storage_hints_index(StorageHintsField index)
    {
        return find_index(format_10_storage_hints, index);
    }

    /**
     * \brief Map of current collection parameters indexes.
     *
     * The index of a entry in the array is the file map value of that entry.
     */
    constexpr CollectionParametersField format_10_collection_parameters[] = {
        CollectionParametersField::query_timeout,
        CollectionParametersField::skew_timeout,
        CollectionParametersField::snaplen,
        CollectionParametersField::promisc,
        CollectionParametersField::interfaces,
        CollectionParametersField::server_addresses,
        CollectionParametersField::vlan_ids,
        CollectionParametersField::filter,
        CollectionParametersField::generator_id,
        CollectionParametersField::host_id
    };

    /**
     * \brief Map of current private (implementation-specific) collection
     * parameters indexes.
     *
     * The index of a entry in the array subtracted from -1 is the map
     * value of that entry.
     */
    constexpr CollectionParametersField format_10_collection_parameters_private[] = {
        CollectionParametersField::dns_port,
    };

    /**
     * \brief find map index of collection parameters fields for current format.
     *
     * \param index the field identifier.
     * \return the field index.
     * \throws std::logic_error if the item isn't specified in the format.
     */
    constexpr int find_collection_parameters_index(CollectionParametersField index)
    {
        return find_index(format_10_collection_parameters, format_10_collection_parameters_private, index);
    }

    /**
     * \brief Map of current configuration indexes.
     *
     * The index of a entry in the array is the file map value of that entry.
     */
    constexpr ConfigurationField current_configuration[] = {
        ConfigurationField::query_timeout,
        ConfigurationField::skew_timeout,
        ConfigurationField::snaplen,
        ConfigurationField::promisc,
        ConfigurationField::interfaces,
        ConfigurationField::vlan_ids,
        ConfigurationField::filter,
        ConfigurationField::query_options,
        ConfigurationField::response_options,
        ConfigurationField::accept_rr_types,
        ConfigurationField::ignore_rr_types,
        ConfigurationField::server_addresses,
        ConfigurationField::max_block_qr_items,
    };

    /**
     * \brief find map index of configuration fields for current format.
     *
     * \param index the field identifier.
     * \return the field index.
     * \throws std::logic_error if the item isn't specified in the format.
     */
    constexpr int find_configuration_index(ConfigurationField index)
    {
        return find_index(current_configuration, index);
    }

    /**
     * \brief Map of current block indexes.
     *
     * The index of a entry in the array is the file map value of that entry.
     */
    constexpr BlockField current_block[] = {
        BlockField::preamble,
        BlockField::statistics,
        BlockField::tables,
        BlockField::queries,
        BlockField::address_event_counts,
        BlockField::malformed_messages,
    };

    /**
     * \brief find map index of block fields for current format.
     *
     * \param index the field identifier.
     * \return the field index.
     * \throws std::logic_error if the item isn't specified in the format.
     */
    constexpr int find_block_index(BlockField index)
    {
        return find_index(current_block, index);
    }

    /**
     * \brief Map of current block preamble indexes.
     *
     * The index of a entry in the array is the file map value of that entry.
     */
    constexpr BlockPreambleField format_10_block_preamble[] = {
        BlockPreambleField::earliest_time,
        BlockPreambleField::block_parameters_index
    };

    /**
     * \brief Map of current block preamble private indexes.
     *
     * The index of a entry in the array subtracted from -1 is the map
     * value of that entry.
     */
    constexpr BlockPreambleField format_10_block_preamble_private[] = {
        BlockPreambleField::compactor_end_time,
        BlockPreambleField::compactor_start_time,
    };

    /**
     * \brief find map index of block preamble fields for current format.
     *
     * \param index the field identifier.
     * \return the field index.
     * \throws std::logic_error if the item isn't specified in the format.
     */
    constexpr int find_block_preamble_index(BlockPreambleField index)
    {
        return find_index(format_10_block_preamble, format_10_block_preamble_private, index);
    }

    /**
     * \brief Map of current block statistics indexes.
     *
     * The index of a entry in the array is the file map value of that entry.
     */
    constexpr BlockStatisticsField format_10_block_statistics[] = {
        BlockStatisticsField::processed_messages,
        BlockStatisticsField::qr_data_items,
        BlockStatisticsField::unmatched_queries,
        BlockStatisticsField::unmatched_responses,
        BlockStatisticsField::discarded_opcode,
        BlockStatisticsField::malformed_items,
    };

    /**
     * \brief Map of current private (implementation-specific) block
     * statistics indexes.
     *
     * The index of a entry in the array subtracted from -1 is the map
     * value of that entry.
     */
    constexpr BlockStatisticsField format_10_block_statistics_private[] = {
        BlockStatisticsField::compactor_non_dns_packets,
        BlockStatisticsField::compactor_out_of_order_packets,
        BlockStatisticsField::compactor_missing_pairs,
        BlockStatisticsField::compactor_missing_packets,
        BlockStatisticsField::compactor_missing_non_dns,
        BlockStatisticsField::compactor_packets,
        BlockStatisticsField::compactor_missing_received,
        BlockStatisticsField::compactor_discarded_packets,
        BlockStatisticsField::compactor_missing_matcher,
        BlockStatisticsField::pcap_packets,
        BlockStatisticsField::pcap_missing_if,
        BlockStatisticsField::pcap_missing_os,
    };

    /**
     * \brief find map index of block statistics fields for current format.
     *
     * \param index the field identifier.
     * \return the field index.
     * \throws std::logic_error if the item isn't specified in the format.
     */
    constexpr int find_block_statistics_index(BlockStatisticsField index)
    {
        return find_index(format_10_block_statistics, format_10_block_statistics_private, index);
    }

    /**
     * \brief Map of current block tables indexes.
     *
     * The index of a entry in the array is the file map value of that entry.
     */
    constexpr BlockTablesField current_block_tables[] = {
        BlockTablesField::ip_address,
        BlockTablesField::classtype,
        BlockTablesField::name_rdata,
        BlockTablesField::query_response_signature,
        BlockTablesField::question_list,
        BlockTablesField::question_rr,
        BlockTablesField::rr_list,
        BlockTablesField::rr,
        BlockTablesField::malformed_message_data,
    };

    /**
     * \brief find map index of block tables fields for current format.
     *
     * \param index the field identifier.
     * \return the field index.
     * \throws std::logic_error if the item isn't specified in the format.
     */
    constexpr int find_block_tables_index(BlockTablesField index)
    {
        return find_index(current_block_tables, index);
    }

    /**
     * \brief Map of current class/type indexes.
     *
     * The index of a entry in the array is the file map value of that entry.
     */
    constexpr ClassTypeField current_class_type[] = {
        ClassTypeField::type_id,
        ClassTypeField::class_id,
    };

    /**
     * \brief find map index of class/type fields for current format.
     *
     * \param index the field identifier.
     * \return the field index.
     * \throws std::logic_error if the item isn't specified in the format.
     */
    constexpr int find_class_type_index(ClassTypeField index)
    {
        return find_index(current_class_type, index);
    }

    /**
     * \brief Map of current question indexes.
     *
     * The index of a entry in the array is the file map value of that entry.
     */
    constexpr QuestionField current_question[] = {
        QuestionField::name_index,
        QuestionField::classtype_index,
    };

    /**
     * \brief find map index of question fields for current format.
     *
     * \param index the field identifier.
     * \return the field index.
     * \throws std::logic_error if the item isn't specified in the format.
     */
    constexpr int find_question_index(QuestionField index)
    {
        return find_index(current_question, index);
    }

    /**
     * \brief Map of current RR indexes.
     *
     * The index of a entry in the array is the file map value of that entry.
     */
    constexpr RRField current_rr[] = {
        RRField::name_index,
        RRField::classtype_index,
        RRField::ttl,
        RRField::rdata_index,
    };

    /**
     * \brief find map index of RR fields for current format.
     *
     * \param index the field identifier.
     * \return the field index.
     * \throws std::logic_error if the item isn't specified in the format.
     */
    constexpr int find_rr_index(RRField index)
    {
        return find_index(current_rr, index);
    }

    /**
     * \brief Map of format 1.0 query response signature indexes.
     *
     * The index of a entry in the array is the file map value of that entry.
     */
    constexpr QueryResponseSignatureField format_10_query_response_signature[] = {
        QueryResponseSignatureField::server_address_index,
        QueryResponseSignatureField::server_port,
        QueryResponseSignatureField::qr_transport_flags,
        QueryResponseSignatureField::qr_type,
        QueryResponseSignatureField::qr_sig_flags,
        QueryResponseSignatureField::query_opcode,
        QueryResponseSignatureField::qr_dns_flags,
        QueryResponseSignatureField::query_rcode,
        QueryResponseSignatureField::query_classtype_index,
        QueryResponseSignatureField::query_qd_count,
        QueryResponseSignatureField::query_an_count,
        QueryResponseSignatureField::query_ns_count,
        QueryResponseSignatureField::query_ar_count,
        QueryResponseSignatureField::edns_version,
        QueryResponseSignatureField::udp_buf_size,
        QueryResponseSignatureField::opt_rdata_index,
        QueryResponseSignatureField::response_rcode,
    };

    /**
     * \brief find map index of query response signature fields for current format.
     *
     * \param index the field identifier.
     * \return the field index.
     * \throws std::logic_error if the item isn't specified in the format.
     */
    constexpr int find_query_response_signature_index(QueryResponseSignatureField index)
    {
        return find_index(format_10_query_response_signature, index);
    }

    /**
     * \brief Map of format 1.0 query response indexes.
     *
     * The index of a entry in the array is the file map value of that entry.
     */
    constexpr QueryResponseField format_10_query_response[] = {
        QueryResponseField::time_offset,
        QueryResponseField::client_address_index,
        QueryResponseField::client_port,
        QueryResponseField::transaction_id,
        QueryResponseField::qr_signature_index,
        QueryResponseField::client_hoplimit,
        QueryResponseField::response_delay,
        QueryResponseField::query_name_index,
        QueryResponseField::query_size,
        QueryResponseField::response_size,
        QueryResponseField::response_processing_data,
        QueryResponseField::query_extended,
        QueryResponseField::response_extended,
    };

    /**
     * \brief find map index of query response fields for current format.
     *
     * \param index the field identifier.
     * \return the field index.
     * \throws std::logic_error if the item isn't specified in the format.
     */
    constexpr int find_query_response_index(QueryResponseField index)
    {
        return find_index(format_10_query_response, index);
    }

    /**
     * \brief Map of current query response extended information indexes.
     *
     * The index of a entry in the array is the file map value of that entry.
     */
    constexpr QueryResponseExtendedField current_query_response_extended[] = {
        QueryResponseExtendedField::question_index,
        QueryResponseExtendedField::answer_index,
        QueryResponseExtendedField::authority_index,
        QueryResponseExtendedField::additional_index,
    };

    /**
     * \brief find map index of query response extended information
     *        fields for current format.
     *
     * \param index the field identifier.
     * \return the field index.
     * \throws std::logic_error if the item isn't specified in the format.
     */
    constexpr int find_query_response_extended_index(QueryResponseExtendedField index)
    {
        return find_index(current_query_response_extended, index);
    }

    /**
     * \brief Map of current address event count indexes.
     *
     * The index of a entry in the array is the file map value of that entry.
     */
    constexpr AddressEventCountField format_10_address_event_count[] = {
        AddressEventCountField::ae_type,
        AddressEventCountField::ae_code,
        AddressEventCountField::ae_address_index,
        AddressEventCountField::ae_transport_flags,
        AddressEventCountField::ae_count,
    };

    /**
     * \brief find map index of address event count fields for current format.
     *
     * \param index the field identifier.
     * \return the field index.
     * \throws std::logic_error if the item isn't specified in the format.
     */
    constexpr int find_address_event_count_index(AddressEventCountField index)
    {
        return find_index(format_10_address_event_count, index);
    }

    /**
     * \brief Map of current malformed message data indexes.
     *
     * The index of a entry in the array is the file map value of that entry.
     */
    constexpr MalformedMessageDataField format_10_malformed_message_data[] = {
        MalformedMessageDataField::server_address_index,
        MalformedMessageDataField::server_port,
        MalformedMessageDataField::mm_transport_flags,
        MalformedMessageDataField::mm_payload,
    };

    /**
     * \brief find map index of malformed message data fields for current format.
     *
     * \param index the field identifier.
     * \return the field index.
     * \throws std::logic_error if the item isn't specified in the format.
     */
    constexpr int find_malformed_message_data_index(MalformedMessageDataField index)
    {
        return find_index(format_10_malformed_message_data, index);
    }

    /**
     * \brief Map of current malformed message indexes.
     *
     * The index of a entry in the array is the file map value of that entry.
     */
    constexpr MalformedMessageField format_10_malformed_message[] = {
        MalformedMessageField::time_offset,
        MalformedMessageField::client_address_index,
        MalformedMessageField::client_port,
        MalformedMessageField::message_data_index,
    };

    /**
     * \brief find map index of malformed message fields for current format.
     *
     * \param index the field identifier.
     * \return the field index.
     * \throws std::logic_error if the item isn't specified in the format.
     */
    constexpr int find_malformed_message_index(MalformedMessageField index)
    {
        return find_index(format_10_malformed_message, index);
    }

    /**
     * \brief Calculate the DNS flags for a Query/Response.
     *
     * The DNS flag value composed from the DNSFlag enum.
     *
     * \param qr    the Query/Response.
     * \return DNS flags value.
     */
    uint16_t dns_flags(const QueryResponse& qr);

    /**
     * \brief Set the basic DNS flags in a query or response message.
     *
     * Note this does not set the query DO flag.
     *
     * \param msg   the message.
     * \param flags DNS flags value.
     * \param query `true` if the message is a query.
     */
    void set_dns_flags(DNSMessage& msg, uint16_t flags, bool query);

    /**
     * \brief Convert possibly older format DNS flags to current.
     *
     * \param flags        DNS flags value.
     * \param from_version the file format version.
     */
    uint16_t convert_dns_flags(uint16_t flags, FileFormatVersion version);

    /**
     * \brief Convert possibly older format QR flags to current.
     *
     * \param flags        QR flags value.
     * \param from_version the file format version.
     */
    uint8_t convert_qr_flags(uint8_t flags, FileFormatVersion version);

    /**
     * \brief Calculate the Transport flags for a Query/Response.
     *
     * The Transport flag value is composed from the TransportFlags enum.
     *
     * \param qr    the Query/Response.
     * \return transport flags value.
     */
    uint8_t transport_flags(const QueryResponse& qr);

    /**
     * \brief Convert possibly older format transport flags to current.
     *
     * \param flags        transport flags value.
     * \param from_version the file format version.
     */
    uint8_t convert_transport_flags(uint8_t flags, FileFormatVersion version);

    /**
     * \brief Calculate the transaction type for a Query/Response.
     *
     * \param qr    the Query/Response.
     * \return transaction type value.
     */
    boost::optional<uint8_t> transaction_type(const QueryResponse& qr);

    /**
     * \class FileVersionFields
     * \brief Provide runtime methods for mapping file map key indexes to
     *        field values based on file version.
     */
    class FileVersionFields
    {
    public:
        /**
         * Default constructor.
         *
         * Build objecting mapping current (latest) file version.
         */
        FileVersionFields();

        /**
         * Constructor.
         *
         * Build objecting mapping idepntified file version.
         *
         * \param major_version   file major version.
         * \param minor_version   file minor version.
         * \param private_version file private version.
         */
        FileVersionFields(unsigned major_version, unsigned minor_version,
                          unsigned private_version);

        /**
         * \brief Return configuration field for given map index.
         *
         * \param index the map index read from file.
         * \returns field identifier.
         */
        ConfigurationField configuration_field(unsigned index) const;

        /**
         * \brief Return block field for given map index.
         *
         * \param index the map index read from file.
         * \returns field identifier.
         */
        BlockField block_field(unsigned index) const;

        /**
         * \brief Return block preamble field for given map index.
         *
         * \param index the map index read from file.
         * \returns field identifier.
         */
        BlockPreambleField block_preamble_field(int index) const;

        /**
         * \brief Return block statistics field for given map index.
         *
         * \param index the map index read from file.
         * \returns field identifier.
         */
        BlockStatisticsField block_statistics_field(int index) const;

        /**
         * \brief Return block tables field for given map index.
         *
         * \param index the map index read from file.
         * \returns field identifier.
         */
        BlockTablesField block_tables_field(unsigned index) const;

        /**
         * \brief Return query response field for given map index.
         *
         * \param index the map index read from file.
         * \returns field identifier.
         */
        QueryResponseField query_response_field(unsigned index) const;

        /**
         * \brief Return class type field for given map index.
         *
         * \param index the map index read from file.
         * \returns field identifier.
         */
        ClassTypeField class_type_field(unsigned index) const;

        /**
         * \brief Return query response signature field for given map index.
         *
         * \param index the map index read from file.
         * \returns field identifier.
         */
        QueryResponseSignatureField query_response_signature_field(unsigned index) const;

        /**
         * \brief Return question field for given map index.
         *
         * \param index the map index read from file.
         * \returns field identifier.
         */
        QuestionField question_field(unsigned index) const;

        /**
         * \brief Return RR field for given map index.
         *
         * \param index the map index read from file.
         * \returns field identifier.
         */
        RRField rr_field(unsigned index) const;

        /**
         * \brief Return query response extended information field
         *        for given map index.
         *
         * \param index the map index read from file.
         * \returns field identifier.
         */
        QueryResponseExtendedField query_response_extended_field(unsigned index) const;

        /**
         * \brief Return address event count field for given map index.
         *
         * \param index the map index read from file.
         * \returns field identifier.
         */
        AddressEventCountField address_event_count_field(unsigned index) const;

        /**
         * \brief Return storage hints field for given map index.
         *
         * \param index the map index read from file.
         * \returns field identifier.
         */
        StorageHintsField storage_hints_field(unsigned index) const;

        /**
         * \brief Return storage parameters field for given map index.
         *
         * \param index the map index read from file.
         * \returns field identifier.
         */
        StorageParametersField storage_parameters_field(unsigned index) const;

        /**
         * \brief Return collection parameters field for given map index.
         *
         * \param index the map index read from file.
         * \returns field identifier.
         */
        CollectionParametersField collection_parameters_field(int index) const;

        /**
         * \brief Return block parameters field for given map index.
         *
         * \param index the map index read from file.
         * \returns field identifier.
         */
        BlockParametersField block_parameters_field(unsigned index) const;

        /**
         * \brief Return malformed message data field for given map index.
         *
         * \param index the map index read from file.
         * \returns field identifier.
         */
        MalformedMessageDataField malformed_message_data_field(unsigned index) const;

        /**
         * \brief Return malformed message field for given map index.
         *
         * \param index the map index read from file.
         * \returns field identifier.
         */
        MalformedMessageField malformed_message_field(unsigned index) const;

    private:
        /**
         * \brief configuration index map.
         */
        std::vector<ConfigurationField> configuration_;

        /**
         * \brief block index map.
         */
        std::vector<BlockField> block_;

        /**
         * \brief block preamble index map.
         */
        std::vector<BlockPreambleField> block_preamble_;

        /**
         * \brief block preamble private index map.
         */
        std::vector<BlockPreambleField> block_preamble_private_;

        /**
         * \brief block statistics index map.
         */
        std::vector<BlockStatisticsField> block_statistics_;

        /**
         * \brief block statistics private index map.
         */
        std::vector<BlockStatisticsField> block_statistics_private_;

        /**
         * \brief block table index map.
         */
        std::vector<BlockTablesField> block_tables_;

        /**
         * \brief query response index map.
         */
        std::vector<QueryResponseField> query_response_;

        /**
         * \brief class/type index map.
         */
        std::vector<ClassTypeField> class_type_;

        /**
         * \brief query response signature index map.
         */
        std::vector<QueryResponseSignatureField> query_response_signature_;

        /**
         * \brief question index map.
         */
        std::vector<QuestionField> question_;

        /**
         * \brief RR index map.
         */
        std::vector<RRField> rr_;

        /**
         * \brief query response extended information index map.
         */
        std::vector<QueryResponseExtendedField> query_response_extended_;

        /**
         * \brief address event count index map.
         */
        std::vector<AddressEventCountField> address_event_count_;

        /**
         * \brief storage hints index map.
         */
        std::vector<StorageHintsField> storage_hints_;

        /**
         * \brief storage parameters index map.
         */
        std::vector<StorageParametersField> storage_parameters_;

        /**
         * \brief collection parameters index map.
         */
        std::vector<CollectionParametersField> collection_parameters_;

        /**
         * \brief collection parameters private index map.
         */
        std::vector<CollectionParametersField> collection_parameters_private_;

        /**
         * \brief block parameters index map.
         */
        std::vector<BlockParametersField> block_parameters_;

        /**
         * \brief malformed message data index map.
         */
        std::vector<MalformedMessageDataField> malformed_message_data_;

        /**
         * \brief malformed message index map.
         */
        std::vector<MalformedMessageField> malformed_message_;
    };
};

#endif
