/*
 * Copyright 2016-2017, 2019 Internet Corporation for Assigned Names and Numbers.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Developed by Sinodun IT (www.sinodun.com)
 */

#include <cstddef>
#include <stdexcept>

#include "blockcbor.hpp"
#include "blockcbordata.hpp"

namespace block_cbor {
    /**
     * \brief Fixed file format string.
     */
    const std::string& FILE_FORMAT_ID = "C-DNS";

    /**
     * \brief Current output format major version.
     */
    const unsigned FILE_FORMAT_10_MAJOR_VERSION = 1;

    /**
     * \brief Current output format minor version.
     */
    const unsigned FILE_FORMAT_10_MINOR_VERSION = 0;

    /**
     * \brief Current output format private version.
     */
    const unsigned FILE_FORMAT_10_PRIVATE_VERSION = 1;

    /**
     * \brief Current output format major version.
     */
    const unsigned FILE_FORMAT_05_MAJOR_VERSION = 0;

    /**
     * \brief Current output format minor version.
     */
    const unsigned FILE_FORMAT_05_MINOR_VERSION = 5;

    /**
     * \brief Pre-draft format id.
     */
    const std::string& FILE_FORMAT_02_ID = "DNS-STAT";

    /**
     * \brief Pre-draft version ID.
     */
    const unsigned FILE_FORMAT_02_VERSION = 2;

    /**
     ** Old formats tables - format 0.5.
     **/

    /**
     * \brief 0.5 block preamble
     */
    const std::vector<BlockPreambleField> format_05_block_preamble = {
        BlockPreambleField::unknown,
        BlockPreambleField::earliest_time
    };

    /**
     * \brief 0.5 block statistics
     */
    const std::vector<BlockStatisticsField> format_05_block_statistics = {
        BlockStatisticsField::processed_messages,
        BlockStatisticsField::qr_data_items,
        BlockStatisticsField::unmatched_queries,
        BlockStatisticsField::unmatched_responses,
        BlockStatisticsField::malformed_items,
        BlockStatisticsField::partially_malformed_packets,
        BlockStatisticsField::unknown,
        BlockStatisticsField::unknown,
        BlockStatisticsField::unknown,
        BlockStatisticsField::unknown,
        BlockStatisticsField::compactor_non_dns_packets,
        BlockStatisticsField::compactor_out_of_order_packets,
        BlockStatisticsField::compactor_missing_pairs,
        BlockStatisticsField::compactor_missing_packets,
        BlockStatisticsField::compactor_missing_non_dns,
    };

    /**
     * \brief 0.5 query response signature
     */
    const std::vector<QueryResponseSignatureField> format_05_query_response_signature = {
        QueryResponseSignatureField::server_address_index,
        QueryResponseSignatureField::server_port,
        QueryResponseSignatureField::qr_transport_flags,
        QueryResponseSignatureField::qr_sig_flags,
        QueryResponseSignatureField::query_opcode,
        QueryResponseSignatureField::qr_dns_flags,
        QueryResponseSignatureField::query_rcode,
        QueryResponseSignatureField::query_classtype_index,
        QueryResponseSignatureField::query_qd_count,
        QueryResponseSignatureField::query_an_count,
        QueryResponseSignatureField::query_ar_count,
        QueryResponseSignatureField::query_ns_count,
        QueryResponseSignatureField::edns_version,
        QueryResponseSignatureField::udp_buf_size,
        QueryResponseSignatureField::opt_rdata_index,
        QueryResponseSignatureField::response_rcode,
    };

    /**
     * \brief 0.5 query response
     */
    const std::vector<QueryResponseField> format_05_query_response = {
        QueryResponseField::time_offset,
        QueryResponseField::time_pseconds,
        QueryResponseField::client_address_index,
        QueryResponseField::client_port,
        QueryResponseField::transaction_id,
        QueryResponseField::qr_signature_index,
        QueryResponseField::client_hoplimit,
        QueryResponseField::response_delay,
        QueryResponseField::response_delay_pseconds,
        QueryResponseField::query_name_index,
        QueryResponseField::query_size,
        QueryResponseField::response_size,
        QueryResponseField::query_extended,
        QueryResponseField::response_extended,
    };

    /**
     ** Old formats tables - format 0.2.
     **/

    /**
     * \brief 0.2 statistics.
     */
    const std::vector<BlockStatisticsField> format_02_block_statistics = {
        BlockStatisticsField::processed_messages,
        BlockStatisticsField::qr_data_items,
        BlockStatisticsField::unmatched_queries,
        BlockStatisticsField::unmatched_responses,
        BlockStatisticsField::malformed_items,
        BlockStatisticsField::compactor_non_dns_packets,
        BlockStatisticsField::compactor_out_of_order_packets,
        BlockStatisticsField::compactor_missing_pairs,
        BlockStatisticsField::compactor_missing_packets,
        BlockStatisticsField::compactor_missing_non_dns,
    };

    /**
     * \brief 0.2 query/response.
     */
    const std::vector<QueryResponseField> format_02_query_response = {
        QueryResponseField::time_offset,
        QueryResponseField::client_address_index,
        QueryResponseField::client_port,
        QueryResponseField::transaction_id,
        QueryResponseField::qr_signature_index,
        QueryResponseField::client_hoplimit,
        QueryResponseField::response_delay,
        QueryResponseField::query_name_index,
        QueryResponseField::response_size,
        QueryResponseField::query_extended,
        QueryResponseField::response_extended,
        QueryResponseField::query_size,
    };

    /**
     * \brief get the number of elements in a C array.
     */
    template<typename T, std::size_t N>
    constexpr std::size_t countof(const T (&)[N]) noexcept
    {
        return N;
    }

    FilePreambleField file_preamble_field(unsigned index, FileFormatVersion ver)
    {
        std::size_t arrsize;
        const FilePreambleField* arr;

        switch(ver)
        {
        case FileFormatVersion::format_02:
            arr = format_02_file_preamble;
            arrsize = countof(format_02_file_preamble);
            break;

        case FileFormatVersion::format_05:
            arr = format_05_file_preamble;
            arrsize = countof(format_05_file_preamble);
            break;

        default:
            arr = format_10_file_preamble;
            arrsize = countof(format_10_file_preamble);
            break;
        }

        if ( index >= arrsize )
            return FilePreambleField::unknown;
        else
            return arr[index];
    }

    FileVersionFields::FileVersionFields()
        : configuration_(current_configuration, current_configuration + countof(current_configuration)),
          block_(current_block, current_block + countof(current_block)),
          block_preamble_(format_10_block_preamble, format_10_block_preamble + countof(format_10_block_preamble)),
          block_statistics_(format_10_block_statistics, format_10_block_statistics + countof(format_10_block_statistics)),
          block_statistics_private_(format_10_block_statistics_private, format_10_block_statistics_private + countof(format_10_block_statistics_private)),
          block_tables_(current_block_tables, current_block_tables + countof(current_block_tables)),
          query_response_(format_10_query_response, format_10_query_response + countof(format_10_query_response)),
          class_type_(current_class_type, current_class_type + countof(current_class_type)),
          query_response_signature_(format_10_query_response_signature, format_10_query_response_signature + countof(format_10_query_response_signature)),
          question_(current_question, current_question + countof(current_question)),
          rr_(current_rr, current_rr + countof(current_rr)),
          query_response_extended_(current_query_response_extended, current_query_response_extended + countof(current_query_response_extended)),
          address_event_count_(current_address_event_count, current_address_event_count + countof(current_address_event_count)),
          storage_hints_(format_10_storage_hints, format_10_storage_hints + countof(format_10_storage_hints)),
          storage_parameters_(format_10_storage_parameters, format_10_storage_parameters + countof(format_10_storage_parameters)),
          collection_parameters_(format_10_collection_parameters, format_10_collection_parameters + countof(format_10_collection_parameters)),
          block_parameters_(format_10_block_parameters, format_10_block_parameters + countof(format_10_block_parameters))
    {
    }

    FileVersionFields::FileVersionFields(unsigned major_version,
                                         unsigned minor_version,
                                         unsigned private_version)
        : FileVersionFields()
    {
        // If the current version, we're done.
        if ( major_version == FILE_FORMAT_10_MAJOR_VERSION &&
             minor_version == FILE_FORMAT_10_MINOR_VERSION )
            return;

        block_statistics_private_.clear();

        if ( major_version == FILE_FORMAT_05_MAJOR_VERSION &&
             minor_version == FILE_FORMAT_05_MINOR_VERSION )
        {
            block_preamble_ = format_05_block_preamble;
            block_statistics_ = format_05_block_statistics;
            query_response_signature_ = format_05_query_response_signature;
            query_response_ = format_05_query_response;
            return;
        }

        if ( major_version == 0 && minor_version == FILE_FORMAT_02_VERSION )
        {
            block_preamble_ = format_05_block_preamble;
            block_statistics_ = format_02_block_statistics;
            query_response_ = format_02_query_response;
            query_response_signature_ = format_05_query_response_signature;
            return;
        }

        throw cbor_file_format_error("Unknown file format version");
    }

    ConfigurationField FileVersionFields::configuration_field(int index) const
    {
        if ( index < configuration_.size() )
            return configuration_[index];
        else
            return ConfigurationField::unknown;
    }

    BlockField FileVersionFields::block_field(int index) const
    {
        if ( index < block_.size() )
            return block_[index];
        else
            return BlockField::unknown;
    }

    BlockPreambleField FileVersionFields::block_preamble_field(int index) const
    {
        if ( index < block_preamble_.size() )
            return block_preamble_[index];
        else
            return BlockPreambleField::unknown;
    }

    BlockStatisticsField FileVersionFields::block_statistics_field(int index) const
    {
        if ( index < 0 && index > -1 - block_statistics_private_.size() )
            return block_statistics_private_[-index - 1];
        else if ( index < block_statistics_.size() )
            return block_statistics_[index];
        else
            return BlockStatisticsField::unknown;
    }

    BlockTablesField FileVersionFields::block_tables_field(int index) const
    {
        if ( index < block_tables_.size() )
            return block_tables_[index];
        else
            return BlockTablesField::unknown;
    }

    QueryResponseField FileVersionFields::query_response_field(int index) const
    {
        if ( index < query_response_.size() )
            return query_response_[index];
        else
            return QueryResponseField::unknown;
    }

    ClassTypeField FileVersionFields::class_type_field(int index) const
    {
        if ( index < class_type_.size() )
            return class_type_[index];
        else
            return ClassTypeField::unknown;
    }

    QueryResponseSignatureField FileVersionFields::query_response_signature_field(int index) const
    {
        if ( index < query_response_signature_.size() )
            return query_response_signature_[index];
        else
            return QueryResponseSignatureField::unknown;
    }

    QuestionField FileVersionFields::question_field(int index) const
    {
        if ( index < question_.size() )
            return question_[index];
        else
            return QuestionField::unknown;
    }

    RRField FileVersionFields::rr_field(int index) const
    {
        if ( index < rr_.size() )
            return rr_[index];
        else
            return RRField::unknown;
    }

    QueryResponseExtendedField FileVersionFields::query_response_extended_field(int index) const
    {
        if ( index < query_response_extended_.size() )
            return query_response_extended_[index];
        else
            return QueryResponseExtendedField::unknown;
    }

    AddressEventCountField FileVersionFields::address_event_count_field(int index) const
    {
        if ( index < address_event_count_.size() )
            return address_event_count_[index];
        else
            return AddressEventCountField::unknown;
    }

    StorageHintsField FileVersionFields::storage_hints_field(int index) const
    {
        if ( index < storage_hints_.size() )
            return storage_hints_[index];
        else
            return StorageHintsField::unknown;
    }

    StorageParametersField FileVersionFields::storage_parameters_field(int index) const
    {
        if ( index < storage_parameters_.size() )
            return storage_parameters_[index];
        else
            return StorageParametersField::unknown;
    }

    CollectionParametersField FileVersionFields::collection_parameters_field(int index) const
    {
        if ( index < collection_parameters_.size() )
            return collection_parameters_[index];
        else
            return CollectionParametersField::unknown;
    }

    BlockParametersField FileVersionFields::block_parameters_field(int index) const
    {
        if ( index < block_parameters_.size() )
            return block_parameters_[index];
        else
            return BlockParametersField::unknown;
    }
};
