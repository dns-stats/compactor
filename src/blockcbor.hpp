/*
 * Copyright 2016-2017 Internet Corporation for Assigned Names and Numbers.
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

namespace block_cbor {
    /**
     * \brief Fixed file format string.
     */
    extern const std::string& FILE_FORMAT_ID;

    /**
     * \brief Current output format major version.
     */
    extern const unsigned FILE_FORMAT_MAJOR_VERSION;

    /**
     * \brief Current output format minor version.
     */
    extern const unsigned FILE_FORMAT_MINOR_VERSION;

    /**
     * \brief Fixed file format string.
     */
    extern const std::string& OLD_FILE_FORMAT_ID;

    /**
     * \brief Old output format version.
     *
     * This is assigned to the format minor version,
     * with a major format version of 0.
     */
    extern const unsigned OLD_FILE_FORMAT_VERSION;

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
        query_signature,
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
        // Obsolete fields.
        format_version,

        // Current fields.
        major_format_version,
        minor_format_version,
        private_version,
        configuration,
        generator_id,
        host_id,

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

        unknown = -1
    };

    /**
     * \enum BlockPreambleField
     * \brief Fields in block preamble map.
     */
    enum class BlockPreambleField
    {
        earliest_time,

        unknown = -1
    };

    /**
     * \enum BlockStatisticsField
     * \brief Fields in block statistics map.
     */
    enum class BlockStatisticsField
    {
        total_packets,
        total_pairs,
        unmatched_queries,
        unmatched_responses,
        completely_malformed_packets,
        partially_malformed_packets,
        compactor_non_dns_packets,
        compactor_out_of_order_packets,
        compactor_missing_pairs,
        compactor_missing_packets,
        compactor_missing_non_dns,

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
        query_signature,
        question_list,
        question_rr,
        rr_list,
        rr,

        unknown = -1
    };

    /**
     * \enum QueryResponseField
     * \brief Fields in query response map.
     */
    enum class QueryResponseField
    {
        time_useconds,
        time_pseconds,
        client_address_index,
        client_port,
        transaction_id,
        query_signature_index,
        client_hoplimit,
        delay_useconds,
        delay_pseconds,
        query_name_index,
        query_size,
        response_size,
        query_extended,
        response_extended,

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
     * \enum QuerySignatureField
     * \brief Fields in query signature map.
     */
    enum class QuerySignatureField
    {
        server_address_index,
        server_port,
        transport_flags,
        qr_sig_flags,
        query_opcode,
        qr_dns_flags,
        query_rcode,
        query_classtype_index,
        query_qd_count,
        query_an_count,
        query_ar_count,
        query_ns_count,
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
        ae_count,

        unknown = -1
    };

    /**
     * \brief find item in a C array.
     *
     * Compile time searching of a C array.
     *
     * \param begin pointer to first item of array.
     * \param end   pointer to end of array, one beyond the last item.
     * \param val   value of entry we're looking for.
     * \returns pointer to matched item.
     * \throws std::logic_error if the item is not in the array.
     */
    template<typename T, typename V>
    constexpr T* find_index_item(T* begin, T* end, V val)
    {
        return ( begin != end ) ? ( *begin == val ) ? begin : find_index_item(begin + 1, end, val ) : throw std::logic_error("");
    }

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
    constexpr unsigned find_index(T (&arr)[N], V val)
    {
        return find_index_item(arr, arr + N, val) - arr;
    }

    /**
     * \brief Map of current file preamble indexes.
     *
     * The index of a entry in the array is the file map value of that entry.
     */
    constexpr FilePreambleField current_file_preamble[] = {
        FilePreambleField::major_format_version,
        FilePreambleField::minor_format_version,
        FilePreambleField::private_version,
        FilePreambleField::configuration,
        FilePreambleField::generator_id,
        FilePreambleField::host_id
    };

    /**
     * \brief Map of pre-draft file preamble indexes.
     *
     * The index of a entry in the array is the file map value of that entry.
     */
    constexpr FilePreambleField old_file_preamble[] = {
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
     * \throws std::logic_error if the item is specified in the format.
     */
    constexpr unsigned find_file_preamble_index(FilePreambleField index)
    {
        return find_index(current_file_preamble, index);
    }

    /**
     * \brief Find preamble field identifier from map index.
     *
     * \param index the map index.
     * \param old   <code>true</code> if the preamble is pre-draft.
     * \returns the field identifier, or <code>unknown</code> if not found.
     */
    FilePreambleField file_preamble_field(unsigned index, bool old);

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
     * \throws std::logic_error if the item is specified in the format.
     */
    constexpr unsigned find_configuration_index(ConfigurationField index)
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
    };

    /**
     * \brief find map index of block fields for current format.
     *
     * \param index the field identifier.
     * \return the field index.
     * \throws std::logic_error if the item is specified in the format.
     */
    constexpr unsigned find_block_index(BlockField index)
    {
        return find_index(current_block, index);
    }

    /**
     * \brief Map of current block preamble indexes.
     *
     * The index of a entry in the array is the file map value of that entry.
     */
    constexpr BlockPreambleField current_block_preamble[] = {
        BlockPreambleField::unknown,
        BlockPreambleField::earliest_time,
    };

    /**
     * \brief find map index of block preamble fields for current format.
     *
     * \param index the field identifier.
     * \return the field index.
     * \throws std::logic_error if the item is specified in the format.
     */
    constexpr unsigned find_block_preamble_index(BlockPreambleField index)
    {
        return find_index(current_block_preamble, index);
    }

    /**
     * \brief Map of current block statistics indexes.
     *
     * The index of a entry in the array is the file map value of that entry.
     */
    constexpr BlockStatisticsField current_block_statistics[] = {
        BlockStatisticsField::total_packets,
        BlockStatisticsField::total_pairs,
        BlockStatisticsField::unmatched_queries,
        BlockStatisticsField::unmatched_responses,
        BlockStatisticsField::completely_malformed_packets,
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
     * \brief find map index of block statistics fields for current format.
     *
     * \param index the field identifier.
     * \return the field index.
     * \throws std::logic_error if the item is specified in the format.
     */
    constexpr unsigned find_block_statistics_index(BlockStatisticsField index)
    {
        return find_index(current_block_statistics, index);
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
        BlockTablesField::query_signature,
        BlockTablesField::question_list,
        BlockTablesField::question_rr,
        BlockTablesField::rr_list,
        BlockTablesField::rr,
    };

    /**
     * \brief find map index of block tables fields for current format.
     *
     * \param index the field identifier.
     * \return the field index.
     * \throws std::logic_error if the item is specified in the format.
     */
    constexpr unsigned find_block_tables_index(BlockTablesField index)
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
     * \throws std::logic_error if the item is specified in the format.
     */
    constexpr unsigned find_class_type_index(ClassTypeField index)
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
     * \throws std::logic_error if the item is specified in the format.
     */
    constexpr unsigned find_question_index(QuestionField index)
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
     * \throws std::logic_error if the item is specified in the format.
     */
    constexpr unsigned find_rr_index(RRField index)
    {
        return find_index(current_rr, index);
    }

    /**
     * \brief Map of current query signature indexes.
     *
     * The index of a entry in the array is the file map value of that entry.
     */
    constexpr QuerySignatureField current_query_signature[] = {
        QuerySignatureField::server_address_index,
        QuerySignatureField::server_port,
        QuerySignatureField::transport_flags,
        QuerySignatureField::qr_sig_flags,
        QuerySignatureField::query_opcode,
        QuerySignatureField::qr_dns_flags,
        QuerySignatureField::query_rcode,
        QuerySignatureField::query_classtype_index,
        QuerySignatureField::query_qd_count,
        QuerySignatureField::query_an_count,
        QuerySignatureField::query_ar_count,
        QuerySignatureField::query_ns_count,
        QuerySignatureField::edns_version,
        QuerySignatureField::udp_buf_size,
        QuerySignatureField::opt_rdata_index,
        QuerySignatureField::response_rcode,
    };

    /**
     * \brief find map index of query signature fields for current format.
     *
     * \param index the field identifier.
     * \return the field index.
     * \throws std::logic_error if the item is specified in the format.
     */
    constexpr unsigned find_query_signature_index(QuerySignatureField index)
    {
        return find_index(current_query_signature, index);
    }

    /**
     * \brief Map of current query response indexes.
     *
     * The index of a entry in the array is the file map value of that entry.
     */
    constexpr QueryResponseField current_query_response[] = {
        QueryResponseField::time_useconds,
        QueryResponseField::time_pseconds,
        QueryResponseField::client_address_index,
        QueryResponseField::client_port,
        QueryResponseField::transaction_id,
        QueryResponseField::query_signature_index,
        QueryResponseField::client_hoplimit,
        QueryResponseField::delay_useconds,
        QueryResponseField::delay_pseconds,
        QueryResponseField::query_name_index,
        QueryResponseField::query_size,
        QueryResponseField::response_size,
        QueryResponseField::query_extended,
        QueryResponseField::response_extended,
    };

    /**
     * \brief find map index of query response fields for current format.
     *
     * \param index the field identifier.
     * \return the field index.
     * \throws std::logic_error if the item is specified in the format.
     */
    constexpr unsigned find_query_response_index(QueryResponseField index)
    {
        return find_index(current_query_response, index);
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
     * \throws std::logic_error if the item is specified in the format.
     */
    constexpr unsigned find_query_response_extended_index(QueryResponseExtendedField index)
    {
        return find_index(current_query_response_extended, index);
    }

    /**
     * \brief Map of current address event count indexes.
     *
     * The index of a entry in the array is the file map value of that entry.
     */
    constexpr AddressEventCountField current_address_event_count[] = {
        AddressEventCountField::ae_type,
        AddressEventCountField::ae_code,
        AddressEventCountField::ae_address_index,
        AddressEventCountField::ae_count,
    };

    /**
     * \brief find map index of address event count fields for current format.
     *
     * \param index the field identifier.
     * \return the field index.
     * \throws std::logic_error if the item is specified in the format.
     */
    constexpr unsigned find_address_event_count_index(AddressEventCountField index)
    {
        return find_index(current_address_event_count, index);
    }

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
        BlockPreambleField block_preamble_field(unsigned index) const;

        /**
         * \brief Return block statistics field for given map index.
         *
         * \param index the map index read from file.
         * \returns field identifier.
         */
        BlockStatisticsField block_statistics_field(unsigned index) const;

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
         * \brief Return query signature field for given map index.
         *
         * \param index the map index read from file.
         * \returns field identifier.
         */
        QuerySignatureField query_signature_field(unsigned index) const;

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
         * \brief block statistics index map.
         */
        std::vector<BlockStatisticsField> block_statistics_;

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
         * \brief query signature index map.
         */
        std::vector<QuerySignatureField> query_signature_;

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
    };
};

#endif
