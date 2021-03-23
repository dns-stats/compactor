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

#ifndef BLOCKEDCBORREADER_HPP
#define BLOCKEDCBORREADER_HPP

#include <chrono>
#include <memory>
#include <unordered_map>
#include <vector>

#include <boost/optional.hpp>
#include <boost/functional/hash.hpp>

#include "addressevent.hpp"
#include "cbordecoder.hpp"
#include "blockcbor.hpp"
#include "blockcbordata.hpp"
#include "configuration.hpp"
#include "pseudoanonymise.hpp"
#include "queryresponse.hpp"

/**
 * \class QueryResponseData
 * \brief Data describing on a single query/response.
 *
 * Collect all the underlying information about a single query/reponse
 * into a single structure suitable for passing to an output
 * backend for further processing.
 *
 * Most items may or may not be present. If not present in the C-DNS file,
 * and a default is present, the value here will be the default.
 */
class QueryResponseData
{
public:
    /**
     * \struct Question
     * \brief Info on a single Question.
     */
    struct Question
    {
        /**
         * \brief the query name in the Question.
         */
        boost::optional<byte_string> qname;

        /**
         * \brief Question class.
         */
        boost::optional<CaptureDNS::QueryClass> qclass;

        /**
         * \brief Question type.
         */
        boost::optional<CaptureDNS::QueryType> qtype;
    };

    /**
     * \struct RR
     * \brief Info on a single RR.
     */
    struct RR
    {
        /**
         * \brief the name in the RR.
         */
        boost::optional<byte_string> name;

        /**
         * \brief RR class.
         */
        boost::optional<CaptureDNS::QueryClass> rclass;

        /**
         * \brief RR type.
         */
        boost::optional<CaptureDNS::QueryType> rtype;

        /**
         * \brief RR TTL.
         */
        boost::optional<uint32_t> ttl;

        /**
         * \brief RR RDATA.
         */
        boost::optional<byte_string> rdata;
    };

    /**
     * \brief the timestamp.
     */
    boost::optional<std::chrono::system_clock::time_point> timestamp;

    /**
     * \brief the client address.
     */
    boost::optional<IPAddress> client_address;

    /**
     * \brief client port.
     */
    boost::optional<uint16_t> client_port;

    /**
     * \brief client hop limit.
     */
    boost::optional<uint8_t> client_hoplimit;

    /**
     * \brief the server address.
     */
    boost::optional<IPAddress> server_address;

    /**
     * \brief server port.
     */
    boost::optional<uint16_t> server_port;

    /**
     * \brief server hop limit.
     */
    boost::optional<uint8_t> server_hoplimit;

    /**
     * \brief the transaction ID.
     */
    boost::optional<uint16_t> id;

    /**
     * \brief the query name in the first Question.
     */
    boost::optional<byte_string> qname;

    /**
     * \brief query/response flags.
     */
    uint8_t qr_flags;

    /**
     * \brief transport flags.
     */
    boost::optional<uint8_t> qr_transport_flags;

    /**
     * \brief transaction type.
     */
    boost::optional<uint8_t> qr_type;

    /*
     * Query-specific items.
     */

    /**
     * \brief DNS flags.
     */
    boost::optional<uint16_t> dns_flags;

    /**
     * \brief class of first Question.
     */
    boost::optional<CaptureDNS::QueryClass> query_class;

    /**
     * \brief type of first Question.
     */
    boost::optional<CaptureDNS::QueryType> query_type;

    /**
     * \brief Query second and subsequent Questions.
     */
    boost::optional<std::vector<Question>> query_questions;

    /**
     * \brief Query Answer sections.
     */
    boost::optional<std::vector<RR>> query_answers;

    /**
     * \brief Query Authority sections.
     */
    boost::optional<std::vector<RR>> query_authorities;

    /**
     * \brief Query Additional sections.
     */
    boost::optional<std::vector<RR>> query_additionals;

    /**
     * \brief query or response QDCOUNT.
     */
    boost::optional<uint16_t> query_qdcount;

    /**
     * \brief query ANCOUNT.
     */
    boost::optional<uint16_t> query_ancount;

    /**
     * \brief query NSCOUNT.
     */
    boost::optional<uint16_t> query_nscount;

    /**
     * \brief query ARCOUNT.
     */
    boost::optional<uint16_t> query_arcount;

    /**
     * \brief query OPCODE.
     */
    boost::optional<CaptureDNS::Opcode> query_opcode;

    /**
     * \brief query EDNS version.
     */
    boost::optional<uint8_t> query_edns_version;

    /**
     * \brief query EDNS UDP size
     */
    boost::optional<uint16_t> query_edns_payload_size;

    /**
     * \brief query OPT RDATA.
     */
    boost::optional<byte_string> query_opt_rdata;

    /**
     * \brief query RCODE, incorporating extended RCODE.
     */
    boost::optional<uint16_t> query_rcode;

    /**
     * \brief the size of the DNS query message.
     */
    boost::optional<uint32_t> query_size;

    /*
     * Response-specific items.
     */

    /**
     * \brief the response delay.
     */
    boost::optional<std::chrono::nanoseconds> response_delay;

    /**
     * \brief response RCODE, incorporating extended RCODE.
     */
    boost::optional<uint16_t> response_rcode;

    /**
     * \brief the size of the DNS response message.
     */
    boost::optional<uint32_t> response_size;

    /**
     * \brief Response second and subsequent Questions.
     */
    boost::optional<std::vector<Question>> response_questions;

    /**
     * \brief Response Answer sections.
     */
    boost::optional<std::vector<RR>> response_answers;

    /**
     * \brief Response Authority sections.
     */
    boost::optional<std::vector<RR>> response_authorities;

    /**
     * \brief Response Additional sections.
     */
    boost::optional<std::vector<RR>> response_additionals;

    /**
     * \brief Write basic information on the query/response to the output stream.
     *
     * \param output the output stream.
     * \param qr     the query/response.
     * \return the output stream.
     */
    friend std::ostream& operator<<(std::ostream& output, const QueryResponseData& qr);
};

/**
 * \class BlockCborReader
 * \brief Read input in the block CBOR format.
 *
 * The block [CBOR] format consists of blocks, or groups, of query/response
 * pairs. Each block has a header, comprising tables of information likely
 * to the repeated in individual query/response pairs.
 *
 * A formal description of the file format is given in a CDDL
 * specification in the documentation.
 *
 * [cbor]: http://cbor.io "CBOR website"
 */
class BlockCborReader
{
public:
    /**
     * \brief Constructor.
     *
     * \param dec               the decoder to use.
     * \param config            the configuration.
     * \param defaults          default values.
     * \param pseudo_anon       pseudo-anonymisation, if to use.
     */
    BlockCborReader(CborBaseDecoder& dec,
                    Configuration& config,
                    const Defaults& defaults,
                    boost::optional<PseudoAnonymise> pseudo_anon ={});

    /**
     * \brief Return the data for the next Query/Response pair.
     *
     * Retrieving the Query/Response pairs should probably be done
     * via an iterator. This fills in for now.
     *
     * \param eof <code>true</code> if data supplied, <code>false</code>
     * on EOF.
     * \returns data for the next Query/Response.
     */
    QueryResponseData readQRData(bool& eof);

    /**
     * \brief Dump the statistics for the block to the stream provided
     *
     * \param os output stream.
     */
    void dump_stats(std::ostream& os) const {
        block_->last_packet_statistics.dump_stats(os);
    }

    /**
     * \brief Dump information on the collector to the stream provided.
     *
     * \param os output stream.
     */
    void dump_collector(std::ostream& os) const;

    /**
     * \brief Dump info on file earliest/latest/end times to the stream provided
     *
     * \param os output stream.
     */
    void dump_times(std::ostream& os) const;

    /**
     * \brief Dump address event info to the stream provided.
     *
     * \param os output stream.
     */
    void dump_address_events(std::ostream& os) const;

protected:
    /**
     * \brief Read the file header.
     *
     * Read the file header and extract the configuration information
     * from the preamble.
     *
     * \param config extracted configuration information.
     * \throws cbor_decode_error if the CBOR is invalid.
     * \throws cbor_file_format_error on unexpected CBOR content.
     */
    void readFileHeader(Configuration& config);

    /**
     * \brief Read the file preamble.
     *
     * Read the file preamble and extract the configuration information
     * therein.
     *
     * \param config extracted configuration information.
     * \param ver    the file format version. Either format 1.0 or format 0.2.
     * \throws cbor_decode_error if the CBOR is invalid.
     * \throws std::logic_error on unexpected CBOR content.
     * \throws cbor_file_format_error on unexpected CBOR content.
     */
    void readFilePreamble(Configuration& config, block_cbor::FileFormatVersion ver);

    /**
     * \brief Read the configuration in pre-format 1.0 files.
     *
     * Read the configuration information.
     *
     * \param config extracted configuration information.
     * \throws cbor_decode_error if the CBOR is invalid.
     * \throws std::logic_error on unexpected CBOR content.
     * \throws cbor_file_format_error on unexpected CBOR content.
     */
    void readConfiguration(Configuration& config);

    /**
     * \brief Read the block parameters in format 1.0 files.
     *
     * Read the block parameter information vector. Set configuration
     * information from parameters.
     *
     * \param config extracted configuration information.
     * \throws cbor_decode_error if the CBOR is invalid.
     * \throws std::logic_error on unexpected CBOR content.
     * \throws cbor_file_format_error on unexpected CBOR content.
     */
    void readBlockParameters(Configuration& config);

    /**
     * \brief Convert byte string to address.
     *
     * Pseudo-anonymise the address if that's enabled.
     *
     * \param str       the byte string.
     * \param is_ipv6   is the address IPv6?
     * \returns the address.
     */
    IPAddress string_to_addr(const byte_string& str, bool is_ipv6);

private:
    /**
     * \brief Read the info for the next block.
     *
     * \return `false` if no more blocks in file.
     */
    bool readBlock();

    /**
     * \brief Get a client address from the address table.
     *
     * If the prefixes are such that we can infer whether the address is
     * IPv4 or IPv6, we don't try to touch the transport flags. If not,
     * we will try to dereference them.
     *
     * \param index           the table index.
     * \param transport_flags the transport flags.
     * \returns the address.
     */
    IPAddress get_client_address(std::size_t index, boost::optional<uint8_t> transport_flags);

    /**
     * \brief Get a server address from the address table.
     *
     * If the prefixes are such that we can infer whether the address is
     * IPv4 or IPv6, we don't try to touch the transport flags. If not,
     * we will try to dereference them.
     *
     * \param index           the table index.
     * \param transport_flags the transport flags.
     * \returns the address.
     */
    IPAddress get_server_address(std::size_t index, boost::optional<uint8_t> transport_flags);

    /**
     * \brief Determine if client prefix means a full IPv4 address.
     *
     * \param b byte string with address.
     * \returns <code>true</code> if full IPv4 address present.
     */
    bool is_ipv4_client_full_address(const byte_string& b) const;

    /**
     * \brief Determine if client prefix means a full IPv6 address.
     *
     * \param b byte string with address.
     * \returns <code>true</code> if full IPv6 address present.
     */
    bool is_ipv6_client_full_address(const byte_string& b) const;

    /**
     * \brief Determine if server prefix means a full IPv4 address.
     *
     * \param b byte string with address.
     * \returns <code>true</code> if full IPv4 address present.
     */
    bool is_ipv4_server_full_address(const byte_string& b) const;

    /**
     * \brief Determine if server prefix means a full IPv6 address.
     *
     * \param b byte string with address.
     * \returns <code>true</code> if full IPv6 address present.
     */
    bool is_ipv6_server_full_address(const byte_string& b) const;

    /**
     * \brief Decode block cbor extra info to our RRs.
     *
     * \param index index of the block RR.
     * \param res   output RR vector.
     */
    void read_extra_info(const std::unique_ptr<block_cbor::QueryResponseExtraInfo>& extra_info,
                         boost::optional<std::vector<QueryResponseData::Question>>& questions,
                         boost::optional<std::vector<QueryResponseData::RR>>& answers,
                         boost::optional<std::vector<QueryResponseData::RR>>& authorities,
                         boost::optional<std::vector<QueryResponseData::RR>>& additionals);

    /**
     * \brief Decode a block cbor RR to our RR.
     *
     * \param index index of the block RR.
     * \param res   output RR vector.
     */
    void read_rr(block_cbor::index_t index, boost::optional<std::vector<QueryResponseData::RR>>& res);

    /**
     * \brief Synthesise Q/R flags from other fields.
     *
     * \param qri query response item.
     * \param sig query response signature.
     * \returns synthesised signature.
     */
    uint8_t synthesise_qr_flags(const block_cbor::QueryResponseItem& qri,
                                const block_cbor::QueryResponseSignature& sig);

    /**
     * \brief the decoder to read from.
     */
    CborBaseDecoder& dec_;

    /**
     * \brief the default values to use when reading.
     */
    const Defaults& defaults_;

    /**
     * \brief index of the next item to read from the current block.
     */
    unsigned next_item_;

    /**
     * \brief `true` if we need to read a new block.
     */
    bool need_block_;

    /**
     * \brief is the block size indefinite?
     */
    bool blocks_indef_;

    /**
     * \brief the number of blocks in the file, if definite.
     */
    uint64_t nblocks_;

    /**
     * \brief the file format version.
     */
    block_cbor::FileFormatVersion file_format_version_;

    /**
     * \brief the current block.
     */
    std::unique_ptr<block_cbor::BlockData> block_;

    /**
     * \brief the number of the current block
     */
    uint64_t current_block_num_;

    /**
     * \brief ID of the capturing program.
     */
    std::string generator_id_;

    /**
     * \brief ID of the capturing host.
     */
    std::string host_id_;

    /**
     * \brief Pointer to the field translation object.
     */
    std::unique_ptr<block_cbor::FileVersionFields> fields_;

    /**
     * \brief pseudo-anonymisation, if to use.
     */
    boost::optional<PseudoAnonymise> pseudo_anon_;

    /**
     * \brief accumulated address events from the file.
     */
    std::unordered_map<AddressEvent, unsigned, boost::hash<AddressEvent>> address_events_read_;

    /**
     * \brief vector of block parameters.
     */
    std::vector<block_cbor::BlockParameters> block_parameters_;

    /**
     * \brief earliest time of data in file.
     */
    boost::optional<std::chrono::system_clock::time_point> earliest_time_;

    /**
     * \brief latest time of data in file.
     */
    boost::optional<std::chrono::system_clock::time_point> latest_time_;

    /**
     * \brief end time of file.
     */
    boost::optional<std::chrono::system_clock::time_point> end_time_;

    /**
     * \brief start time of file.
     */
    boost::optional<std::chrono::system_clock::time_point> start_time_;
};

#endif
