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

#ifndef BLOCKEDCBORDATA_HPP
#define BLOCKEDCBORDATA_HPP

#include <chrono>
#include <deque>
#include <unordered_map>
#include <vector>

#include <boost/functional/hash.hpp>
#include <boost/optional.hpp>

#include "addressevent.hpp"
#include "bytestring.hpp"
#include "blockcbor.hpp"
#include "capturedns.hpp"
#include "cbordecoder.hpp"
#include "cborencoder.hpp"
#include "ipaddress.hpp"
#include "makeunique.hpp"
#include "packetstatistics.hpp"

namespace boost {
    /**
     * \brief Calculate a hash value for a boost::optional<T>.
     *
     * std::optional is hashable, boost::optional isn't. Do something
     * about that.
     *
     * \returns hash value.
     */
    template<typename T>
    std::size_t hash_value(const boost::optional<T>& t)
    {
        bool there = t;
        std::size_t seed = boost::hash_value(there);
        if ( there )
            boost::hash_combine(seed, *t);
        return seed;
    }
}

namespace block_cbor {

    namespace {
        // Default for storage parameters.
        const unsigned DEFAULT_TICKS_PER_SECOND = 1000000;
        const unsigned DEFAULT_MAX_BLOCK_ITEMS = 5000;
        const unsigned DEFAULT_IPV4_PREFIX_LENGTH = 32;
        const unsigned DEFAULT_IPV6_PREFIX_LENGTH = 128;

        // Defaults for collection parameters.
        const unsigned DEFAULT_QUERY_TIMEOUT = 5;
        const unsigned DEFAULT_SKEW_TIMEOUT = 10;
        const unsigned DEFAULT_SNAPLEN = 65535;
        const unsigned DEFAULT_PROMISC = false;
    }

    // Block header table types.

    /**
     * \brief type for the index into a header.
     *
     * Note that the index may be either is 1-based or 0-based depending
     * on the file format version. Formats before 1.0 are 1-based, from
     * 1.0 on are 0-based. In pre-format 1.0 versions, index 0 was reserved
     * for 'value not present'.
     */
    using index_t = boost::optional<std::size_t>;

    /**
     * \struct Timestamp
     * \brief A timestamp as POSIX time in seconds since the epoch
     * and subsecond ticks.
     */
    struct Timestamp
    {
        /**
         * \brief Constructor.
         *
         * \param t     the time point.
         * \param ticks_per_second the number of ticks in a second.
         */
        Timestamp(const std::chrono::system_clock::time_point& t,
                  uint64_t ticks_per_second)
        {
            setFromTimePoint(t, ticks_per_second);
        }

        /**
         * \brief Constructor.
         */
        Timestamp() : secs(0), ticks(0) {}

        /**
         * \brief POSIX seconds since the epoch.
         */
        uint64_t secs;

        /**
         * \brief subsecond ticks.
         *
         * The number of ticks per second is a block parameter.
         */
        uint64_t ticks;

        /**
         * \brief Read the object contents from CBOR.
         *
         * \param dec    CBOR stream to read from.
         * \throws cbor_file_format_error on unexpected CBOR content.
         * \throws cbor_decode_error on malformed CBOR items.
         * \throws cbor_end_of_input on end of CBOR file.
         */
        void readCbor(CborBaseDecoder& dec);

        /**
         * \brief Write the object contents to CBOR.
         *
         * \param enc CBOR stream to write to.
         */
        void writeCbor(CborBaseEncoder& enc);

        /**
         * \brief Set timestamp from time point.
         *
         * \param t     the time point.
         * \param ticks_per_second the number of ticks in a second.
         */
        void setFromTimePoint(const std::chrono::system_clock::time_point& t,
                              uint64_t ticks_per_second);

        /**
         * \brief Get the time point represented by this timestamp.
         *
         * \param ticks_per_second the number of ticks in a second.
         * \returns the time point.
         */
        std::chrono::system_clock::time_point getTimePoint(uint64_t ticks_per_second);
    };

    /**
     * \struct StorageHints
     * \brief Bitmap hints on what data was being collected, and so
     * should appear in the block is present on the wire.
     */
    struct StorageHints
    {
        /**
         * \brief Default constructor.
         */
        StorageHints() :
            query_response_hints(),
            query_response_signature_hints(),
            rr_hints(),
            other_data_hints()
        {}

        /**
         * \brief Hints relating to Query/Response data.
         */
        QueryResponseHintFlags query_response_hints;

        /**
         * \brief Hints relating to Query/Response signature data.
         */
        QueryResponseSignatureHintFlags query_response_signature_hints;

        /**
         * \brief Hints relating to Resource Record data.
         */
        RRHintFlags rr_hints;

        /**
         * \brief Hints relating to other data.
         */
        OtherDataHintFlags other_data_hints;

        /**
         * \brief Read the object contents from CBOR.
         *
         * \param dec    CBOR stream to read from.
         * \param fields translate map keys to internal values.
         * \throws cbor_file_format_error on unexpected CBOR content.
         * \throws cbor_decode_error on malformed CBOR items.
         * \throws cbor_end_of_input on end of CBOR file.
         */
        void readCbor(CborBaseDecoder& dec, const FileVersionFields& fields);

        /**
         * \brief Write the object contents to CBOR.
         *
         * \param enc CBOR stream to write to.
         */
        void writeCbor(CborBaseEncoder& enc);
    };

    /**
     * \struct StorageParameters
     * \brief Info on the data stored within a block.
     */
    struct StorageParameters
    {
        /**
         * \brief Default constructor.
         */
        StorageParameters() :
            ticks_per_second(DEFAULT_TICKS_PER_SECOND),
            max_block_items(DEFAULT_MAX_BLOCK_ITEMS),
            storage_hints(),
            storage_flags(),
            client_address_prefix_ipv4(DEFAULT_IPV4_PREFIX_LENGTH),
            client_address_prefix_ipv6(DEFAULT_IPV6_PREFIX_LENGTH),
            server_address_prefix_ipv4(DEFAULT_IPV4_PREFIX_LENGTH),
            server_address_prefix_ipv6(DEFAULT_IPV6_PREFIX_LENGTH)
        { }

        /**
         * \brief number of ticks per second.
         */
        uint64_t ticks_per_second;

        /**
         * \brief Max number of items (Q/R, AddressEventCounts, Malformed data)
         * in the block.
         */
        unsigned max_block_items;

        /**
         * \brief Storage hints.
         */
        StorageHints storage_hints;

        /**
         * \brief Opcodes recorded by collector.
         */
        std::vector<unsigned> opcodes;

        /**
         * \brief Resource Record types recorded by collector.
         */
        std::vector<unsigned> rr_types;

        /**
         * \brief Storage flags (flags about the data content).
         */
        StorageFlags storage_flags;

        /**
         * \brief Client IPv4 address prefix length (number of bits
         * of a client IPv4 address stored).
         */
        unsigned client_address_prefix_ipv4;

        /**
         * \brief Client IPv6 address prefix length (number of bits
         * of a client IPv6 address stored).
         */
        unsigned client_address_prefix_ipv6;

        /**
         * \brief Server IPv4 address prefix length (number of bits
         * of a server IPv4 address stored).
         */
        unsigned server_address_prefix_ipv4;

        /**
         * \brief Server IPv6 address prefix length (number of bits
         * of a server IPv6 address stored).
         */
        unsigned server_address_prefix_ipv6;

        /**
         * \brief Text describing the sampling method, if sampling used.
         */
        std::string sampling_method;

        /**
         * \brief Text describing the anonymisation method, if
         * anonymisation used.
         */
        std::string anonymisation_method;

        /**
         * \brief Read the object contents from CBOR.
         *
         * \param dec    CBOR stream to read from.
         * \param fields translate map keys to internal values.
         * \throws cbor_file_format_error on unexpected CBOR content.
         * \throws cbor_decode_error on malformed CBOR items.
         * \throws cbor_end_of_input on end of CBOR file.
         */
        void readCbor(CborBaseDecoder& dec, const FileVersionFields& fields);

        /**
         * \brief Write the object contents to CBOR.
         *
         * \param enc CBOR stream to write to.
         */
        void writeCbor(CborBaseEncoder& enc);
    };

    /**
     * \struct CollectionParameters
     * \brief Info on the data collection settings for the data in a block.
     */
    struct CollectionParameters
    {
        /**
         * \brief Default constructor.
         */
        CollectionParameters() :
            query_timeout(DEFAULT_QUERY_TIMEOUT),
            skew_timeout(DEFAULT_SKEW_TIMEOUT),
            snaplen(DEFAULT_SNAPLEN),
            promisc(DEFAULT_PROMISC)
        { }

        /**
         * \brief period in seconds after which a query is deemed to
         * not have received a response.
         */
        unsigned query_timeout;

        /**
         * \brief the maximum time in microseconds to allow for out of
         * temporal order packet delivery. If a response arrives without a
         * query, once a packet arrives with a timestamp this much later,
         * give up hoping for a query to arrive.
         */
        unsigned skew_timeout;

        /**
         * \brief packet capture snap length. See `tcpdump` documentation for more.
         */
        unsigned snaplen;

        /**
         * \brief `true` if the interface should be put into promiscous mode.
         * See `tcpdump` documentation for more.
         */
        bool promisc;

        /**
         * \brief the network interfaces to capture from.
         *
         * This will be operating system dependent. A Linux example is `eth0`.
         */
        std::vector<std::string> interfaces;

        /**
         * \brief the server network addresses.
         *
         * Optional addresses for the server interfaces. Stored in C-DNS but
         * not otherwise used.
         */
        std::vector<IPAddress> server_addresses;

        /**
         * \brief which vlan IDs are to be accepted.
         */
        std::vector<unsigned> vlan_ids;

        /**
         * \brief packet filter
         *
         * `libpcap` packet filter expression. Packets not matching will be
         * silently discarded.
         */
        std::string filter;

        /**
         * \brief generator ID
         *
         * String identifying application doing the collection.
         */
        std::string generator_id;

        /**
         * \brief host ID
         *
         * String identifying the hostname of the machine doing the collection.
         */
        std::string host_id;

        /**
         * \brief Read the object contents from CBOR.
         *
         * \param dec    CBOR stream to read from.
         * \param fields translate map keys to internal values.
         * \throws cbor_file_format_error on unexpected CBOR content.
         * \throws cbor_decode_error on malformed CBOR items.
         * \throws cbor_end_of_input on end of CBOR file.
         */
        void readCbor(CborBaseDecoder& dec, const FileVersionFields& fields);

        /**
         * \brief Write the object contents to CBOR.
         *
         * \param enc CBOR stream to write to.
         */
        void writeCbor(CborBaseEncoder& enc);
    };

        /**
     * \struct BlockParameters
     * \brief Info on all parameters applicable to a block.
     */
    struct BlockParameters
    {
        /**
         * \brief storage parameters for the block.
         */
        StorageParameters storage_parameters;

        /**
         * \brief collection parameters for the block.
         */
        CollectionParameters collection_parameters;

        /**
         * \brief Read the object contents from CBOR.
         *
         * \param dec    CBOR stream to read from.
         * \param fields translate map keys to internal values.
         * \throws cbor_file_format_error on unexpected CBOR content.
         * \throws cbor_decode_error on malformed CBOR items.
         * \throws cbor_end_of_input on end of CBOR file.
         */
        void readCbor(CborBaseDecoder& dec, const FileVersionFields& fields);

        /**
         * \brief Write the object contents to CBOR.
         *
         * \param enc CBOR stream to write to.
         */
        void writeCbor(CborBaseEncoder& enc);
    };

    /**
     * \struct IndexVectorItem
     * \brief A header list item that's a vector of indexes to items.
     */
    struct IndexVectorItem
    {
        /**
         * \brief the string data.
         */
        std::vector<index_t> vec;

        /**
         * \brief return the key to be used for storing values.
         */
        const std::vector<index_t>& key() const
        {
            return vec;
        }

        /**
         * \brief Read the object contents from CBOR.
         *
         * \param dec      CBOR stream to read from.
         * \param fields   translate map keys to internal values. Unused.
         * \throws cbor_file_format_error on unexpected CBOR content.
         * \throws cbor_decode_error on malformed CBOR items.
         * \throws cbor_end_of_input on end of CBOR file.
         */
        void readCbor(CborBaseDecoder& dec,
                      const FileVersionFields& fields);

        /**
         * \brief Write the object contents to CBOR.
         *
         * \param enc     CBOR stream to write to.
         */
        void writeCbor(CborBaseEncoder& enc);
    };

    /**
     * \struct ByteStringItem
     * \brief A header list item that's a string (e.g. name, RDATA).
     */
    struct ByteStringItem
    {
        /**
         * \brief the string data.
         */
        byte_string str;

        /**
         * \brief return the key to be used for storing values.
         */
        const byte_string& key() const
        {
            return str;
        }

        /**
         * \brief Read the object contents from CBOR.
         *
         * \param dec      CBOR stream to read from.
         * \param fields   translate map keys to internal values. Unused.
         * \throws cbor_file_format_error on unexpected CBOR content.
         * \throws cbor_decode_error on malformed CBOR items.
         * \throws cbor_end_of_input on end of CBOR file.
         */
        void readCbor(CborBaseDecoder& dec,
                      const FileVersionFields& fields);

        /**
         * \brief Write the object contents to CBOR.
         *
         * \param enc     CBOR stream to write to.
         */
        void writeCbor(CborBaseEncoder& enc);
    };

    /**
     * \struct ClassType
     * \brief A DNS Class and Type.
     */
    struct ClassType
    {
        /**
         * \brief Default constructor.
         */
        ClassType() : qclass(), qtype() { }

        /**
         * \brief the DNS Class.
         */
        boost::optional<CaptureDNS::QueryClass> qclass;

        /**
         * \brief the DNS Type.
         */
        boost::optional<CaptureDNS::QueryType> qtype;

        /**
         * \brief return the key to be used for storing values.
         */
        const ClassType& key() const
        {
            return *this;
        }

        /**
         * \brief Implement equality operator.
         *
         * \param rhs item to compare to.
         * \returns `true` if the two are equal.
         */
        bool operator==(const ClassType& rhs) const {
            return ( qclass == rhs.qclass && qtype == rhs.qtype );
        }

        /**
         * \brief Inequality operator.
         *
         * \param rhs the class/type to compare to.
         * \returns `false` if the two are equal.
         */
        bool operator!=(const ClassType& rhs) const {
            return !( *this == rhs );
        }

        /**
         * \brief Read the object contents from CBOR.
         *
         * \param dec      CBOR stream to read from.
         * \param fields   translate map keys to internal values.
         * \throws cbor_file_format_error on unexpected CBOR content.
         * \throws cbor_decode_error on malformed CBOR items.
         * \throws cbor_end_of_input on end of CBOR file.
         */
        void readCbor(CborBaseDecoder& dec,
                      const FileVersionFields& fields);

        /**
         * \brief Write the object contents to CBOR.
         *
         * \param enc     CBOR stream to write to.
         */
        void writeCbor(CborBaseEncoder& enc);
    };

    /**
     * \brief Calculate a hash value for the item.
     *
     * \returns hash value.
     */
    std::size_t hash_value(const ClassType &ct);

    /**
     * \struct Question
     * \brief A DNS Question.
     */
    struct Question
    {
        /**
         * \brief Default constructor.
         */
        Question() : qname(), classtype() { }

        /**
         * \brief Index of the QNAME.
         */
        index_t qname;

        /**
         * \brief index of the QClass/QType.
         */
        index_t classtype;

        /**
         * \brief return the key to be used for storing values.
         */
        const Question& key() const
        {
            return *this;
        }

        /**
         * \brief Implement equality operator.
         *
         * \param rhs item to compare to.
         * \returns `true` if the two are equal.
         */
        bool operator==(const Question& rhs) const {
            return ( qname == rhs.qname && classtype == rhs.classtype );
        }

        /**
         * \brief Inequality operator.
         *
         * \param rhs the class/type to compare to.
         * \returns `false` if the two are equal.
         */
        bool operator!=(const Question& rhs) const {
            return !( *this == rhs );
        }

        /**
         * \brief Read the object contents from CBOR.
         *
         * \param dec      CBOR stream to read from.
         * \param fields   translate map keys to internal values.
         * \throws cbor_file_format_error on unexpected CBOR content.
         * \throws cbor_decode_error on malformed CBOR items.
         * \throws cbor_end_of_input on end of CBOR file.
         */
        void readCbor(CborBaseDecoder& dec,
                      const FileVersionFields& fields);

        /**
         * \brief Write the object contents to CBOR.
         *
         * \param enc     CBOR stream to write to.
         */
        void writeCbor(CborBaseEncoder& enc);
    };

    /**
     * \brief Calculate a hash value for the item.
     *
     * \returns hash value.
     */
    std::size_t hash_value(const Question& q);

    /**
     * \struct ResourceRecord
     * \brief A DNS ResourceRecord.
     */
    struct ResourceRecord
    {
        /**
         * \brief Default constructor.
         */
        ResourceRecord() : name(), classtype(), ttl(), rdata() { }

        /**
         * \brief index of RR name.
         */
        index_t name;

        /**
         * \brief index of RR class/type.
         */
        index_t classtype;

        /**
         * \brief RR TTL.
         */
        boost::optional<uint32_t> ttl;

        /**
         * \brief index of RR RDATA.
         */
        index_t rdata;

        /**
         * \brief return the key to be used for storing values.
         */
        const ResourceRecord& key() const
        {
            return *this;
        }

        /**
         * \brief Implement equality operator.
         *
         * \param rhs item to compare to.
         * \returns `true` if the two are equal.
         */
        bool operator==(const ResourceRecord& rhs) const {
            return ( name == rhs.name && classtype == rhs.classtype &&
                     ttl == rhs.ttl && rdata == rhs.rdata );
        }

        /**
         * \brief Inequality operator.
         *
         * \param rhs the class/type to compare to.
         * \returns `false` if the two are equal.
         */
        bool operator!=(const ResourceRecord& rhs) const {
            return !( *this == rhs );
        }

        /**
         * \brief Read the object contents from CBOR.
         *
         * \param dec      CBOR stream to read from.
         * \param fields   translate map keys to internal values.
         * \throws cbor_file_format_error on unexpected CBOR content.
         * \throws cbor_decode_error on malformed CBOR items.
         * \throws cbor_end_of_input on end of CBOR file.
         */
        void readCbor(CborBaseDecoder& dec,
                      const FileVersionFields& fields);

        /**
         * \brief Write the object contents to CBOR.
         *
         * \param enc     CBOR stream to write to.
         */
        void writeCbor(CborBaseEncoder& enc);
    };

    /**
     * \brief Calculate a hash value for the item.
     *
     * \returns hash value.
     */
    std::size_t hash_value(const ResourceRecord& rr);

    /**
     * \struct QueryResponseSignature
     * \brief A DNS Query Signature.
     */
    struct QueryResponseSignature
    {
        /**
         * \brief Default constructor.
         */
        QueryResponseSignature() :
            qr_flags(), server_address(), server_port(), qr_transport_flags(),
            query_rcode(), response_rcode(), query_opcode(),
            query_edns_version(), query_edns_payload_size(),
            query_opt_rdata(), dns_flags(), query_classtype(),
            qdcount(), query_ancount(), query_nscount(), query_arcount() { }

        /**
         * \brief indicate whether query and response are present.
         */
        uint8_t qr_flags;

        /**
         * \brief index of address of the DNS server.
         */
        index_t server_address;

        /**
         * \brief port of DNS server.
         */
        boost::optional<uint16_t> server_port;

        /**
         * \brief transport flags.
         */
        boost::optional<uint8_t> qr_transport_flags;

        /**
         * \brief query RCODE, incorporating extended RCODE.
         */
        boost::optional<CaptureDNS::Rcode> query_rcode;

        /**
         * \brief response RCODE, incorporating extended RCODE.
         */
        boost::optional<CaptureDNS::Rcode> response_rcode;

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
        index_t query_opt_rdata;

        /**
         * \brief DNS flags.
         */
        boost::optional<uint16_t> dns_flags;

        /**
         * \brief query class/type.
         */
        index_t query_classtype;

        /**
         * \brief query or response QDCOUNT.
         */
        boost::optional<uint16_t> qdcount;

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
         * \brief return the key to be used for storing values.
         */
        const QueryResponseSignature& key() const
        {
            return *this;
        }

        /**
         * \brief Implement equality operator.
         *
         * \param rhs item to compare to.
         * \returns `true` if the two are equal.
         */
        bool operator==(const QueryResponseSignature& rhs) const {
            if ( qr_flags != rhs.qr_flags ||
                 server_address != rhs.server_address ||
                 server_port != rhs.server_port ||
                 qr_transport_flags != rhs.qr_transport_flags ||
                 dns_flags != rhs.dns_flags ||
                 qdcount != rhs.qdcount )
                return false;

            if ( !(qr_flags & QUERY_HAS_NO_QUESTION) &&
                 query_classtype != rhs.query_classtype )
                return false;

            if ( ( qr_flags & QUERY_ONLY ) &&
                 ( query_rcode != rhs.query_rcode ||
                   query_opcode != rhs.query_opcode ||
                   query_ancount != rhs.query_ancount ||
                   query_nscount != rhs.query_nscount ||
                   query_arcount != rhs.query_arcount ) )
                return false;

            if ( ( qr_flags & RESPONSE_ONLY ) &&
                 response_rcode != rhs.response_rcode )
                return false;

            if ( ( qr_flags & QUERY_HAS_OPT ) &&
                 ( query_edns_version != rhs.query_edns_version ||
                   query_edns_payload_size != rhs.query_edns_payload_size ||
                   query_opt_rdata != rhs.query_opt_rdata ) )
                return false;

            return true;
        }

        /**
         * \brief Inequality operator.
         *
         * \param rhs the class/type to compare to.
         * \returns `false` if the two are equal.
         */
        bool operator!=(const QueryResponseSignature& rhs) const {
            return !(*this == rhs);
        }

        /**
         * \brief Read the object contents from CBOR.
         *
         * \param dec      CBOR stream to read from.
         * \param fields   translate map keys to internal values.
         * \throws cbor_file_format_error on unexpected CBOR content.
         * \throws cbor_decode_error on malformed CBOR items.
         * \throws cbor_end_of_input on end of CBOR file.
         */
        void readCbor(CborBaseDecoder& dec,
                      const FileVersionFields& fields);

        /**
         * \brief Write the object contents to CBOR.
         *
         * \param enc     CBOR stream to write to.
         */
        void writeCbor(CborBaseEncoder& enc);
    };

    /**
     * \brief Calculate a hash value for the item.
     *
     * \returns hash value.
     */
    std::size_t hash_value(const QueryResponseSignature& qs);

    /**
     * \struct QueryResponseExtraInfo
     * \brief Holds extra info sections for query or response.
     *
     * This is not used in a header table with unique entries, and so does
     * not need an equality operator.
     */
    struct QueryResponseExtraInfo
    {
        /**
         * \brief index of questions list.
         */
        index_t questions_list;

        /**
         * \brief index of Answer RR list.
         */
        index_t answers_list;

        /**
         * \brief index of Authority RR list.
         */
        index_t authority_list;

        /**
         * \brief index of Additional RR list.
         */
        index_t additional_list;
    };

    /**
     * \struct QueryResponseItem
     * \brief Data for an individual Query/Response in the block.
     *
     * This is not used in a header table with unique entries, and so does
     * not need an equality operator.
     */
    struct QueryResponseItem
    {
        /**
         * \brief indicate whether query and response are present.
         *  Only used internally within the code, not written to cbor
         */
        int qr_flags;

        /**
         * \brief index of client address.
         */
        index_t client_address;

        /**
         * \brief client port.
         */
        boost::optional<uint16_t> client_port;

        /**
         * \brief client hop limit.
         */
        boost::optional<uint8_t> hoplimit;

        /**
         * \brief the transaction ID.
         */
        boost::optional<uint16_t> id;

        /**
         * \brief the timestamp.
         */
        boost::optional<std::chrono::system_clock::time_point> tstamp;

        /**
         * \brief the response delay.
         */
        boost::optional<std::chrono::nanoseconds> response_delay;

        /**
         * \brief the first query QNAME.
         */
        index_t qname;

        /**
         * \brief the query signature.
         */
        index_t signature;

        /**
         * \brief the size of the DNS query message.
         */
        boost::optional<uint32_t> query_size;

        /**
         * \brief the size of the DNS response message.
         */
        boost::optional<uint32_t> response_size;

        /**
         * \brief Optional extra query info.
         */
        std::unique_ptr<QueryResponseExtraInfo> query_extra_info;

        /**
         * \brief Optional extra response info.
         */
        std::unique_ptr<QueryResponseExtraInfo> response_extra_info;

        /**
         * \brief Default constructor.
         */
        QueryResponseItem()
        {
            clear();
        }

        /**
         * \brief clear the query/response.
         */
        void clear();

        /**
         * \brief Read the object contents from CBOR.
         *
         * \param dec              CBOR stream to read from.
         * \param earliest_time    earliest time in block.
         * \param block_parameters parameters for this block.
         * \param fields           translate map keys to internal values.
         * \throws cbor_file_format_error on unexpected CBOR content.
         * \throws cbor_decode_error on malformed CBOR items.
         * \throws cbor_end_of_input on end of CBOR file.
         */
        void readCbor(CborBaseDecoder& dec,
                      const std::chrono::system_clock::time_point& earliest_time,
                      const BlockParameters& block_parameters,
                      const FileVersionFields& fields);

        /**
         * \brief Write the object contents to CBOR.
         *
         * \param enc              CBOR stream to write to.
         * \param earliest_time    earliest time in block.
         * \param block_parameters parameters for this block.
         */
        void writeCbor(CborBaseEncoder& enc,
                       const std::chrono::system_clock::time_point& earliest_time,
                       const BlockParameters& block_parameters);
    };

    /**
     * \struct AddressEventItem
     * \brief A description of an address event.
     */
    struct AddressEventItem
    {
        /**
         * \brief Default constructor.
         */
        AddressEventItem() : type(), code(), address() { }

        /**
         * \brief AddressEvent type.
         */
        boost::optional<AddressEvent::EventType> type;

        /**
         * \brief AddressEvent code.
         */
        boost::optional<unsigned> code;

        /**
         * \brief index of event address.
         */
        index_t address;

        /**
         * \brief address event transport flags.
         */
        boost::optional<uint8_t> transport_flags;

        /**
         * \brief return the key to be used for storing values.
         */
        const AddressEventItem& key() const
        {
            return *this;
        }

        /**
         * \brief Implement equality operator.
         *
         * \param rhs item to compare to.
         * \returns `true` if the two are equal.
         */
        bool operator==(const AddressEventItem& rhs) const {
            return ( type == rhs.type && code == rhs.code && address == rhs.address && transport_flags == rhs.transport_flags);
        }

        /**
         * \brief Inequality operator.
         *
         * \param rhs the class/type to compare to.
         * \returns `false` if the two are equal.
         */
        bool operator!=(const AddressEventItem& rhs) const {
            return !( *this == rhs );
        }
    };

    /**
     * \brief Calculate a hash value for the item.
     *
     * \returns hash value.
     */
    std::size_t hash_value(const AddressEventItem& aei);

    /**
     * \struct AddressEventCount
     * \brief A count of address events.
     */
    struct AddressEventCount
    {
        /**
         * \brief the AddressEvent.
         */
        AddressEventItem aei;

        /**
         * \brief Count of identical AddressEvents.
         */
        unsigned count;

        /**
         * \brief Read the object contents from CBOR.
         *
         * \param dec      CBOR stream to read from.
         * \param fields   translate map keys to internal values.
         * \throws cbor_file_format_error on unexpected CBOR content.
         * \throws cbor_decode_error on malformed CBOR items.
         * \throws cbor_end_of_input on end of CBOR file.
         */
        void readCbor(CborBaseDecoder& dec,
                      const FileVersionFields& fields);

        /**
         * \brief Write the object contents to CBOR.
         *
         * \param enc CBOR stream to write to.
         */
        void writeCbor(CborBaseEncoder& enc);
    };

    /**
     * \struct MalformedMessageData
     * \brief Table data for malformed messages
     */
    struct MalformedMessageData
    {
        /**
         * \brief Default constructor.
         */
        MalformedMessageData()
            : server_address(), server_port(),
              mm_transport_flags(), mm_payload() { }

        /**
         * \brief index of address of the DNS server.
         */
        index_t server_address;

        /**
         * \brief port of DNS server.
         */
        boost::optional<uint16_t> server_port;

        /**
         * \brief transport flags.
         */
        boost::optional<uint8_t> mm_transport_flags;

        /**
         * \brief the message data.
         */
        boost::optional<byte_string> mm_payload;

        /**
         * \brief return the key to be used for storing values.
         */
        const MalformedMessageData& key() const
        {
            return *this;
        }

        /**
         * \brief Implement equality operator.
         *
         * \param rhs item to compare to.
         * \returns `true` if the two are equal.
         */
        bool operator==(const MalformedMessageData& rhs) const {
            return ( server_address == rhs.server_address &&
                     server_port == rhs.server_port &&
                     mm_transport_flags == rhs.mm_transport_flags &&
                     mm_payload == rhs.mm_payload );
        }

        /**
         * \brief Inequality operator.
         *
         * \param rhs the class/type to compare to.
         * \returns `false` if the two are equal.
         */
        bool operator!=(const MalformedMessageData& rhs) const {
            return !( *this == rhs );
        }

        /**
         * \brief Read the object contents from CBOR.
         *
         * \param dec      CBOR stream to read from.
         * \param fields   translate map keys to internal values.
         * \throws cbor_file_format_error on unexpected CBOR content.
         * \throws cbor_decode_error on malformed CBOR items.
         * \throws cbor_end_of_input on end of CBOR file.
         */
        void readCbor(CborBaseDecoder& dec,
                      const FileVersionFields& fields);

        /**
         * \brief Write the object contents to CBOR.
         *
         * \param enc CBOR stream to write to.
         */
        void writeCbor(CborBaseEncoder& enc);
    };

    /**
     * \brief Calculate a hash value for the item.
     *
     * \param mmd message data item.
     * \returns hash value.
     */
    std::size_t hash_value(const MalformedMessageData& mmd);

    /**
     * \struct MalformedMessageItem
     * \brief Individual malformed messages.
     */
    struct MalformedMessageItem
    {
        /**
         * \brief Default constructor.
         */
        MalformedMessageItem()
        {
            clear();
        }

        /**
         * \brief Clear the malformed message.
         */
        void clear();

        /**
         * \brief the timestamp.
         */
        boost::optional<std::chrono::system_clock::time_point> tstamp;

        /**
         * \brief index of client address.
         */
        index_t client_address;

        /**
         * \brief client port.
         */
        boost::optional<uint16_t> client_port;

        /**
         * \brief index of message data.
         */
        index_t message_data;

        /**
         * \brief Read the object contents from CBOR.
         *
         * \param dec           CBOR stream to read from.
         * \param earliest_time earliest time in block.
         * \param block_parameters parameters for this block.
         * \param fields        translate map keys to internal values.
         * \throws cbor_file_format_error on unexpected CBOR content.
         * \throws cbor_decode_error on malformed CBOR items.
         * \throws cbor_end_of_input on end of CBOR file.
         */
        void readCbor(CborBaseDecoder& dec,
                      const std::chrono::system_clock::time_point& earliest_time,
                      const BlockParameters& block_parameters,
                      const FileVersionFields& fields);

        /**
         * \brief Write the object contents to CBOR.
         *
         * \param enc           CBOR stream to write to.
         * \param earliest_time earliest time in block.
         * \param block_parameters parameters for this block.
         */
        void writeCbor(CborBaseEncoder& enc,
                       const std::chrono::system_clock::time_point& earliest_time,
                       const BlockParameters& block_parameters);
    };

    /**
     * \class KeyRef
     * \brief A class to let a reference act as a map key.
     */
    template<typename T>
    class KeyRef
    {
    public:
        /**
         * \brief Constructor.
         *
         * \param key a reference to the key item.
         */
        explicit KeyRef(const T& key) : key_(key) { }

        /**
         * \brief Equality operator.
         *
         * \param rhs the ker reference to compare to.
         * \returns `true` if the two referenced items are equal.
         */
        bool operator==(const KeyRef<T>& rhs) const
        {
            return ( key_ == rhs.key_ );
        }

        /**
         * \brief Inequality operator.
         *
         * \param rhs the ker reference to compare to.
         * \returns `false` if the two referenced items are equal.
         */
        bool operator!=(const KeyRef<T>& rhs) const
        {
            return !( *this == rhs );
        }

        /**
         * \brief Calculate a hash value for the referenced item.
         *
         * \returns hash value.
         */
        friend std::size_t hash_value(const KeyRef<T>& k)
        {
            boost::hash<T> hash_func;
            return hash_func(k.key_);
        }

    private:
        /**
         * \brief reference to the item.
         */
        const T& key_;
    };

    /**
     * \class HeaderList
     * \brief A list of header items of particular type.
     *
     * Header items are stored in an array of the values, and a reference
     * to the value used elsewhere. The reference is the array index plus 1;
     * index 0 is reserved to mean 'not present'.
     *
     * Header items are not duplicated. An attempt to add a duplicate value
     * gives back the index of the original.
     *
     * Header items may be stored under a separately nominated key type.
     * They must also have a 'key()' method returing from the item the
     * key value used for that item. This must be of the key type. The aim
     * of all this is to make the map keys a reference to the value in
     * the main item deque, and so avoid the heap overhead of duplicating
     * the key values.
     */
    template<typename T, typename K = T>
    class HeaderList
    {
    public:
        /**
         * \brief Default constructor.
         */
        explicit HeaderList(bool one_based = false)
            : one_based_(one_based) {}

        /**
         * \brief Find if a key value is in the list.
         *
         * \param key   the key value to search for.
         * \param index the index of the item, if found.
         * \returns `true` if the item is found.
         */
        bool find(const K& key, index_t& index)
        {
            auto find = map_.find(KeyRef<K>(key));
            if ( find != map_.end() )
            {
                index = find->second;
                return true;
            }
            else
            {
                index = boost::none;
                return false;
            }
        }

        /**
         * \brief Add a new value to the list.
         *
         * Add a new value to the list and update the map to reference
         * the location of the value in the vector.
         *
         * \param val the value to add.
         * \returns index reference to the value.
         */
        index_t add_value(const T& val)
        {
            items_.push_back(val);
            return record_last_key();
        }

        /**
         * \brief Add a new value to the list.
         *
         * Add a new value to the list and update the map to reference
         * the location of the value in the vector.
         *
         * \param val the value to add.
         * \returns index reference to the value.
         */
        index_t add_value(T&& val)
        {
            items_.push_back(val);
            return record_last_key();
        }

        /**
         * \brief Add a new value to the list.
         *
         * If the value is present in the list already, return the existing
         * value index. Otherwise add the value to the list.
         *
         * \param val the value to add.
         * \returns index reference to the value.
         */
        index_t add(const T& val)
        {
            const K& key = val.key();
            index_t res;
            if ( !find(key, res) )
                res = add_value(val);
            return res;
        }

        /**
         * \brief Clear the list contents.
         */
        void clear()
        {
            items_.clear();
            map_.clear();
        }

        /**
         * \brief Get the indexed item.
         *
         * \param pos the index.
         */
        const T& operator[](index_t pos) const
        {
            if ( one_based_ )
            {
                if ( *pos > 0 || *pos <= items_.size() )
                    return items_[*pos - 1];
            }
            else
            {
                if ( *pos < items_.size() )
                    return items_[*pos];
            }
            throw cbor_file_format_error("Block index out of range");
        }

        /**
         * \brief Get the number of items stored.
         */
        typename std::deque<T>::size_type size() const
        {
            return items_.size();
        }

        /**
         * \brief Read the object contents from CBOR.
         *
         * \param dec      CBOR stream to read from.
         * \param fields   translate map keys to internal values.
         * \throws cbor_file_format_error on unexpected CBOR content.
         * \throws cbor_decode_error on malformed CBOR items.
         * \throws cbor_end_of_input on end of CBOR file.
         */
        void readCbor(CborBaseDecoder& dec,
                      const FileVersionFields& fields)
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

                T item;
                item.readCbor(dec, fields);
                add(item);
            }
        }

        /**
         * \brief Write the list to CBOR.
         *
         * \param enc     CBOR stream to write to.
         */
        void writeCbor(CborBaseEncoder& enc)
        {
            enc.writeArrayHeader(items_.size());
            for ( auto& i : items_ )
                i.writeCbor(enc);
        }

        /**
         * \brief Iterator begin
         *
         * \returns iterator.
         */
        typename std::deque<T>::iterator begin()
        {
            return items_.begin();
        }

        /**
         * \brief Iterator end
         *
         * \returns iterator.
         */
        typename std::deque<T>::iterator end()
        {
            return items_.end();
        }

    private:
        /**
         * \brief Record the key to the latest item in the vector.
         *
         * \returns index reference to the value.
         */
        index_t record_last_key()
        {
            index_t res = items_.size();
            if ( !one_based_ )
                res = *res - 1;
            map_[KeyRef<K>(items_.back().key())] = *res;
            return res;
        }

        /**
         * \brief header items. Must grow efficiently and not change references.
         */
        std::deque<T> items_;

        /**
         * \brief map of values present.
         */
        std::unordered_map<KeyRef<K>, index_t, boost::hash<KeyRef<K>>> map_;

        /**
         * \brief are indexes 1-based?
         *
         * If not, they are 0-based.
         */
        bool one_based_;
    };

    /**
     * \struct BlockData
     * \brief The output blocks.
     *
     * This structure accumulates the data to be written in a block.
     */
    struct BlockData
    {
    private:
        /**
         * \brief the array of block parameters for this file.
         *
         * For writing we will always use entry 0.
         */
        const std::vector<BlockParameters>& block_parameters_;

    public:
        /**
         * Constructor.
         *
         * \param block_parameters vector of block parameters for this file.
         * \param file_version     the file format version.
         * \param bp_index         default index of vector item to use.
         */
        explicit BlockData(const std::vector<BlockParameters>& block_parameters,
                           FileFormatVersion file_version = FileFormatVersion::format_10,
                           unsigned bp_index = 0)
            : block_parameters_(block_parameters),
              block_parameters_index(bp_index),
              ip_addresses(file_version < FileFormatVersion::format_10),
              class_types(file_version < FileFormatVersion::format_10),
              questions(file_version < FileFormatVersion::format_10),
              resource_records(file_version < FileFormatVersion::format_10),
              names_rdatas(file_version < FileFormatVersion::format_10),
              query_response_signatures(file_version < FileFormatVersion::format_10),
              questions_lists(file_version < FileFormatVersion::format_10),
              rrs_lists(file_version < FileFormatVersion::format_10),
              malformed_message_data(file_version < FileFormatVersion::format_10)
        {
            init();
        }

        /**
         * \brief the earliest time of any entry in the block.
         */
        std::chrono::system_clock::time_point earliest_time;

        /**
         * \brief the index of the parameters applicable to this block.
         */
        unsigned block_parameters_index;

        /**
         * \brief packet statistics at the start of the block.
         */
        PacketStatistics start_packet_statistics;

        /**
         * \brief packet statistics at the latest item added.
         */
        PacketStatistics last_packet_statistics;

        // Header items.

        /**
         * \brief the header list of IP addresses.
         */
        HeaderList<ByteStringItem, byte_string> ip_addresses;

        /**
         * \brief the header list of CLASS/TYPE pairs.
         */
        HeaderList<ClassType> class_types;

        /**
         * \brief the header list of Questions.
         */
        HeaderList<Question> questions;

        /**
         * \brief the header list of Resource Records.
         */
        HeaderList<ResourceRecord> resource_records;

        /**
         * \brief the header list of NAMEs or RDATA.
         */
        HeaderList<ByteStringItem, byte_string> names_rdatas;

        /**
         * \brief the header list of query signatures.
         */
        HeaderList<QueryResponseSignature> query_response_signatures;

        /**
         * \brief the header list of question lists.
         */
        HeaderList<IndexVectorItem, std::vector<index_t>> questions_lists;

        /**
         * \brief the header list of RR lists.
         */
        HeaderList<IndexVectorItem, std::vector<index_t>> rrs_lists;

        /**
         * \brief the header list of malformed message data.
         */
        HeaderList<MalformedMessageData> malformed_message_data;

        /**
         * \brief the block list of completed query responses.
         */
        std::vector<QueryResponseItem> query_response_items;

        /**
         * \brief the list of address event counts.
         */
        std::unordered_map<AddressEventItem, unsigned, boost::hash<AddressEventItem>> address_event_counts;

        /**
         * \brief the block list of malformed messages.
         */
        std::vector<MalformedMessageItem> malformed_messages;

        /**
         * \brief Clear all block data.
         */
        void clear()
        {
            ip_addresses.clear();
            class_types.clear();
            questions.clear();
            resource_records.clear();
            names_rdatas.clear();
            query_response_signatures.clear();
            query_response_items.clear();
            questions_lists.clear();
            rrs_lists.clear();
            address_event_counts.clear();
            malformed_message_data.clear();
            malformed_messages.clear();
        }

        /**
         * \brief Clear all block data and statistics.
         */
        void init()
        {
            clear();
            start_packet_statistics = {};
            last_packet_statistics = {};
        }

        /**
         * \brief determine if the block is full.
         *
         * \returns `true` if the block is full.
         */
        bool is_full()
        {
            unsigned max_block_items = block_parameters_[block_parameters_index].storage_parameters.max_block_items;
            return
                ( query_response_items.size() >= max_block_items ||
                  address_event_counts.size() >= max_block_items ||
                  malformed_messages.size() >= max_block_items );
        }

        /**
         * brief Add a new IP address to the block headers.
         *
         * \param addr the address to add.
         * \returns the index of the address.
         */
        index_t add_address(const byte_string& addr)
        {
            index_t res;
            if ( !ip_addresses.find(addr, res) )
            {
                ByteStringItem item;
                item.str = addr;
                res = ip_addresses.add_value(std::move(item));
            }
            return res;
        }

        /**
         * brief Add a new class/type to the block headers.
         *
         * \param ct the class/type to add.
         * \returns the index of the class/type.
         */
        index_t add_classtype(const ClassType& ct)
        {
            return class_types.add(ct);
        }

        /**
         * brief Add a new query response signature to the block headers.
         *
         * \param qs the query response signature to add.
         * \returns the index of the query response signature.
         */
        index_t add_query_response_signature(const QueryResponseSignature& qs)
        {
            return query_response_signatures.add(qs);
        }

        /**
         * brief Add a new question to the block headers.
         *
         * \param q the question to add.
         * \returns the index of the question.
         */
        index_t add_question(const Question& q)
        {
            return questions.add(q);
        }

        /**
         * brief Add a new questions list to the block headers.
         *
         * \param ql the questions list to add.
         * \returns the index of the questions list.
         */
        index_t add_questions_list(const std::vector<index_t>& ql)
        {
            index_t res;
            if ( !questions_lists.find(ql, res) )
            {
                IndexVectorItem item;
                item.vec = ql;
                res = questions_lists.add_value(std::move(item));
            }
            return res;
        }

        /**
         * brief Add a new NAME or RDATA to the block headers.
         *
         * \param rd the NAME or RDATA to add.
         * \returns the index of the NAME or RDATA.
         */
        index_t add_name_rdata(const byte_string& rd)
        {
            index_t res;
            if ( !names_rdatas.find(rd, res) )
            {
                ByteStringItem item;
                item.str = rd;
                res = names_rdatas.add_value(std::move(item));
            }
            return res;
        }

        /**
         * brief Add a new RR to the block headers.
         *
         * \param rr the RR to add.
         * \returns the index of the RR.
         */
        index_t add_resource_record(const ResourceRecord& rr)
        {
            return resource_records.add(rr);
        }

        /**
         * brief Add a new RR list to the block headers.
         *
         * \param rl the RR list to add.
         * \returns the index of the RR list.
         */
        index_t add_rrs_list(const std::vector<index_t>& rl)
        {
            index_t res;
            if ( !rrs_lists.find(rl, res) )
            {
                IndexVectorItem item;
                item.vec = rl;
                res = rrs_lists.add_value(std::move(item));
            }
            return res;
        }

        /**
         * brief Add a new malformed message data to the block headers.
         *
         * \param mmd the malformed message data to add.
         * \returns the index of the malformed message data.
         */
        index_t add_malformed_message_data(const MalformedMessageData& mmd)
        {
            return malformed_message_data.add(mmd);
        }

        /**
         * \brief Count the AddressEvent.
         *
         * \param ae the AddressEvent.
         * \param type       the type of address event.
         * \param code       the event code.
         * \param address    the address.
         */
        void count_address_event(const AddressEvent::EventType& type,
                                 unsigned code,
                                 const byte_string& address,
                                 bool is_ipv6)
        {
            AddressEventItem aei;

            aei.type = type;
            aei.code = code;
            aei.address = add_address(address);
            aei.transport_flags = is_ipv6 ? 1 : 0;

            auto search = address_event_counts.find(aei);
            if ( search != address_event_counts.end() )
                ++search->second;
            else
                address_event_counts[aei] = 1;
        }

        /**
         * \brief Read the object contents from CBOR.
         *
         * \param dec      CBOR stream to read from.
         * \param fields   translate map keys to internal values.
         * \throws cbor_file_format_error on unexpected CBOR content.
         * \throws cbor_decode_error on malformed CBOR items.
         * \throws cbor_end_of_input on end of CBOR file.
         */
        void readCbor(CborBaseDecoder& dec,
                      const FileVersionFields& fields);

        /**
         * \brief Read the block preamble.
         *
         * \param dec    CBOR stream to read from.
         * \param fields translate map keys to internal values.
         */
        void readBlockPreamble(CborBaseDecoder& dec, const FileVersionFields& fields);

        /**
         * \brief Read header tables from CBOR.
         *
         * \param dec      CBOR stream to read from.
         * \param fields   translate map keys to internal values.
         */
        void readHeaders(CborBaseDecoder& dec,
                         const FileVersionFields& fields);

        /**
         * \brief Read block query/response items from CBOR.
         *
         * \param dec      CBOR decoder.
         * \param fields   translate map keys to internal values.
         */
        void readItems(CborBaseDecoder& dec,
                       const FileVersionFields& fields);

        /**
         * \brief Read block statistics from CBOR. Accumulate the stats over
         *  multiple blocks when reading.
         *
         * \param dec CBOR decoder.
         * \param fields translate map keys to internal values.
         */
        void readStats(CborBaseDecoder& dec, const FileVersionFields& fields);

        /**
         * \brief Read block address event counts from CBOR.
         *
         * \param dec CBOR decoder.
         * \param fields translate map keys to internal values.
         */
        void readAddressEventCounts(CborBaseDecoder& dec,
                                    const FileVersionFields& fields);

        /**
         * \brief Read block malformed message from CBOR.
         *
         * \param dec CBOR decoder.
         * \param fields translate map keys to internal values.
         */
        void readMalformedMessageItems(CborBaseDecoder& dec, const FileVersionFields& fields);

        /**
         * \brief Write the block out CBOR encoded.
         *
         * \param enc     the CBOR encoder to use for the write.
         */
        void writeCbor(CborBaseEncoder& enc);

        /**
         * \brief Write block headers.
         *
         * \param enc     the CBOR encoder to use for the write.
         */
        void writeHeaders(CborBaseEncoder& enc);

        /**
         * \brief Write items.
         *
         * \param enc     the CBOR encoder to use for the write.
         */
        void writeItems(CborBaseEncoder& enc);

        /**
         * \brief Write block stats.
         *
         * \param enc the CBOR encoder to use for the write.
         */
        void writeStats(CborBaseEncoder& enc);

        /**
         * \brief Write AddressEvent counts.
         *
         * \param enc the CBOR encoder to use for the write.
         */
        void writeAddressEventCounts(CborBaseEncoder& enc);

        /**
         * \brief Write malformed messages.
         *
         * \param enc the CBOR encoder to use for the write.
         */
        void writeMalformedMessageItems(CborBaseEncoder& enc);
    };
}

#endif
