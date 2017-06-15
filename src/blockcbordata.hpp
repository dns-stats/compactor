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

#ifndef BLOCKEDCBORDATA_HPP
#define BLOCKEDCBORDATA_HPP

#include <chrono>
#include <deque>
#include <unordered_map>
#include <vector>

#include <boost/functional/hash.hpp>

#include "addressevent.hpp"
#include "bytestring.hpp"
#include "blockcbor.hpp"
#include "cbordecoder.hpp"
#include "cborencoder.hpp"
#include "capturedns.hpp"
#include "ipaddress.hpp"
#include "makeunique.hpp"
#include "packetstatistics.hpp"

namespace block_cbor {

    namespace {
        const unsigned DEFAULT_MAX_BLOCK_ITEMS = 5000;
    }

    // Block header table types.

    /**
     * \brief QueryResponse flags values enum.
     */
    enum QueryResponseFlags
    {
        QUERY_ONLY = (1 << 0),
        RESPONSE_ONLY = (1 << 1),
        QUERY_AND_RESPONSE = (QUERY_ONLY | RESPONSE_ONLY),
        QR_HAS_QUESTION = (1 << 2),
        QUERY_HAS_OPT = (1 << 3),
        RESPONSE_HAS_OPT = (1 << 4),
        RESPONSE_HAS_NO_QUESTION = (1 << 5),
    };

    /**
     * \brief type for the index into a header.
     *
     * Note that the index is 1-based. Index 0 is reserved for
     * 'value not present'.
     */
    using index_t = std::size_t;

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
         * \param dec    CBOR stream to read from.
         * \param fields translate map keys to internal values. Unused.
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
         * \param dec    CBOR stream to read from.
         * \param fields translate map keys to internal values. Unused.
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
     * \struct IPAddressItem
     * \brief A header list item that's an IP address.
     */
    struct IPAddressItem
    {
        /**
         * \brief the IP address.
         */
        IPAddress addr;

        /**
         * \brief return the key to be used for storing values.
         */
        const IPAddress& key() const
        {
            return addr;
        }

        /**
         * \brief Read the object contents from CBOR.
         *
         * \param dec    CBOR stream to read from.
         * \param fields translate map keys to internal values. Unused.
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
        CaptureDNS::QueryClass qclass;

        /**
         * \brief the DNS Type.
         */
        CaptureDNS::QueryType qtype;

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
        uint32_t ttl;

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
     * \brief Calculate a hash value for the item.
     *
     * \returns hash value.
     */
    std::size_t hash_value(const ResourceRecord& rr);

    /**
     * \struct QuerySignature
     * \brief A DNS Query Signature.
     */
    struct QuerySignature
    {
        /**
         * \brief Default constructor.
         */
        QuerySignature() :
            qr_flags(), server_address(), server_port(), transport_flags(),
            query_rcode(), response_rcode(), query_opcode(),
            query_edns_version(), query_edns_payload_size(),
            query_opt_rdata(), dns_flags(), query_classtype(),
            qdcount(), query_ancount(), query_nscount(), query_arcount() { }

        /**
         * \brief indicate whether query and response are present.
         */
        int qr_flags;

        /**
         * \brief index of address of the DNS server.
         */
        index_t server_address;

        /**
         * \brief port of DNS server.
         */
        uint16_t server_port;

        /**
         * \brief transport flags.
         */
        uint8_t transport_flags;

        /**
         * \brief query RCODE, incorporating extended RCODE.
         */
        uint16_t query_rcode;

        /**
         * \brief response RCODE, incorporating extended RCODE.
         */
        uint16_t response_rcode;

        /**
         * \brief query OPCODE.
         */
        uint8_t query_opcode;

        /**
         * \brief query EDNS version.
         */
        uint8_t query_edns_version;

        /**
         * \brief query EDNS UDP size
         */
        uint16_t query_edns_payload_size;

        /**
         * \brief query OPT RDATA.
         */
        index_t query_opt_rdata;

        /**
         * \brief DNS flags.
         */
        uint16_t dns_flags;

        /**
         * \brief query class/type.
         */
        index_t query_classtype;

        /**
         * \brief query or response QDCOUNT.
         */
        uint16_t qdcount;

        /**
         * \brief query ANCOUNT.
         */
        uint16_t query_ancount;

        /**
         * \brief query NSCOUNT.
         */
        uint16_t query_nscount;

        /**
         * \brief query ARCOUNT.
         */
        uint16_t query_arcount;

        /**
         * \brief return the key to be used for storing values.
         */
        const QuerySignature& key() const
        {
            return *this;
        }

        /**
         * \brief Implement equality operator.
         *
         * \param rhs item to compare to.
         * \returns `true` if the two are equal.
         */
        bool operator==(const QuerySignature& rhs) const {
            if ( qr_flags != rhs.qr_flags ||
                 server_address != rhs.server_address ||
                 server_port != rhs.server_port ||
                 transport_flags != rhs.transport_flags ||
                 dns_flags != rhs.dns_flags ||
                 qdcount != rhs.qdcount )
                return false;

            if ( ( qr_flags & QR_HAS_QUESTION ) &&
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
        bool operator!=(const QuerySignature& rhs) const {
            return !(*this == rhs);
        }

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
     * \brief Calculate a hash value for the item.
     *
     * \returns hash value.
     */
    std::size_t hash_value(const QuerySignature& qs);

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
        uint16_t client_port;

        /**
         * \brief client hop limit.
         */
        uint8_t hoplimit;

        /**
         * \brief the transaction ID.
         */
        uint16_t id;

        /**
         * \brief the timestamp.
         */
        std::chrono::system_clock::time_point tstamp;

        /**
         * \brief the response delay.
         */
        std::chrono::microseconds response_delay;

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
        uint32_t query_size;

        /**
         * \brief the size of the DNS response message.
         */
        uint32_t response_size;

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
         * \param dec           CBOR stream to read from.
         * \param earliest_time earliest time in block.
         * \param fields        translate map keys to internal values.
         * \throws cbor_file_format_error on unexpected CBOR content.
         * \throws cbor_decode_error on malformed CBOR items.
         * \throws cbor_end_of_input on end of CBOR file.
         */
        void readCbor(CborBaseDecoder& dec,
                      const std::chrono::system_clock::time_point& earliest_time,
                      const FileVersionFields& fields);

        /**
         * \brief Write the object contents to CBOR.
         *
         * \param enc           CBOR stream to write to.
         * \param earliest_time earliest time in block.
         */
        void writeCbor(CborBaseEncoder& enc,
                       const std::chrono::system_clock::time_point& earliest_time);
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
        AddressEvent::EventType type;

        /**
         * \brief AddressEvent code.
         */
        unsigned code;

        /**
         * \brief index of event address.
         */
        index_t address;

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
            return ( type == rhs.type && code == rhs.code && address == rhs.address);
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
        HeaderList() {}

        /**
         * \brief Find if a key value is in the list.
         *
         * \param key the key value to search for.
         * \returns index of the value, or 0 if not found.
         */
        index_t find(const K& key)
        {
            auto find = map_.find(KeyRef<K>(key));
            if ( find != map_.end() )
                return find->second;
            else
                return 0;
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
            index_t res = find(key);
            if ( res == 0 )
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
            return items_[pos - 1];
        }

        /**
         * \brief Get the number of items stored.
         */
        typename std::vector<T>::size_type size() const
        {
            return items_.size();
        }

        /**
         * \brief Read the object contents from CBOR.
         *
         * \param dec    CBOR stream to read from.
         * \param fields translate map keys to internal values.
         * \throws cbor_file_format_error on unexpected CBOR content.
         * \throws cbor_decode_error on malformed CBOR items.
         * \throws cbor_end_of_input on end of CBOR file.
         */
        void readCbor(CborBaseDecoder& dec, const FileVersionFields& fields)
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
         * \param enc CBOR stream to write to.
         */
        void writeCbor(CborBaseEncoder& enc)
        {
            enc.writeArrayHeader();
            for ( auto& i : items_ )
                i.writeCbor(enc);
            enc.writeBreak();
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
            map_[KeyRef<K>(items_.back().key())] = res;
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
         * \brief maximum number of query/response items in block.
         */
        unsigned max_block_qr_items_;

    public:
        /**
         * Constructor.
         *
         * \param max_block_qr_items number of query/response items to full.
         */
        BlockData(unsigned max_block_qr_items = DEFAULT_MAX_BLOCK_ITEMS)
            : max_block_qr_items_(max_block_qr_items)
        {
            init();
        }

        /**
         * \brief the earliest time of any entry in the block.
         */
        std::chrono::system_clock::time_point earliest_time;

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
        HeaderList<IPAddressItem, IPAddress> ip_addresses;

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
        HeaderList<QuerySignature> query_signatures;

        /**
         * \brief the header list of question lists.
         */
        HeaderList<IndexVectorItem, std::vector<index_t>> questions_lists;

        /**
         * \brief the header list of RR lists.
         */
        HeaderList<IndexVectorItem, std::vector<index_t>> rrs_lists;

        /**
         * \brief the block list of completed query responses.
         */
        std::vector<QueryResponseItem> query_response_items;

        /**
         * \brief the list of address event counts.
         */
        std::unordered_map<AddressEventItem, unsigned, boost::hash<AddressEventItem>> address_event_counts;

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
            query_signatures.clear();
            query_response_items.clear();
            questions_lists.clear();
            rrs_lists.clear();
            address_event_counts.clear();
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
            return ( query_response_items.size() >= max_block_qr_items_ );
        }

        /**
         * brief Add a new IP address to the block headers.
         *
         * \param addr the address to add.
         * \returns the index of the address.
         */
        index_t add_address(const IPAddress& addr)
        {
            index_t res = ip_addresses.find(addr);
            if ( res == 0 )
            {
                IPAddressItem item;
                item.addr = addr;
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
         * brief Add a new query signature to the block headers.
         *
         * \param qs the query signature to add.
         * \returns the index of the query signature.
         */
        index_t add_query_signature(const QuerySignature& qs)
        {
            return query_signatures.add(qs);
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
            index_t res = questions_lists.find(ql);
            if ( res == 0 )
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
            index_t res = names_rdatas.find(rd);
            if ( res == 0 )
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
            index_t res = rrs_lists.find(rl);
            if ( res == 0 )
            {
                IndexVectorItem item;
                item.vec = rl;
                res = rrs_lists.add_value(std::move(item));
            }
            return res;
        }

        /**
         * \brief Count the AddressEvent.
         *
         * \param ae the AddressEvent.
         */
        void count_address_event(const AddressEvent& ae)
        {
            AddressEventItem aei;

            aei.type = ae.type();
            aei.code = ae.code();
            aei.address = add_address(ae.address());

            auto search = address_event_counts.find(aei);
            if ( search != address_event_counts.end() )
                ++search->second;
            else
                address_event_counts[aei] = 1;
        }

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
         * \brief Read the block preamble.
         *
         * \param dec    CBOR stream to read from.
         * \param fields translate map keys to internal values.
         */
        void readBlockPreamble(CborBaseDecoder& dec, const FileVersionFields& fields);

        /**
         * \brief Read header tables from CBOR.
         *
         * \param dec    CBOR stream to read from.
         * \param fields translate map keys to internal values.
         */
        void readHeaders(CborBaseDecoder& dec, const FileVersionFields& fields);

        /**
         * \brief Read block query/response items from CBOR.
         *
         * \param dec    CBOR decoder.
         * \param fields translate map keys to internal values.
         */
        void readItems(CborBaseDecoder& dec, const FileVersionFields& fields);

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
        void readAddressEventCounts(CborBaseDecoder& dec, const FileVersionFields& fields);

        /**
         * \brief Write the block out CBOR encoded.
         *
         * \param enc the CBOR encoder to use for the write.
         */
        void writeCbor(CborBaseEncoder& enc);

        /**
         * \brief Write block headers.
         *
         * \param enc the CBOR encoder to use for the write.
         */
        void writeHeaders(CborBaseEncoder& enc);

        /**
         * \brief Write items.
         *
         * \param enc the CBOR encoder to use for the write.
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
    };
}

#endif
