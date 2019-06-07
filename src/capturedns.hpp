/*
 * Copyright 2016-2019 Internet Corporation for Assigned Names and Numbers.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Developed by Sinodun IT (www.sinodun.com)
 *
 * This file is based on the DNS packet type in libtins. libtins is
 * Copyright (c) 2016, Matias Fontanini. For the licence details, see
 * LICENSE.txt.
 */

#ifndef CAPTUREDNS_HPP
#define CAPTUREDNS_HPP

#include <list>
#include <string>
#include <vector>

#include <boost/optional.hpp>

#include <tins/tins.h>
#include <tins/memory_helpers.h>

#include "config.h"

#include "bytestring.hpp"

/**
 * \class CaptureDNS
 * \brief Represents a DNS PDU.
 *
 * This class represents the DNS PDU, and allows easy access
 * to queries and answer records.
 *
 * So, why has it been created? Simply, the `libtins` DNS decoder suffers
 * from problems for this capture application:
 * - it is lazy; questions and response records are only decoded when
 *   requested. This means that packet decoding problems can cause an
 *   exception to be thrown. This greatly complicates writing output to
 *   a file, as decode errors part-way through writing a record must be
 *   handled.
 * - it performs some expansion on selected response RDATA, for example
 *   expanding A and AAAA addresses to a printable string. It expects
 *   response RDATA when supplied to have gone through this expansion,
 *   and attempts to reverse it. This greatly complicates RDATA handling.
 * - names are reported after decoding, and when providing names they
 *   are then re-encoded internally. The decode/encode process is not
 *   necessarily idempotent on challenging names, for example any that
 *   have \0 bytes in label data.
 * - the capture, though, does need to expand any compressed labels in
 *   RDATA to the uncompressed label form. There are no available hooks
 *   for doing this.
 *
 * The DNS PDU is not parsed automatically while sniffing, so you will
 * have to parse it manually from an UDP packet's payload, for example:
 *
 * \code
 * // Assume we get an udp packet from somewhere.
 * UDP udp = get_udp_packet();
 *
 * // Now:
 * // 1 - Get the RawPDU layer (contains the payload).
 * // 2 - Construct a DNS object over its contents.
 * CaptureDNS dns = udp.rfind_pdu<RawPDU>().to<CaptureDNS>();
 *
 * // Now use the DNS object!
 * for(const auto& query : dns.queries()) {
 *     // Process a query
 * }
 * \endcode
 */
class CaptureDNS : public Tins::PDU
{
public:
    /**
     * \brief This PDU's flag.
     */
    static const Tins::PDU::PDUType pdu_flag = Tins::PDU::DNS;

    /**
     * \brief The DNS type.
     */
    enum QRType
    {
        QUERY = 0,
        RESPONSE = 1
    };

    /**
     * \brief DNS opcodes.
     */
    enum Opcode
    {
        OP_QUERY = 0,
        OP_IQUERY,
        OP_STATUS,
        OP_NOTIFY = 4,
        OP_UPDATE,
        OP_DSO
    };

    static const std::vector<Opcode> OPCODES;

    /**
     * \brief DNS rcodes.
     */
    enum Rcode
    {
        NOERROR = 0,
        FORMERR,
        SERVFAIL,
        NXDOMAIN,
        NOTIMP,
        REFUSED,
        YXDOMAIN,
        YXRRSET,
        NOTAUTH,
        NOTZONE,
        DSOTYPENI,
        BADVERS = 16,
        BADSIG,
        BADKEY,
        BADTIME,
        BADMODE,
        BADNAME,
        BADALG,
        BADTRUNC,
        BADCOOKIE
    };

    /**
     * \brief Query types enum.
     */
    enum QueryType
    {
        A = 1,
        NS,
        MD,
        MF,
        CNAME,
        SOA,
        MB,
        MG,
        MR,
        NULL_R,
        WKS,
        PTR,
        HINFO,
        MINFO,
        MX,
        TXT,
        RP,
        AFSDB,
        X25,
        ISDN,
        RT,
        NSAP,
        NSAP_PTR,
        SIG,
        KEY,
        PX,
        GPOS,
        AAAA,
        LOC,
        NXT,
        EID,
        NIMLOC,
        SRV,
        ATMA,
        NAPTR,
        KX,
        CERTIFICATE,
        A6,
        DNAM,
        SINK,
        OPT,
        APL,
        DS,
        SSHFP,
        IPSECKEY,
        RRSIG,
        NSEC,
        DNSKEY,
        DHCID,
        NSEC3,
        NSEC3PARAM,
        TLSA,
        HIP = 55,
        NINFO,
        RKEY,
        TALINK,
        CDS,
        SPF = 99,
        UINFO,
        UID,
        GID,
        UNSPEC,
        NID,
        L32,
        L64,
        LP,
        EU148,
        EUI64,
        TKEY = 249,
        TSIG,
        IXFR,
        AXFR,
        MAILB,
        MAILA,
        TYPE_ANY,
        URI,
        CAA,
        TA = 32768,
        DLV,

        NSEC3PARAMS = NSEC3PARAM,
        CERT = CERTIFICATE
    };

    static const std::vector<QueryType> QUERYTYPES;
    /**
     * \brief Query classes enum.
     */
    enum QueryClass
    {
        INTERNET = 1,
        CHAOS    = 3,
        HESIOD   = 4,
        /**
         * \cond
         */
        IN = INTERNET,
        CH = CHAOS,
        HS = HESIOD,
        /**
         * \endcond
         */
        CLASS_NONE = 254,
        CLASS_ANY = 255
    };

    /**
     * \brief Query types enum.
     */
    enum EDNS0Code
    {
        NSID = 3,
        DAU = 5,
        DHU,
        N3U,
        CLIENT_SUBNET,
        EXPIRE,
        COOKIE,
        TCP_KEEPALIVE,
        PADDING,
        CHAIN,
        KEY_TAG,
        DEVICE_ID = 26946
    };

    /**
     * \brief Name compression type enum.
     */
    enum NameCompression
    {
        NONE,
        DEFAULT,
        KNOT_1_6
    };

    /**
     * \brief Class that represent DNS queries.
     */
    class query
    {
    public:
        /**
         * \brief Constructs a DNS query.
         *
         * \param nm The name of the domain being resolved, in label format.
         * \param tp The query type.
         * \param cl The query class.
         */
        query(byte_string&& nm, QueryType tp, QueryClass cl)
            : name_(nm), type_(tp), qclass_(cl) {}

        /**
         * \brief Constructs a DNS query.
         *
         * \param nm The name of the domain being resolved, in label format.
         * \param tp The query type.
         * \param cl The query class.
         */
        query(const byte_string& nm, QueryType tp, QueryClass cl)
            : name_(nm), type_(tp), qclass_(cl) {}

        /**
         * \brief Constructs a DNS query.
         *
         * \param nm The name of the domain being resolved, in decoded form.
         * \param tp The query type.
         * \param cl The query class.
         */
        query(const std::string& nm, QueryType tp, QueryClass cl)
            : name_(encode_domain_name(nm)), type_(tp), qclass_(cl) {}

        /**
         * \brief Getter for the name field.
         *
         * \returns name in label format.
         */
        const byte_string& dname() const {
            return name_;
        }

        /**
         * \brief Getter for the query type field.
         *
         * \returns query type.
         */
        QueryType query_type() const {
            return type_;
        }

        /**
         * \brief Getter for the query class field.
         *
         * \returns query class.
         */
        QueryClass query_class() const {
            return qclass_;
        }
    private:
        /**
         * \brief query name (QNAME).
         */
        byte_string name_;
        /**
         * \brief query type (QTYPE).
         */
        QueryType type_;
        /**
         * \brief query class (QCLASS).
         */
        QueryClass qclass_;
    };

    /**
     * \brief Class that represent DNS resource records.
     */
    class resource
    {
    public:
        /**
         * Constructs a Resource object.
         *
         * \param dname The domain name for which this record
         * provides an answer, in label form.
         * \param data The resource's payload.
         * \param type The type of this record.
         * \param rclass The class of this record.
         * \param ttl The time-to-live of this record.
         */
        resource(byte_string&& dname,
                 byte_string&& data,
                 QueryType type,
                 QueryClass rclass,
                 uint32_t ttl)
            : dname_(dname), data_(data),
              type_(type), qclass_(rclass), ttl_(ttl) {}

        /**
         * Constructs a Resource object.
         *
         * \param dname The domain name for which this record
         * provides an answer, in label form.
         * \param data The resource's payload.
         * \param type The type of this record.
         * \param rclass The class of this record.
         * \param ttl The time-to-live of this record.
         */
        resource(const byte_string& dname,
                 const byte_string& data,
                 QueryType type,
                 QueryClass rclass,
                 uint32_t ttl)
            : dname_(dname), data_(data),
              type_(type), qclass_(rclass), ttl_(ttl) {}

        /**
         * Constructs a Resource object.
         *
         * \param dname The domain name for which this records
         * provides an answer, in decoded form.
         * \param data The resource's payload.
         * \param type The type of this record.
         * \param rclass The class of this record.
         * \param ttl The time-to-live of this record.
         */
        resource(const std::string& dname,
                 const byte_string& data,
                 QueryType type,
                 QueryClass rclass,
                 uint32_t ttl)
            : dname_(encode_domain_name(dname)), data_(data),
              type_(type), qclass_(rclass), ttl_(ttl) {}

        /**
         * \brief Getter for the domain name field.
         *
         * \returns the domain name for which this record
         * provides an answer. The name is in label format.
         */
        const byte_string& dname() const {
            return dname_;
        }

        /**
         * Getter for the data field.
         *
         * \returns resource data.
         */
        const byte_string& data() const {
            return data_;
        }

        /**
         * Getter for the query type field.
         *
         * \returns resource type.
         */
        QueryType query_type() const {
            return type_;
        }

        /**
         * Getter for the query class field.
         *
         * \returns resource class.
         */
        QueryClass query_class() const {
            return qclass_;
        }

        /**
         * Getter for the time-to-live (TTL) field.
         *
         * \returns resource TTL.
         */
        uint32_t ttl() const {
            return ttl_;
        }

    private:
        /**
         * \brief resource name.
         */
        byte_string dname_;
        /**
         * \brief resource data (RDATA).
         */
        byte_string data_;
        /**
         * \brief resource type.
         */
        QueryType type_;
        /**
         * \brief resource class.
         */
        QueryClass qclass_;
        /**
         * \brief resource time-to-live (TTL).
         */
        uint32_t ttl_;
    };

    /**
     * \brief Class the respresents an EDNS0 option.
     */
    class EDNS0_option
    {
    public:
        /**
         * \brief Constructor.
         *
         * \param code  the option code.
         * \param data  the option data.
         */
        EDNS0_option(EDNS0Code code, const byte_string &data)
            : code_(code), data_(data) {}

        /**
         * \brief Constructor.
         *
         * \param code  the option code.
         * \param data  the option data.
         */
        EDNS0_option(EDNS0Code code, byte_string &&data)
            : code_(code), data_(data) {}

        /**
         * \brief Getter for the option code.
         *
         * \returns the option code.
         */
        EDNS0Code code() const {
            return code_;
        }

        /**
         * \brief Getter for the option data.
         *
         * \returns the option data.
         */
        const byte_string& data() const {
            return data_;
        }

    private:
        /**
         * \brief option code.
         */
        EDNS0Code code_;

        /**
         * \brief option data.
         */
        byte_string data_;
    };

    /**
     * \brief Class that represents EDNS0 extensions.
     */
    class EDNS0
    {
    public:
        /**
         * \brief Typedef for list of options.
         */
        using options_type = std::list<EDNS0_option>;

        /**
         * \brief Constructor.
         *
         * \param udp_payload_size      UDP payload size.
         * \param do_bit                DO bit.
         * \param extended_rcode        Extended RCODE.
         * \param edns_version          EDNS version. Should be 0.
         */
        EDNS0(uint16_t udp_payload_size,
              bool do_bit,
              uint8_t extended_rcode,
              uint8_t edns_version = 0)
            : udp_payload_size_(udp_payload_size),
              extended_rcode_(extended_rcode),
              do_bit_(do_bit),
              edns_version_(edns_version) {}

        /**
         * \brief Constructor.
         *
         * \param resource              The resource. Must have type OPT.
         * \throws Tins::malformed_packet if resource is not OPT.
         */
        explicit EDNS0(const resource& resource)
            : udp_payload_size_(static_cast<uint16_t>(resource.query_class()))
        {
            if ( resource.query_type() != OPT )
                throw Tins::malformed_packet();

            extract_ttl_data(resource.ttl());
            extract_options(resource.data());
        }

        /**
         * \brief Constructor.
         *
         * Build from raw resource contents.
         *
         * \param query_class           The resource class.
         * \param ttl                   The resource TTL.
         * \param data                  The resource data.
         * \throws Tins::malformed_packet on resource data format error.
         */
        EDNS0(QueryClass query_class, uint32_t ttl, const byte_string& data)
            : udp_payload_size_(static_cast<uint16_t>(query_class))
        {
            extract_ttl_data(ttl);
            extract_options(data);
        }

        /**
         * \brief Getter for the UDP payload size.
         *
         * \return UDP payload size.
         */
        const uint16_t udp_payload_size() const {
            return udp_payload_size_;
        }

        /**
         * \brief Getter for the DO bit.
         *
         * \return <code>true</code> if DO bit set.
         */
        const bool do_bit() const {
            return do_bit_;
        }

        /**
         * \brief Getter for the extended RCODE.
         *
         * \returns extended RCODE.
         */
        const uint8_t extended_rcode() const {
            return extended_rcode_;
        }

        /**
         * \brief Getter for the EDNS version.
         *
         * \returns EDNS version.
         */
        const uint8_t edns_version() const {
            return edns_version_;
        }

        /**
         * \brief Getter for the individual options.
         *
         * \returns the options in this EDNS0.
         */
        const options_type& options() const {
            return options_;
        }

        /**
         * \brief Add an option.
         */
        void add_option(const EDNS0_option& opt) {
            options_.push_back(opt);
        }

        /**
         * \brief Construct the resource embodying this EDNS0.
         *
         * \returns the resource.
         */
        resource rr() const {
            return resource("",
                            make_options_data(),
                            OPT,
                            static_cast<QueryClass>(udp_payload_size_),
                            make_ttl());
        }

    private:
        /**
         * \brief Calculate the TTL value for a resource.
         *
         * \returns the TTL value.
         */
        uint32_t make_ttl() const;

        /**
         * \brief Extract EDNS0 values from a TTL.
         *
         * \param ttl the TTL.
         */
        void extract_ttl_data(uint32_t ttl);

        /**
         * \brief Construct resource data from the options.
         *
         * \returns resource data with the options.
         */
        byte_string make_options_data() const;

        /**
         * \brief Extract EDNS0 options from resource data.
         *
         * \param data the resource data.
         */
        void extract_options(const byte_string& data);

        /**
         * \brief the EDNS0 UDP payload size.
         */
        uint16_t udp_payload_size_;

        /**
         * \brief the EDNS0 extended RCODE.
         */
        uint8_t extended_rcode_;

        /**
         * \brief the EDNS0 DO bit.
         */
        bool do_bit_;

        /**
         * \brief the individual EDNS0 options.
         */
        options_type options_;

        /**
         * \brief the EDNS0 version.
         */
        uint8_t edns_version_;
    };

    /**
     * \brief Typedef for list of queries.
     */
    using queries_type = std::list<query>;

    /**
     * \brief Typedef for list of resources.
     */
    using resources_type = std::list<resource>;

    /**
     * \brief Extracts metadata for this protocol based on the buffer provided
     *
     * \param buffer Pointer to a buffer
     * \param total_sz Size of the buffer pointed by buffer
     */
    static metadata extract_metadata(const uint8_t *buffer, uint32_t total_sz);

    /**
     * \brief Constructs a DNS object from a buffer.
     *
     * If there's not enough size for the DNS header, or any of the
     * records are malformed, a malformed_packet is be thrown.
     *
     * \param buffer The buffer from which this PDU will be
     * constructed.
     * \param total_sz The total size of the buffer.
     * \throws Tins::malformed_packet if any records are malformed.
     */
    CaptureDNS(const uint8_t* buffer, uint32_t total_sz);

    /**
     * \brief Getter for the id field.
     *
     * \return uint16_t containing the value of the id field.
     */
    uint16_t id() const {
        return Tins::Endian::be_to_host(header_.id);
    }

    /**
     * \brief Getter for the query response field.
     *
     * \return QRType containing the value of the query response
     * field.
     */
    QRType type() const {
        return static_cast<QRType>(header_.qr);
    }

    /**
     * \brief Getter for the opcode field.
     *
     * \return Opcode containing the value of the opcode field.
     */
    Opcode opcode() const {
        return Opcode(header_.opcode);
    }

    /**
     * \brief Getter for the authoritative answer field.
     *
     * \return uint8_t containing the value of the authoritative
     * answer field.
     */
    uint8_t authoritative_answer() const {
        return header_.aa;
    }

    /**
     * \brief Getter for the truncated field.
     *
     * \return uint8_t containing the value of the truncated field.
     */
    uint8_t truncated() const {
        return header_.tc;
    }

    /**
     * \brief Getter for the recursion desired field.
     *
     * \return uint8_t containing the value of the recursion
     * desired field.
     */
    uint8_t recursion_desired() const {
        return header_.rd;
    }

    /**
     * \brief Getter for the recursion available field.
     *
     * \return uint8_t containing the value of the recursion
     * available field.
     */
    uint8_t recursion_available() const {
        return header_.ra;
    }

    /**
     * \brief Getter for the z desired field.
     *
     * \return uint8_t containing the value of the z field.
     */
    uint8_t z() const {
        return header_.z;
    }

    /**
     * \brief Getter for the authenticated data field.
     *
     * \return uint8_t containing the value of the authenticated
     * data field.
     */
    uint8_t authenticated_data() const {
        return header_.ad;
    }

    /**
     * \brief Getter for the checking disabled field.
     *
     * \return uint8_t containing the value of the checking
     * disabled field.
     */
    uint8_t checking_disabled() const {
        return header_.cd;
    }

    /**
     * \brief Getter for the rcode field.
     *
     * \return uint8_t containing the value of the rcode field.
     */
    uint8_t rcode() const {
        return header_.rcode;
    }

    /**
     * \brief Getter for the questions field.
     *
     * \return uint16_t containing the value of the questions field.
     */
    uint16_t questions_count() const {
        return Tins::Endian::be_to_host(header_.questions);
    }

    /**
     * \brief Getter for the answers field.
     *
     * \return uint16_t containing the value of the answers field.
     */
    uint16_t answers_count() const {
        return Tins::Endian::be_to_host(header_.answers);
    }

    /**
     * \brief Getter for the authority field.
     *
     * \return uint16_t containing the value of the authority field.
     */
    uint16_t authority_count() const {
        return Tins::Endian::be_to_host(header_.authority);
    }

    /**
     * \brief Getter for the additional field.
     *
     * \return uint16_t containing the value of the additional field.
     */
    uint16_t additional_count() const {
        return Tins::Endian::be_to_host(header_.additional);
    }

    /**
     * \brief Getter for the PDU's type.
     *
     * \return Returns the PDUType corresponding to the PDU.
     */
    PDUType pdu_type() const {
        return pdu_flag;
    }

    /**
     * \brief The header's size
     */
    uint32_t header_size() const;

    /**
     * \brief The size of trailing data after DNS content.
     */
    uint32_t trailing_data_size() const {
        return trailing_data_size_;
    }

    // Methods

    /**
     * \brief Getter for this PDU's DNS queries.
     *
     * \return The query records in this PDU.
     */
    const queries_type& queries() const {
        return queries_;
    }

    /**
     * \brief Getter for this PDU's DNS answers
     *
     * \return The answer records in this PDU.
     */
    const resources_type& answers() const {
        return answers_;
    }

    /**
     * \brief Getter for this PDU's DNS authority records.
     *
     * \return The authority records in this PDU.
     */
    const resources_type& authority() const {
        return authority_;
    }

    /**
     * \brief Getter for this PDU's DNS additional records.
     *
     * \return The additional records in this PDU.
     */
    const resources_type& additional() const {
        return additional_;
    }

    /**
     * \brief Getter for this PDU's EDNS0 (OPT) record, if it has one.
     *
     * \return Optional EDNS0 info.
     */
    const boost::optional<EDNS0>& edns0() const {
        return edns0_;
    }

    /**
     * \sa PDU::clone
     */
    CaptureDNS* clone() const {
        return new CaptureDNS(*this);
    }

    // Interfaces for constructing DNS packets.

    /**
     * \brief Default constructor.
     *
     * This constructor initializes every field to 0.
     */
    CaptureDNS();

    /**
     * \brief Setter for the id field.
     *
     * \param new_id The new id to be set.
     */
    void id(uint16_t new_id) {
        header_.id = Tins::Endian::host_to_be(new_id);
    }

    /**
     * \brief Setter for the query response field.
     *
     * \param new_qr The new qr to be set.
     */
    void type(QRType new_qr) {
        header_.qr = new_qr;
    }

    /**
     * \brief Setter for the opcode field.
     *
     * \param new_opcode The new opcode to be set.
     */
    void opcode(Opcode new_opcode) {
        header_.opcode = new_opcode;
    }

    /**
     * \brief Setter for the authoritative answer field.
     *
     * \param new_aa the value of the authoritative answer field.
     */
    void authoritative_answer(uint8_t new_aa) {
        header_.aa = new_aa;
    }

    /**
     * \brief Setter for the truncated field.
     *
     * \param new_tc the value of the truncated field.
     */
    void truncated(uint8_t new_tc) {
        header_.tc = new_tc;
    }

    /**
     * \brief Setter for the recursion desired field.
     *
     * \param new_rd the value of the recursion desired field.
     */
    void recursion_desired(uint8_t new_rd) {
        header_.rd = new_rd;
    }

    /**
     * \brief Setter for the recursion available field.
     *
     * \param new_ra the value of the recursion available field.
     */
    void recursion_available(uint8_t new_ra) {
        header_.ra = new_ra;
    }

    /**
     * \brief Setter for the z desired field.
     *
     * \param new_z the value of the z field.
     */
    void z(uint8_t new_z) {
        header_.z = new_z;
    }

    /**
     * \brief Setter for the authenticated data field.
     *
     * \param new_ad the value of the authenticated data field.
     */
    void authenticated_data(uint8_t new_ad) {
        header_.ad = new_ad;
    }

    /**
     * \brief Setter for the checking disabled field.
     *
     * \param new_cd the value of the checking disabled field.
     */
    void checking_disabled(uint8_t new_cd) {
        header_.cd = new_cd;
    }

    /**
     * \brief Setter for the rcode field.
     *
     * \param new_rcode the value of the rcode field.
     */
    void rcode(uint8_t new_rcode) {
        header_.rcode = new_rcode;
    }

    /**
     * \brief Add a query.
     *
     * \param query The query to be added.
     */
    void add_query(const query& query) {
        queries_.push_back(query);
        header_.questions = Tins::Endian::host_to_be(static_cast<uint16_t>(questions_count() + 1));
        cached_header_size_ = 0;
    }

    /**
     * \brief Add an answer.
     *
     * \param res The answer to be added.
     */
    void add_answer(const resource& res) {
        answers_.push_back(res);
        header_.answers = Tins::Endian::host_to_be(static_cast<uint16_t>(answers_count() + 1));
        cached_header_size_ = 0;
    }

    /**
     * \brief Add an authority.
     *
     * \param res The authority to be added.
     */
    void add_authority(const resource& res) {
        authority_.push_back(res);
        header_.authority = Tins::Endian::host_to_be(static_cast<uint16_t>(authority_count() + 1));
        cached_header_size_ = 0;
    }

    /**
     * \brief Add an additional.
     *
     * \param res The additional to be added.
     */
    void add_additional(const resource& res) {
        if ( res.query_type() == OPT )
            add_edns0(res.dname(), res.query_class(), res.ttl(), res.data());
        additional_.push_back(res);
        header_.additional = Tins::Endian::host_to_be(static_cast<uint16_t>(additional_count() + 1));
        cached_header_size_ = 0;
    }

    /**
     * \brief Clear any cached header size.
     */
    void clear_cached_size() const {
        cached_header_size_ = 0;
    }

    /**
     * \brief Convert a DNS name from label to printable format.
     *
     * The label must not be compressed.
     *
     * \param label the label to convert.
     * \returns the printable name.
     * \throws Tins::invalid_domain_name
     */
    static std::string decode_domain_name(const byte_string& label);

    /**
     * \brief Convert a DNS name from printable to label format.
     *
     * \param name the name to convert.
     * \returns the label.
     */
    static byte_string encode_domain_name(const std::string& name);

    /**
     * \brief Get the type of name compression to be used when serializing.
     *
     * \returns type of name compression to use.
     */
    static NameCompression name_compression()
    {
        return name_compression_;
    }

    /**
     * \brief Set the type of name compression to be used when serializing.
     *
     * \param nc type of name compression to use.
     */
    static void set_name_compression(NameCompression nc)
    {
        name_compression_ = nc;
    }

private:
    /**
     * \struct dns_header
     * \brief Structure repesenting the header layout of a DNS packet.
     */
    TINS_BEGIN_PACK
    struct dns_header {
        uint16_t id;
        #if TINS_IS_LITTLE_ENDIAN
            uint16_t
                rd:1,
                tc:1,
                aa:1,
                opcode:4,
                qr:1,
                rcode:4,
                cd:1,
                ad:1,
                z:1,
                ra:1;
        #elif TINS_IS_BIG_ENDIAN
            uint16_t
                qr:1,
                opcode:4,
                aa:1,
                tc:1,
                rd:1,
                ra:1,
                z:1,
                ad:1,
                cd:1,
                rcode:4;
        #endif
        uint16_t questions, answers,
                 authority, additional;
    } TINS_END_PACK;

    /**
     * \brief Read a DNS name and decompress it.
     *
     * The name is returned in DNS label format.
     *
     * The entire packet data is required to decompress compressed labels.
     *
     * \param s         memory stream to read from.
     * \param buffer    the whole packet data.
     * \param buflen    the length of the packet.
     * \returns the printable name.
     */
    static byte_string read_dname(Tins::Memory::InputMemoryStream& s, const uint8_t *buffer, uint32_t buflen);

    /**
     * \brief Read a DNS name at the given buffer offset and decompress it.
     *
     * The name is returned in DNS label format.
     *
     * The entire packet data is required to decompress compressed labels.
     *
     * \param offset    the buffer offset to start at.
     * \param buffer    the whole packet data.
     * \param buflen    the length of the packet.
     * \param res       add the name to the name here.
     * \param res_end   end of output buffer.
     * \returns the buffer offset for the next item after the name.
     */
    static uint16_t read_dname_offset(uint16_t offset, const uint8_t *buffer, uint32_t buflen, unsigned char*& res, const unsigned char* res_end);

    /**
     * \brief Given RDATA, expand any compressed label items therein.
     *
     * \param query_type        the query type of the RDATA.
     * \paran offset            the offset of the start of RDATA in the buffer.
     * \param len               the RDATA length.
     * \param buf               buffer containing the packet.
     * \param buflen            the length of the packet.
     * \returns the expanded RDATA.
     * \throws Tins::malformed_packet.
     */
    static byte_string expand_rr_data(uint16_t query_type, uint16_t offset, uint16_t len, const uint8_t* buf, uint16_t buflen);

    /**
     * \brief Read a Resource Record and add it.
     *
     * The entire packet data is required to decompress compressed labels.
     *
     * \param res        resources collection to add data to.
     * \param s          memory stream to read from.
     * \param buffer     the whole packet data.
     * \param buflen     the length of the packet.
     * \param allow_opt  <code>true</code> if this is an additional RR. OPT
     *                   are only allowed if so, and only one of those.
     * \returns the resource.
     * \throws Tins::malformed_packet.
     */
    void add_rr(resources_type& res, Tins::Memory::InputMemoryStream& s, const uint8_t *buffer, uint32_t buflen, bool allow_opt);

    /**
     * \brief Add EDNS0.
     *
     * \param name              the resource dname.
     * \param query_class       the query class.
     * \param ttl               the resource TTL.
     * \param data              the resource data.
     * \throws Tins::malformed_packet if bad format or OPT already present.
     */
    void add_edns0(const byte_string& dname, QueryClass query_class, uint32_t ttl, const byte_string& data);

    /**
     * \brief write serialised version of the packet.
     *
     * This function is for `libtins` use when serialising the packet.
     *  Don't use it.
     *
     * \param buffer    the packet data.
     * \param total_sz  the packet length.
     * \param parent    the parent PDU (libtins < 4.0 only).
     */
#ifdef HAVE_LIBTINS4
    void write_serialization(uint8_t* buffer, uint32_t total_sz);
#else
    void write_serialization(uint8_t* buffer, uint32_t total_sz, const PDU* parent);
#endif

    /**
     * \brief the DNS packet header.
     */
    dns_header header_;

    /**
     * \brief the packet question section.
     */
    queries_type queries_;

    /**
     * \brief the packet answers section.
     */
    resources_type answers_;

    /**
     * \brief the packet authority section.
     */
    resources_type authority_;

    /**
     * \brief the packet additional section.
     */
    resources_type additional_;

    /**
     * \brief ENDS0, if any.
     */
    boost::optional<EDNS0> edns0_;

    /**
     * \brief the amount of trailing data in the message.
     */
    uint32_t trailing_data_size_;

    /**
     * \brief cached header size value.
     */
    mutable uint32_t cached_header_size_;

    /**
     * \brief type of name compression to use when serialising.
     */
    static NameCompression name_compression_;
};

#endif
