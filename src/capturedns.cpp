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

#include <cstring>
#include <stdexcept>
#include <memory>
#include <vector>

#include <boost/version.hpp>

#include "capturedns.hpp"

using Tins::Memory::InputMemoryStream;
using Tins::Memory::OutputMemoryStream;

namespace {
    const unsigned MAX_DNAME_LEN = 512;
    const unsigned DO_BIT = (1 << 15);
}

const std::vector<CaptureDNS::Opcode> CaptureDNS::OPCODES =
{
    OP_QUERY,
    OP_IQUERY,
    OP_STATUS,
    OP_NOTIFY,
    OP_UPDATE,
    OP_DSO
};

const std::vector<CaptureDNS::QueryType> CaptureDNS::QUERYTYPES =
{
    A,
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
    HIP,
    NINFO,
    RKEY,
    TALINK,
    CDS,
    SPF,
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
    TKEY,
    TSIG,
    IXFR,
    AXFR,
    MAILB,
    MAILA,
    TYPE_ANY,
    URI,
    CAA,
    TA,
    DLV
};

CaptureDNS::NameCompression CaptureDNS::name_compression_ = CaptureDNS::DEFAULT;

uint32_t CaptureDNS::EDNS0::make_ttl() const
{
    uint32_t res = 0;
    if ( do_bit_ )
        res |= DO_BIT;
    res |= (edns_version_ << 16);
    res |= (extended_rcode_ << 24);
    return res;
}

void CaptureDNS::EDNS0::extract_ttl_data(uint32_t ttl)
{
    do_bit_ = ( (ttl & DO_BIT) != 0 );
    edns_version_ = (ttl & 0x00ff0000) >> 16;
    extended_rcode_ = (ttl & 0xff000000) >> 24;
}

byte_string CaptureDNS::EDNS0::make_options_data() const
{
    byte_string res;

    for (const auto& opt : options_)
    {
        res.push_back((opt.code() & 0xff00) >> 8);
        res.push_back(opt.code() & 0xff);
        res.push_back((opt.data().size() & 0xff00) >> 8);
        res.push_back(opt.data().size() & 0xff);
        res.append(opt.data());
    }

    return res;
}

void CaptureDNS::EDNS0::extract_options(const byte_string& data)
{
    InputMemoryStream stream(data.data(), data.size());

    while (stream)
    {
        EDNS0Code code = static_cast<EDNS0Code>(stream.read_be<uint16_t>());
        uint16_t len = stream.read_be<uint16_t>();
        if ( !stream.can_read(len) )
            throw Tins::malformed_packet();
        byte_string optdata(stream.pointer(), len);
        stream.skip(len);

        options_.emplace_back(code, std::move(optdata));
    }
}

// cppcheck-suppress unusedFunction
Tins::PDU::metadata CaptureDNS::extract_metadata(const uint8_t *, uint32_t total_sz) {
    if (TINS_UNLIKELY(sizeof(dns_header))) {
        throw Tins::malformed_packet();
    }
    return metadata(total_sz, pdu_flag, Tins::PDU::UNKNOWN);
}

CaptureDNS::CaptureDNS()
    : header_(), trailing_data_size_(0), cached_header_size_(0)
{
}

CaptureDNS::CaptureDNS(const uint8_t* buffer, uint32_t total_sz)
    : trailing_data_size_(0), cached_header_size_(0)
{
    InputMemoryStream stream(buffer, total_sz);
    stream.read(header_);

    // Questions
    for ( uint16_t i = 0; i < questions_count(); ++i )
    {
        byte_string dname(read_dname(stream, buffer, total_sz));
        uint16_t query_type = stream.read_be<uint16_t>();
        uint16_t query_class = stream.read_be<uint16_t>();
        queries_.emplace_back(std::move(dname), static_cast<QueryType>(query_type), static_cast<QueryClass>(query_class));
    }

    // RRs.
    for ( uint16_t i = 0; i < answers_count(); ++i )
        add_rr(answers_, stream, buffer, total_sz, false);
    for ( uint16_t i = 0; i < authority_count(); ++i )
        add_rr(authority_, stream, buffer, total_sz, false);
    for ( uint16_t i = 0; i < additional_count(); ++i )
        add_rr(additional_, stream, buffer, total_sz, true);

    trailing_data_size_ = stream.size();
}

byte_string CaptureDNS::read_dname(InputMemoryStream& s, const uint8_t *buffer, uint32_t buflen)
{
    unsigned char namebuf[MAX_DNAME_LEN];
    unsigned char* res = namebuf;

    uint16_t offset = s.pointer() - buffer;
    s.skip(read_dname_offset(offset, buffer, buflen, res, namebuf + sizeof(namebuf)) - offset);
    return byte_string(namebuf, res - namebuf);
}

uint16_t CaptureDNS::read_dname_offset(uint16_t offset, const uint8_t *buffer, uint32_t buflen, unsigned char*& res, const unsigned char* res_end)
{
    const uint8_t* ptr = &buffer[offset];
    const uint8_t* bufend = &buffer[buflen];
    bool followed_compression = false;
    const uint8_t* end_offset_ptr = ptr;
    const uint8_t* compress_src_ptr;
    const uint8_t* compress_target_ptr;

    if ( ptr >= bufend )
        throw Tins::malformed_packet();

    while ( *ptr != 0 )
    {
        uint16_t new_offset;
        uint8_t len;

        switch (*ptr & 0xc0)
        {
        case 0xc0:
            compress_src_ptr = ptr;
            new_offset = (*ptr++ & 0x3f) << 8;
            if ( ptr >= bufend )
                throw Tins::malformed_packet();
            new_offset += *ptr;
            if ( !followed_compression )
            {
                end_offset_ptr = ptr;
                followed_compression = true;
            }
            /*
             * Compression target must always point backwards in the
             * packet. Otherwise loops are possible.
             */
            compress_target_ptr = &buffer[new_offset];
            if ( compress_target_ptr >= compress_src_ptr )
                throw Tins::malformed_packet();
            ptr = compress_target_ptr;
            break;

        case 0:
            len = *ptr & 0x3f;
            if ( ( ptr + len + 1u ) >= bufend ||
                 ( res + len ) >= res_end )
                throw Tins::malformed_packet();
            std::memcpy(res, ptr, len + 1);
            res += len + 1;
            ptr += len + 1;
            if ( !followed_compression )
                end_offset_ptr = ptr;
            break;

        default:
            throw Tins::malformed_packet();
        }
    }

    *res++ = '\0';    // Preserve terminating '\0' empty label.
    return end_offset_ptr - buffer + 1;
}

// Implementation taken from Libtins dns.cpp.
// cppcheck-suppress unusedFunction
std::string CaptureDNS::decode_domain_name(const byte_string& label)
{
    std::string output;
    if ( label.empty() )
        return output;

    const uint8_t* ptr = label.data();
    const uint8_t* end = ptr + label.size();
    while ( *ptr )
    {
        // We can't handle offsets
        if ( (*ptr & 0xc0) )
            throw Tins::invalid_domain_name();
        else
        {
            // It's a label, grab its size.
            uint8_t size = *ptr;
            ptr++;
            if ( ptr + size > end )
                throw Tins::malformed_packet();
            // Append a dot if it's not the first one.
            if ( !output.empty() )
                output.push_back('.');
            output.append(reinterpret_cast<const char *>(ptr), size);
            ptr += size;
        }
    }

    return output;
}

// Implementation taken from Libtins dns.cpp.
byte_string CaptureDNS::encode_domain_name(const std::string& name)
{
    byte_string output;

    if ( !name.empty() )
    {
        std::size_t index, last_index = 0;

        while ( ( index = name.find('.', last_index+1) ) != std::string::npos )
        {
            output.push_back(index - last_index);
            output.append(name.begin() + last_index, name.begin() + index);
            last_index = index + 1; //skip dot
        }
        output.push_back(name.size() - last_index);
        output.append(name.begin() + last_index, name.end());
    }
    output.push_back('\0');
    return output;
}

void CaptureDNS::add_rr(CaptureDNS::resources_type& res, Tins::Memory::InputMemoryStream& s, const uint8_t *buffer, uint32_t buflen, bool allow_opt)
{
    byte_string dname(read_dname(s, buffer, buflen));
    uint16_t query_type = s.read_be<uint16_t>();
    uint16_t query_class = s.read_be<uint16_t>();
    uint32_t ttl = s.read_be<uint32_t>();
    uint16_t data_size = s.read_be<uint16_t>();
    if ( !s.can_read(data_size) )
        throw Tins::malformed_packet();
    byte_string data(expand_rr_data(query_type, s.pointer() - buffer, data_size, buffer, buflen));
    s.skip(data_size);

    if ( query_type == OPT )
    {
        // Only allowed in ADDITIONAL.
        if ( !allow_opt )
            throw Tins::malformed_packet();

        add_edns0(dname, static_cast<QueryClass>(query_class), ttl, data);
    }

    res.emplace_back(std::move(dname), std::move(data), static_cast<QueryType>(query_type), static_cast<QueryClass>(query_class), ttl);
}

void CaptureDNS::add_edns0(const byte_string& dname, QueryClass query_class, uint32_t ttl, const byte_string& data)
{
    // Name must be empty (apart from the terminating \0), and we mustn't have
    // one already.
    if ( edns0_ || dname.size() > 1 )
        throw Tins::malformed_packet();
#if BOOST_VERSION >= 105600
    edns0_.emplace(static_cast<QueryClass>(query_class), ttl, data);
#else
    edns0_ = EDNS0(static_cast<QueryClass>(query_class), ttl, data);
#endif
}

byte_string CaptureDNS::expand_rr_data(uint16_t query_type, uint16_t offset, uint16_t len, const uint8_t *buf, uint16_t buflen)
{
    byte_string res;
    uint16_t rdata_end = offset + len;
    unsigned char namebuf[MAX_DNAME_LEN];
    unsigned char* name;

    switch(query_type)
    {
    case NS:
    case CNAME:
    case PTR:
        // RDATA is a single label.
        name = namebuf;
        offset = read_dname_offset(offset, buf, buflen, name, namebuf + sizeof(namebuf));
        res = byte_string(namebuf, name - namebuf);
        break;

    case MX:
        // RDATA is 2 bytes preference followed by label.
        if ( len < 4 )
            throw Tins::malformed_packet();
        res = byte_string(buf + offset, 2);
        name = namebuf;
        offset = read_dname_offset(offset + 2, buf, buflen, name, namebuf + sizeof(namebuf));
        res.append(namebuf, name - namebuf);
        break;

    case SOA:
        // SOA is two labels followed by 5 32bit quantities.
        name = namebuf;
        offset = read_dname_offset(offset, buf, buflen, name, namebuf + sizeof(namebuf));
        res = byte_string(namebuf, name - namebuf);
        name = namebuf;
        offset = read_dname_offset(offset, buf, buflen, name, namebuf + sizeof(namebuf));
        res.append(namebuf, name - namebuf);
        if ( offset + 20 > rdata_end )
            throw Tins::malformed_packet();
        res.append(buf + offset, 20);
        break;

    case SRV:
        // RDATA is 2 bytes priority, 2 bytes weight, 2 bytes port and name.
        // Name compression is forbidden by RFC2782, but was permitted by
        // its predecessor RFC2052, so just in case...
        if ( len < 8 )
            throw Tins::malformed_packet();
        res = byte_string(buf + offset, 6);
        name = namebuf;
        offset = read_dname_offset(offset + 6, buf, buflen, name, namebuf + sizeof(namebuf));
        res.append(namebuf, name - namebuf);
        break;

    default:
        res = byte_string(buf + offset, len);
        break;
    }

    if ( offset > rdata_end )
        throw Tins::malformed_packet();
    return res;
}

namespace {

    /**
     * \brief Label location.hint enum.
     */
    enum LabelHintFlag
    {
        HINT_NONE = 0,
        HINT_QUERY = 1,
        HINT_RDATA = 1 << 1
    };

    /**
     * \brief Hints about the location of a label.
     *
     * These are used by particular types of label compression to determine
     * whether to compression the label and if so what labels can be
     * considered for compression against.
     */
    class LabelHint
    {
    public:
        /**
         * Constructor.
         *
         * \param f location type.
         * \param n RR number in RR set. If in a query, use 0.
         */
        LabelHint(LabelHintFlag f, uint16_t n = 0)
            : flag_(f), rr_no_(n) {}

        /**
         * \brief Is this label the QNAME in a query?
         *
         * \returns <code>true</code> if the label is the QNAME in a query.
         */
        bool is_query() const
        {
            return ( (flag_ & HINT_QUERY) != 0 );
        }

        /**
         * \brief Does this label occur in RDATA?
         *
         * \returns <code>true</code> if the label is in response RDATA.
         */
        bool is_rdata() const
        {
            return ( (flag_ & HINT_RDATA) != 0 );
        }

        /**
         * \brief Return the index of the RR in the RR set.
         *
         * If the label is part of a response, return the (zero based)
         * index within the RR set of the RR in which it occurs. If in
         * a query, return 0.
         */
        uint16_t rr_no() const
        {
            return rr_no_;
        }

    private:
        /**
         * \brief the hint flag.
         */
        LabelHintFlag flag_;

        /**
         * \brief the index of the RR in the RR set, 0 if in a query.
         */
        uint16_t rr_no_;
    };

    /**
     * \class LabelCompressionItem
     * \brief A label and information on its compressed representation if any.
     */
    class LabelCompressionItem
    {
        struct LabelComponent
        {
            byte_string text;
            uint16_t offset;
        };

    public:
        /**
         * \brief Constructor.
         *
         * \param label  the label.
         * \param qtype  the type of the section holding the label.
         * \param hint   hints about the label.
         * \param query  is the label in a query?
         * \param rdata  does the label occur in rdata?
         * \param offset the offset in the DNS data at which the label occurs.
         */
        LabelCompressionItem(const byte_string& label,
                             CaptureDNS::QueryType qtype,
                             LabelHint hint,
                             uint16_t offset)
            : label_(label), qtype_(qtype),
              hint_(hint), offset_(offset),
              compressed_label_prefix_(0),
              compressed_label_pos_(0)
        {
            byte_string::size_type start = 0;
            while ( label[start] != 0 )
            {
                LabelComponent lc;
                lc.offset = offset + start;
                lc.text = label.substr(start + 1, label[start]);
                components_.push_back(lc);

                start += label[start] + 1;
                if ( start >= label.size() )
                    throw std::length_error("Bad label in compression");
            }
        }

        /**
         * \brief returns the label.
         */
        const byte_string& label() const
        {
            return label_;
        }

        /**
         * \brief returns the label offset.
         */
        unsigned offset() const
        {
            return offset_;
        }

        /**
         * \brief returns the hint.
         */
        const LabelHint& hint() const
        {
            return hint_;
        }

        /**
         * \brief see if compression is already perfect.
         *
         * \returns <code>true</code> if compression is unimprovable.
         */
        bool is_compression_perfect()
        {
            if ( !compressed_label_ )
                return false;

            switch(CaptureDNS::name_compression())
            {
            case CaptureDNS::KNOT_1_6:
                return
                    ( compressed_label_prefix_ == 0 &&
                      qtype_ == compressed_label_->qtype_ );

            default:
                return ( compressed_label_prefix_ == 0 );
            }
        }

        /**
         * \brief see if compression is better than the existing.
         *
         * \param i the prefix index for the new compression.
         * \param l the other (pre-existing) label which could potentially
         *          be used to compress this label.
         * \returns <code>true</code> if compression is better than current.
         */
        bool is_compression_better(unsigned i, const std::shared_ptr<LabelCompressionItem>& l)
        {
            switch(CaptureDNS::name_compression())
            {
            case CaptureDNS::KNOT_1_6:
                // Knot does compression convenient to its internal
                // structures. We believe it only compresses against
                // the previous RR in the RRset, or the query if
                // (bug?) the query is not the same type as the RR. Also,
                // Additional records compress their NAME
                // against the data in the corresponsing Authority record.
                //
                // This set of heuristics attemps to duplicate this processing.
                // We differentiate NAME from RDATA items, and allow NAME to
                // compress against any previous (to handle the Additional
                // case).
                //
                // This doesn't give the same compression targets, but
                // is aimed at giving the same overall message length.
                if ( hint_.is_rdata() )
                {
                    if ( l->hint_.is_query() )
                    {
                        if ( hint_.rr_no() > 0 )
                            return false;
                    }
                    else
                    {
                        if ( !l->hint_.is_rdata() )
                            return false;

                        if ( qtype_ != l->qtype_ )
                            return false;

                        if ( l->hint_.rr_no() + 1 != hint_.rr_no() )
                            return false;
                    }
                }
                // Fallthrough!

            default:
                return ( !compressed_label_ || i < compressed_label_prefix_ );
            }
        }

        /**
         * \brief see if the label can be compressed using another label.
         *
         * This will update the label compression information if the other
         * label can be used to compress and provides better compression than
         * any existing compression.
         *
         * Note that labels that are root labels are not checked.
         *
         * \param l the other (pre-existing) label which could potentially
         *          be used to compress this label.
         * \throws std::length_error if the label is improperly formed.
         */
        void compress_using(const std::shared_ptr<LabelCompressionItem>& l)
        {
            // Don't compress root labels or compress using root labels.
            if ( components_.size() == 0 || l->components_.size() == 0 )
                return;

            // Do we already have a perfect compression?
            if ( is_compression_perfect() )
                return;

            unsigned my_index = components_.size() - 1;
            unsigned their_index = l->components_.size() - 1;
            unsigned matching_items = 0;
            unsigned match_prefix = my_index;

            while ( components_[my_index].text == l->components_[their_index].text )
            {
                ++matching_items;
                match_prefix = my_index;

                if ( my_index == 0 || their_index == 0 )
                    break;

                --my_index;
                --their_index;
            }

            if ( matching_items > 0 && is_compression_better(match_prefix, l) )
            {
                compressed_label_ = l;
                compressed_label_prefix_ = match_prefix;

                // If the target is already compressed, we may be trying to
                // compress against a subset of the target compressed
                // section. If so, follow the compression links until
                // we find the subset target. This seems to be what
                // Knot does, and makes no difference with the default
                // scheme, which will always find the earliest match.
                while ( compressed_label_->compressed_label_ &&
                        ( compressed_label_->components_.size() - compressed_label_->compressed_label_prefix_ ) > matching_items )
                    compressed_label_ = compressed_label_->compressed_label_;

                compressed_label_pos_ = compressed_label_->components_[compressed_label_->components_.size() - matching_items].offset;
            }
        }

        /**
         * \brief returns the compressed label.
         *
         * If the label could not be compressed, this will return the
         * uncompressed label.
         *
         * \returns the compressed label.
         */
        byte_string compressed_label() const
        {
            if ( compressed_label_ )
            {
                byte_string res;
                for ( unsigned i = 0; i < compressed_label_prefix_; ++i )
                {
                    res.push_back(components_[i].text.size());
                    res.append(components_[i].text);
                }
                res.push_back(0xc0 | (compressed_label_pos_ >> 8));
                res.push_back(compressed_label_pos_ & 0xff);
                return res;
            }
            else
                return label_;
        }

        /**
         * \brief return the size of the compressed label.
         *
         * If the label could not be compressed, this return the
         * size of the uncompressed label.
         *
         * \returns the size of the compressed label.
         */
        unsigned compressed_label_size() const
        {
            if ( compressed_label_ )
            {
                unsigned res = 2;
                for ( unsigned i = 0; i < compressed_label_prefix_; ++i )
                    res += components_[i].text.size() + 1;
                return res;
            }
            else
                return label_.size();
        }

    private:
        /**
         * \brief the uncompressed label.
         */
        byte_string label_;

        /**
         * \brief the type of the section holding the label.
         */
        CaptureDNS::QueryType qtype_;

        /**
         * \brief hints about the label.
         */
        LabelHint hint_;

        /**
         * \brief the label components.
         *
          * A component is a section of text in a label.
         */
        std::vector<LabelComponent> components_;

        /**
         * \brief the offset in the DNS message at which the label starts.
         */
        uint16_t offset_;

        /**
         * \brief if the label can be compressed, the label prefix.
         *
         * This is the count of components that aren't compressed.
         */
        unsigned compressed_label_prefix_;

        /**
         * \brief the position in the DNS message where the compressed
         * representation starts.
         */
        uint16_t compressed_label_pos_;

        /**
         * \brief the label we're compressed against.
         */
        std::shared_ptr<LabelCompressionItem> compressed_label_;
    };

    /**
     * \class LabelCompressionInfo
     * \brief Information on all labels in a message and their compression.
     */
    class LabelCompressionInfo
    {
    public:
        /**
         * \brief Default constructor.
         */
        LabelCompressionInfo() {}

        /**
         * \brief Add a new label to the message label information.
         *
         * \param label  the label.
         * \param qtype  the section type containing the label.
         * \param hint   hints about the label.
         * \param offset the offset in the DNS message at which the label starts.
         * \returns a pointer to the label compression for that label. The
         * pointer remains valid only as long as this object is valid.
         */
        std::shared_ptr<LabelCompressionItem>
        add_label(byte_string label, CaptureDNS::QueryType qtype,
                  LabelHint hint, unsigned offset)
        {
            std::shared_ptr<LabelCompressionItem> l =
                std::make_shared<LabelCompressionItem>(label, qtype, hint, offset);
            if ( CaptureDNS::name_compression() != CaptureDNS::NONE )
            {
                for ( const auto& it : items_ )
                    l->compress_using(it);
            }
            items_.push_back(l);
            return l;
        }

    private:
        /**
         * \brief the set of message labels and their compression info.
         */
        std::vector<std::shared_ptr<LabelCompressionItem>> items_;
    };

    /**
     * \class OutputBufferStream
     * \brief A Tins `OutputMemoryStream` which can report the current
     *        buffer offset.
     */
    class OutputBufferStream : public OutputMemoryStream
    {
    public:
        /**
         * \brief Constructor.
         *
         * \param buffer   the buffer to use for the stream.
         * \param total_sz the size of the buffer.
         */
        OutputBufferStream(uint8_t* buffer, size_t total_sz)
            : OutputMemoryStream(buffer, total_sz),
              buffer_start_(buffer)
        {
        }

        /**
         * \brief the current buffer offset.
         *
         * \returns the offset in the buffer at which the next item will
         *          be written.
         */
        std::ptrdiff_t offset()
        {
            return pointer() - buffer_start_;
        }

    private:
        /**
         * \brief the start of the buffer.
         */
        const uint8_t* buffer_start_;
    };

    /**
     * \brief extract label from start of byte string.
     *
     * Updates the byte string to remove the label.
     *
     * \param b input byte string.
     * \returns the label.
     */
    byte_string extract_label(byte_string& b)
    {
        byte_string::size_type start = 0;
        while (b[start] != 0)
            start += b[start] + 1;
        ++start;
        byte_string res = b.substr(0, start);
        b = b.substr(start);
        return res;
    }

    /**
     * \brief compress resource data.
     *
     * \param rdata  resource data.
     * \param type   resource data type.
     * \param offset initial output offset.
     * \param lci    label compression info.
     * \param rr_no  RR index number, first is 0.
     * \returns compressed resource data.
     */
    byte_string compress_rdata(byte_string rdata,
                               CaptureDNS::QueryType type,
                               uint16_t offset,
                               LabelCompressionInfo& lci,
                               uint16_t rr_no)
    {
        byte_string res;
        std::shared_ptr<LabelCompressionItem> l;
        LabelHint hint(HINT_RDATA, rr_no);

        switch(type)
        {
        case CaptureDNS::NS:
        case CaptureDNS::CNAME:
        case CaptureDNS::PTR:
            // RDATA is a single label.
            l = lci.add_label(rdata, type, hint, offset);
            return l->compressed_label();

        case CaptureDNS::MX:
            // RDATA is 2 bytes preference followed by label.
            res = rdata.substr(0, 2);
            offset += 2;
            rdata = rdata.substr(2);
            l = lci.add_label(extract_label(rdata), type, hint, offset);
            res.append(l->compressed_label());
            return res;

        case CaptureDNS::SOA:
            // Two labels followed by 5 32bit quantities.
            l = lci.add_label(extract_label(rdata), type, hint, offset);
            offset += l->compressed_label_size();
            res = l->compressed_label();
            l = lci.add_label(extract_label(rdata), type, hint, offset);
            res.append(l->compressed_label());
            res.append(rdata);
            return res;

        default:
            return rdata;
        }
    }

    /**
     * \brief write serialised query.
     *
     * \param stream stream to serialise to.
     * \param q      query to serialise.
     * \param lci    label compression info.
     */
    void serialise_query(OutputBufferStream& stream,
                         const CaptureDNS::query& q,
                         LabelCompressionInfo& lci)
    {
        auto l = lci.add_label(q.dname(), q.query_type(),
                               LabelHint(HINT_QUERY), stream.offset());
        stream.write(l->compressed_label().data(), l->compressed_label().size());
        stream.write_be<uint16_t>(q.query_type());
        stream.write_be<uint16_t>(q.query_class());
    }

    /**
     * \brief write serialised resource.
     *
     * \param stream stream to serialise to.
     * \param r      resource to serialise.
     * \param lci    label compression info.
     * \param rr_no  RR index number, first is 0.
     */
    void serialise_resource(OutputBufferStream& stream,
                            const CaptureDNS::resource& r,
                            LabelCompressionInfo& lci,
                            uint16_t rr_no)
    {
        auto l = lci.add_label(r.dname(), r.query_type(),
                               LabelHint(HINT_NONE, rr_no), stream.offset());
        stream.write(l->compressed_label().data(), l->compressed_label().size());
        stream.write_be<uint16_t>(r.query_type());
        stream.write_be<uint16_t>(r.query_class());
        stream.write_be(r.ttl());

        // Note the size is written before the data, so the offset
        // must be at the start of where the data will appear.
        byte_string rdata =
            compress_rdata(r.data(), r.query_type(),
                           stream.offset() + sizeof(uint16_t),
                           lci, rr_no);
        stream.write_be<uint16_t>(rdata.size());
        stream.write(rdata.data(), rdata.size());
    }


    /**
     * \brief write serialised resource section.
     *
     * \param stream stream to serialise to.
     * \param s      resource section to write.
     * \param lci    label compression info.
     */
    void serialise_resource_section(OutputBufferStream& stream,
                                    const CaptureDNS::resources_type& s,
                                    LabelCompressionInfo& lci)
    {
        uint16_t rr_no = 0;
        CaptureDNS::QueryType last_qtype;
        bool first = true;

        for ( const auto& r : s )
        {
            if ( first )
            {
                last_qtype = r.query_type();
                first = false;
            }
            else
            {
                if ( r.query_type() == last_qtype )
                    ++rr_no;
                else
                    rr_no = 0;
            }

            serialise_resource(stream, r, lci, rr_no);
        }
    }

    /**
     * \brief calculate serialised query size.
     *
     * \param q      query to size.
     * \param lci    label compression info.
     * \returns size of the serialised query.
     */
    uint32_t size_query(const CaptureDNS::query& q,
                        LabelCompressionInfo& lci)
    {
        auto l = lci.add_label(q.dname(), q.query_type(),
                               LabelHint(HINT_QUERY), 0);
        return l->compressed_label_size() + sizeof(uint16_t) * 2;
    }

    /**
     * \brief calculate serialised resource size.
     *
     * \param r      resource to size.
     * \param lci    label compression info.
     * \param rr_no  RR index number within set.
     * \returns size of the serialised resource.
     */
    uint32_t size_resource(const CaptureDNS::resource& r,
                           LabelCompressionInfo& lci,
                           uint16_t rr_no)
    {
        auto l = lci.add_label(r.dname(), r.query_type(),
                               LabelHint(HINT_NONE, rr_no), 0);
        return
            l->compressed_label_size() +
            sizeof(uint16_t) * 3 +
            sizeof(uint32_t) +
            compress_rdata(r.data(), r.query_type(), 0, lci, rr_no).size();
    }

    /**
     * \brief calculate serialised resource section size.
     *
     * \param s      resource section to size.
     * \param lci    label compression info.
     * \returns size of the serialised section.
     */
    uint32_t size_resource_section(const CaptureDNS::resources_type& s,
                                   LabelCompressionInfo& lci)
    {
        uint32_t res = 0;
        uint16_t rr_no = 0;
        CaptureDNS::QueryType last_qtype;
        bool first = true;

        for ( const auto& r : s )
        {
            if ( first )
            {
                last_qtype = r.query_type();
                first = false;
            }
            else
            {
                if ( r.query_type() == last_qtype )
                    ++rr_no;
                else
                    rr_no = 0;
            }

            res += size_resource(r, lci, rr_no);
        }

        return res;
    }
}

// This is used by libtins only.
#ifdef HAVE_LIBTINS4
// cppcheck-suppress unusedFunction
void CaptureDNS::write_serialization(uint8_t* buffer, uint32_t total_sz)
#else
void CaptureDNS::write_serialization(uint8_t* buffer, uint32_t total_sz, const PDU *)
#endif
{
    LabelCompressionInfo lci;
    OutputBufferStream stream(buffer, total_sz);
    stream.write(header_);
    for ( const auto& q : queries_ )
        serialise_query(stream, q, lci);

    serialise_resource_section(stream, answers_, lci);
    serialise_resource_section(stream, authority_, lci);
    serialise_resource_section(stream, additional_, lci);
}

// This is used by libtins only.
// cppcheck-suppress unusedFunction
uint32_t CaptureDNS::header_size() const
{
    // libtins calls this function frequently, expecting it to be
    // trivial to calculate (I presume). Since, due mostly to name
    // compression, it is not trivial, cache the result and use that
    // where possible.
    if ( cached_header_size_ != 0 )
        return cached_header_size_;

    // OK, we're going to have to calculate this.
    LabelCompressionInfo lci;

    uint32_t res = sizeof(header_);
    for ( const auto& q : queries_ )
        res += size_query(q, lci);

    res += size_resource_section(answers_, lci);
    res += size_resource_section(authority_, lci);
    res += size_resource_section(additional_, lci);
    cached_header_size_ = res;
    return res;
}
