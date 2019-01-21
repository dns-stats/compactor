/*
 * Copyright 2018-2019 Internet Corporation for Assigned Names and Numbers, Sinodun IT.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <chrono>
#include <stdexcept>
#include <string>

#include <ctemplate/template.h>
#include <ctemplate/template_modifiers.h>

#include "config.h"

#include "capturedns.hpp"
#include "geoip.hpp"
#include "log.hpp"

#include "template-backend.hpp"

/**
 ** Modifiers
 **/

namespace
{
    class CStringModifier : public ctemplate::TemplateModifier
    {
    public:
        // cppcheck-suppress unusedFunction
        virtual void Modify(const char* in, size_t inlen,
                            const ctemplate::PerExpandData* per_expand_data,
                            ctemplate::ExpandEmitter* out,
                            const std::string& arg) const
        {
            const char* pos = in;
            const char* const limit = in + inlen;

            while (pos < limit) {
                switch (*pos) {
                case '\0':
                    out->Emit("\\0");
                    break;

                case '\b':
                    out->Emit("\\b");
                    break;

                case '\t':
                    out->Emit("\\t");
                    break;

                case '\n':
                    out->Emit("\\n");
                    break;

                case '\r':
                    out->Emit("\\r");
                    break;

                case '\\':
                    out->Emit("\\\\");
                    break;

                case '"':
                    out->Emit("\\\"");
                    break;

                case '\'':
                    out->Emit("\\'");
                    break;

                default:
                    if ( std::use_facet<std::ctype<char>>(loc).is(std::ctype<char>::print, *pos) )
                    {
                        out->Emit(pos, 1);
                    }
                    else
                    {
                        out->Emit("\\x");

                        char buf[2];
                        unsigned char nyb = (*pos >> 4) & 0xf;
                        buf[0] = ( nyb > 9 ) ? 'a' + nyb - 10 : '0' + nyb;
                        nyb = *pos & 0xf;
                        buf[1] = ( nyb > 9 ) ? 'a' + nyb - 10 : '0' + nyb;
                        out->Emit(buf, 2);
                    }
                    break;
                }
                pos++;
            }
        }

    private:
        std::locale loc;
    };

    class HexStringModifier : public ctemplate::TemplateModifier
    {
    public:
        virtual void Modify(const char* in, size_t inlen,
                            const ctemplate::PerExpandData* per_expand_data,
                            ctemplate::ExpandEmitter* out,
                            const std::string& arg) const
        {
            const char* pos = in;
            const char* const limit = in + inlen;

            while (pos < limit) {
                switch (*pos) {
                case '\0':
                    out->Emit("\\0");
                    break;

                default:
                    out->Emit("\\x");

                    char buf[2];
                    unsigned char nyb = (*pos >> 4) & 0xf;
                    buf[0] = ( nyb > 9 ) ? 'a' + nyb - 10 : '0' + nyb;
                    nyb = *pos & 0xf;
                    buf[1] = ( nyb > 9 ) ? 'a' + nyb - 10 : '0' + nyb;
                    out->Emit(buf, 2);
                    break;
                }
                pos++;
            }
        }
    };

    // CSV escaping as per RFC4180.
    class CSVEscapeModifier : public ctemplate::TemplateModifier
    {
    public:
        virtual void Modify(const char* in, size_t inlen,
                            const ctemplate::PerExpandData* per_expand_data,
                            ctemplate::ExpandEmitter* out,
                            const std::string& arg) const
        {
            bool need_escape = false;

            for ( const char* pos = in; pos < in + inlen; ++pos )
            {
                if ( *pos == '"' || *pos == ',' ||
                     *pos == '\r' || *pos == '\n' )
                {
                    need_escape = true;
                    break;
                }
            }

            if ( need_escape )
            {
                out->Emit('"');
                for ( const char* pos = in; pos < in + inlen; ++pos )
                {
                    if ( *pos == '"' )
                        out->Emit('"');
                    out->Emit(*pos);
                }
                out->Emit('"');
            }
            else
                out->Emit(in, inlen);
        }
    };

    class IPAddrModifier : public ctemplate::TemplateModifier
    {
    public:
        virtual void Modify(const char* in, size_t inlen,
                            const ctemplate::PerExpandData* per_expand_data,
                            ctemplate::ExpandEmitter* out,
                            const std::string& arg) const
        {
            byte_string b(reinterpret_cast<const unsigned char*>(in), inlen);
            IPAddress addr(b);
            out->Emit(addr.str());
        }
    };

    class IP6AddrModifier : public ctemplate::TemplateModifier
    {
    public:
        virtual void Modify(const char* in, size_t inlen,
                            const ctemplate::PerExpandData* per_expand_data,
                            ctemplate::ExpandEmitter* out,
                            const std::string& arg) const
        {
            byte_string b(reinterpret_cast<const unsigned char*>(in), inlen);
            IPAddress addr(b);
            Tins::IPv6Address addr6 = addr;
            out->Emit(addr6.to_string());
        }
    };

    class IP6AddrBinModifier : public ctemplate::TemplateModifier
    {
    public:
        virtual void Modify(const char* in, size_t inlen,
                            const ctemplate::PerExpandData* per_expand_data,
                            ctemplate::ExpandEmitter* out,
                            const std::string& arg) const
        {
            byte_string b(reinterpret_cast<const unsigned char*>(in), inlen);
            IPAddress addr(b);
            Tins::IPv6Address addr6 = addr;
            for ( auto b : addr6 )
                out->Emit(b);
        }
    };

    template<typename T>
    static std::string ToString(const T& val)
    {
        std::ostringstream oss;

        oss << val;
        return oss.str();
    }

    template<>
    std::string ToString(const IPAddress& addr)
    {
        return to_string(addr.asNetworkBinary());
    }

    class IPAddrGeoLocationModifier : public ctemplate::TemplateModifier
    {
    public:
        explicit IPAddrGeoLocationModifier(GeoIPContext& ctx) : ctx_(ctx) {}

        virtual void Modify(const char* in, size_t inlen,
                            const ctemplate::PerExpandData* per_expand_data,
                            ctemplate::ExpandEmitter* out,
                            const std::string& arg) const
        {
            byte_string b(reinterpret_cast<const unsigned char*>(in), inlen);
            IPAddress addr(b);
            out->Emit(ToString<uint32_t>(ctx_.location_code(addr)));
        }

    private:
        GeoIPContext& ctx_;
    };

    class IPAddrGeoASNModifier : public ctemplate::TemplateModifier
    {
    public:
        explicit IPAddrGeoASNModifier(GeoIPContext& ctx) : ctx_(ctx) {}

        virtual void Modify(const char* in, size_t inlen,
                            const ctemplate::PerExpandData* per_expand_data,
                            ctemplate::ExpandEmitter* out,
                            const std::string& arg) const
        {
            byte_string b(reinterpret_cast<const unsigned char*>(in), inlen);
            IPAddress addr(b);
            out->Emit(ToString<uint32_t>(ctx_.as_number(addr)));
        }

    private:
        GeoIPContext& ctx_;
    };

    class NoGeoLocationModifier : public ctemplate::TemplateModifier
    {
    public:
        virtual void Modify(const char* in, size_t inlen,
                            const ctemplate::PerExpandData* per_expand_data,
                            ctemplate::ExpandEmitter* out,
                            const std::string& arg) const
        {
            throw geoip_error("No GeoLocation data.");
        }
    };

    class DateModifier : public ctemplate::TemplateModifier
    {
    public:
        virtual void Modify(const char* in, size_t inlen,
                            const ctemplate::PerExpandData* per_expand_data,
                            ctemplate::ExpandEmitter* out,
                            const std::string& arg) const
        {
            std::string s(in, inlen);
            std::time_t t = static_cast<std::time_t>(std::stoll(s));
            std::tm tm = *std::gmtime(&t);
            char buf[40];
            std::strftime(buf, sizeof(buf), "%F", &tm);
            out->Emit(buf);
        }
    };

    class DateTimeModifier : public ctemplate::TemplateModifier
    {
    public:
        virtual void Modify(const char* in, size_t inlen,
                            const ctemplate::PerExpandData* per_expand_data,
                            ctemplate::ExpandEmitter* out,
                            const std::string& arg) const
        {
            std::string s(in, inlen);
            std::time_t t = static_cast<std::time_t>(std::stoll(s));
            std::tm tm = *std::gmtime(&t);
            char buf[40];
            std::strftime(buf, sizeof(buf), "%F %T", &tm);
            out->Emit(buf);
        }
    };

    CStringModifier cStringModifier;
    HexStringModifier hexStringModifier;
    CSVEscapeModifier csvEscapeModifier;
    IPAddrModifier ipaddrModifier;
    IP6AddrModifier ip6addrModifier;
    IP6AddrBinModifier ip6addrBinModifier;
    DateModifier dateModifier;
    DateTimeModifier dateTimeModifier;

    std::unique_ptr<GeoIPContext> geoip;
    std::unique_ptr<IPAddrGeoLocationModifier> ipaddr_geoloc;
    std::unique_ptr<IPAddrGeoASNModifier> ipaddr_geoasn;
    std::unique_ptr<NoGeoLocationModifier> no_geoloc;

    void load_modifiers(const std::string& db_dir)
    {
        ctemplate::AddModifier("x-cstring", &cStringModifier);
        ctemplate::AddModifier("x-hexstring", &hexStringModifier);
        ctemplate::AddModifier("x-csvescape", &csvEscapeModifier);
        ctemplate::AddModifier("x-ipaddr", &ipaddrModifier);
        ctemplate::AddModifier("x-ip6addr", &ip6addrModifier);
        ctemplate::AddModifier("x-ip6addr-bin", &ip6addrBinModifier);
        ctemplate::AddModifier("x-date", &dateModifier);
        ctemplate::AddModifier("x-datetime", &dateTimeModifier);

        try
        {
            geoip = make_unique<GeoIPContext>(db_dir);
            ipaddr_geoloc = make_unique<IPAddrGeoLocationModifier>(*geoip);
            ipaddr_geoasn = make_unique<IPAddrGeoASNModifier>(*geoip);
            ctemplate::AddModifier("x-ipaddr-geo-location", ipaddr_geoloc.get());
            ctemplate::AddModifier("x-ipaddr-geo-asn", ipaddr_geoasn.get());
        }
        catch (const geoip_error& e)
        {
            LOG_INFO << "No GeoIP data available " << e.what();
            no_geoloc = make_unique<NoGeoLocationModifier>();
            ctemplate::AddModifier("x-ipaddr-geo-location", no_geoloc.get());
            ctemplate::AddModifier("x-ipaddr-geo-asn", no_geoloc.get());
        }
    }
}

TemplateException::TemplateException(const std::string& fname, const std::string& msg)
    : std::runtime_error("Template " + fname + ": " + msg + ".")
{
}

bool TemplateBackend::loaded_modifiers = false;

TemplateBackend::TemplateBackend(const TemplateBackendOptions& opts, const std::string& fname)
    : OutputBackend(opts.baseopts), opts_(opts)
{
    if ( !loaded_modifiers )
    {
        load_modifiers(opts.geoip_db_dir_path);
        loaded_modifiers = true;
    }

    if ( !ctemplate::LoadTemplate(opts.template_name, ctemplate::DO_NOT_STRIP) )
        throw TemplateLoadException(opts.template_name);

    output_path_ = output_name(fname);

    if ( opts.baseopts.xz_output )
        writer_ = make_unique<XzStreamWriter>(output_path_, opts.baseopts.xz_preset);
    else if ( opts.baseopts.gzip_output )
        writer_ = make_unique<GzipStreamWriter>(output_path_, opts.baseopts.gzip_level);
    else
        writer_ = make_unique<StreamWriter>(output_path_, 0);
}

TemplateBackend::~TemplateBackend()
{
}

void TemplateBackend::output(std::shared_ptr<QueryResponse>& qr, const Configuration& config)
{
    IPAddress client_address, server_address;
    uint16_t client_port, server_port;
    std::chrono::system_clock::time_point query_timestamp, response_timestamp;
    const CaptureDNS *dns;
    unsigned transport_flags = 0;
    unsigned query_response_flags = 0;
    unsigned dns_flags = 0;

    ctemplate::TemplateDictionary dict("ONE_QUERY_RESPONSE");

    if ( first_line ) {
        dict.ShowSection("QUERY_RESPONSE_HEADER");
        first_line = false;
    }

    dict.SetIntValue("query_response_has_query", qr->has_query());
    dict.SetIntValue("query_response_has_response", qr->has_response());

    if ( qr->has_query() )
    {
        query_response_flags |= (1 << 0);
        auto edns0 = qr->query().dns.edns0();
        if ( edns0 )
            query_response_flags |= (1 << 3);
        dict.SetIntValue("query_response_query_has_opt", edns0 ? 1 : 0);

        client_address = qr->query().clientIP;
        server_address = qr->query().serverIP;
        client_port = qr->query().clientPort;
        server_port = qr->query().serverPort;
        query_timestamp = qr->query().timestamp;
        if ( qr->has_response() )
            response_timestamp = qr->response().timestamp;
        else
            response_timestamp = query_timestamp;

        if ( qr->query().tcp )
            transport_flags |= (1 << 0);
        dict.SetIntValue("transport_tcp", qr->query().tcp);

        dns = &qr->query().dns;

        if ( dns->questions_count() > 0 )
            query_response_flags |= (1 << 2);
        dict.SetIntValue("query_response_query_has_question", dns->questions_count() > 0);

        if ( dns->checking_disabled() )
            dns_flags |= (1 << 0);
        if ( dns->authenticated_data() )
            dns_flags |= (1 << 1);
        if ( dns->z() )
            dns_flags |= (1 << 2);
        if ( dns->recursion_available() )
            dns_flags |= (1 << 3);
        if ( dns->recursion_desired() )
            dns_flags |= (1 << 4);
        if ( dns->truncated() )
            dns_flags |= (1 << 5);
        if ( dns->authoritative_answer() )
            dns_flags |= (1 << 6);

        dict.SetIntValue("query_checking_disabled", dns->checking_disabled());
        dict.SetIntValue("query_authenticated_data", dns->authenticated_data());
        dict.SetIntValue("query_z", dns->z());
        dict.SetIntValue("query_recursion_available", dns->recursion_available());
        dict.SetIntValue("query_recursion_desired", dns->recursion_desired());
        dict.SetIntValue("query_truncated", dns->truncated());
        dict.SetIntValue("query_authoritative_answer", dns->authoritative_answer());

        if ( edns0 )
        {
            if ( edns0->do_bit() )
                dns_flags |= (1 << 7);
            dict.SetIntValue("query_do", edns0->do_bit());
            dict.SetIntValue("query_edns_version", edns0->edns_version());
            dict.SetIntValue("query_edns_udp_payload_size", edns0->udp_payload_size());
        }

        dict.SetIntValue("client_hoplimit", qr->query().hoplimit);
        dict.SetIntValue("query_len", qr->query().wire_size);

        dict.SetIntValue("query_opcode", dns->opcode());
        dict.SetIntValue("query_rcode", dns->rcode());
        dict.SetIntValue("query_qdcount", dns->questions_count());
        dict.SetIntValue("query_ancount", dns->answers_count());
        dict.SetIntValue("query_nscount", dns->authority_count());
        dict.SetIntValue("query_arcount", dns->additional_count());
    }
    else
    {
        if ( qr->response().tcp )
            transport_flags |= (1 << 0);
        dict.SetIntValue("transport_tcp", qr->response().tcp);

        client_address = qr->response().clientIP;
        server_address = qr->response().serverIP;
        client_port = qr->response().clientPort;
        server_port = qr->response().serverPort;
        query_timestamp = qr->response().timestamp;
        response_timestamp = query_timestamp;
        dns = &qr->response().dns;
    }

    if ( client_address.is_ipv6() )
        transport_flags |= (1 << 1);
    dict.SetIntValue("transport_ipv6", client_address.is_ipv6());

    dict.SetValue("timestamp_secs", ToString(std::chrono::duration_cast<std::chrono::seconds>(query_timestamp.time_since_epoch()).count()));

    dict.SetValue("timestamp_microsecs", ToString(std::chrono::duration_cast<std::chrono::microseconds>(query_timestamp.time_since_epoch()).count()));

    dict.SetValue("timestamp_nanosecs", ToString(std::chrono::duration_cast<std::chrono::nanoseconds>(query_timestamp.time_since_epoch()).count()));

    std::chrono::nanoseconds ns = response_timestamp - query_timestamp;
    dict.SetIntValue("response_delay_nanosecs", ns.count());

    dict.SetIntValue("id", dns->id());

    dict.SetValue("client_address", ToString(client_address));
    dict.SetValue("server_address", ToString(server_address));

    dict.SetIntValue("client_port", client_port);
    dict.SetIntValue("server_port", server_port);

    if ( dns->questions_count() > 0 )
    {
        dict.SetValue("query_name", ToString(CaptureDNS::decode_domain_name(dns->queries().front().dname())));
        dict.SetIntValue("query_type", dns->queries().front().query_type());
        dict.SetIntValue("query_class", dns->queries().front().query_class());
    }

    if ( qr->has_response() )
    {
        query_response_flags |= (1 << 1);
        auto edns0 = qr->response().dns.edns0();
        if ( edns0 )
            query_response_flags |= (1 << 4);
        dict.SetIntValue("query_response_response_has_opt", edns0 ? 1 : 0);
        if ( qr->response().dns.questions_count() > 0 )
            query_response_flags |= (1 << 5);

        dns = &qr->response().dns;

        dict.SetIntValue("query_response_response_has_question", dns->questions_count() > 0);

        if ( dns->checking_disabled() )
            dns_flags |= (1 << 8);
        if ( dns->authenticated_data() )
            dns_flags |= (1 << 9);
        if ( dns->z() )
            dns_flags |= (1 << 10);
        if ( dns->recursion_available() )
            dns_flags |= (1 << 11);
        if ( dns->recursion_desired() )
            dns_flags |= (1 << 12);
        if ( dns->truncated() )
            dns_flags |= (1 << 13);
        if ( dns->authoritative_answer() )
            dns_flags |= (1 << 14);

        dict.SetIntValue("response_checking_disabled", dns->checking_disabled());
        dict.SetIntValue("response_authenticated_data", dns->authenticated_data());
        dict.SetIntValue("response_z", dns->z());
        dict.SetIntValue("response_recursion_available", dns->recursion_available());
        dict.SetIntValue("response_recursion_desired", dns->recursion_desired());
        dict.SetIntValue("response_truncated", dns->truncated());
        dict.SetIntValue("response_authoritative_answer", dns->authoritative_answer());

        dict.SetIntValue("response_len", qr->response().wire_size);

        dict.SetIntValue("response_rcode", dns->rcode());

        dict.SetIntValue("response_qdcount", dns->questions_count());
        dict.SetIntValue("response_ancount", dns->answers_count());
        dict.SetIntValue("response_nscount", dns->authority_count());
        dict.SetIntValue("response_arcount", dns->additional_count());
    }

    dict.SetIntValue("transport_flags", transport_flags);
    dict.SetIntValue("query_response_flags", query_response_flags);
    dict.SetIntValue("dns_flags", dns_flags);

    for ( auto&& val : opts_.values )
        dict.SetValue(val.first, val.second);

    std::string out;

    if ( ctemplate::ExpandTemplate(opts_.template_name, ctemplate::DO_NOT_STRIP, &dict, &out) )
        writer_->writeBytes(out);
    else
        throw TemplateExpandException(output_path_);
}

std::string TemplateBackend::output_file()
{
    if ( output_path_ == StreamWriter::STDOUT_FILE_NAME )
        return "";
    return output_path_;
}
