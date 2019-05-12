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

#include "configuration.hpp"

#include "baseoutputwriter.hpp"

BaseOutputWriter::BaseOutputWriter(const Configuration& config)
    : config_(config)
{
}

void BaseOutputWriter::writeQR(const std::shared_ptr<QueryResponse>& qr,
                               const PacketStatistics& stats)
{
    checkForRotation(qr->timestamp());
    startRecord(qr);

    writeBasic(qr, stats);

    if ( qr->has_query() && config_.output_options_queries != 0 )
    {
        startExtendedQueryGroup();
        writeSections(qr->query(), config_.output_options_queries);
        endExtendedGroup();
    }
    if ( qr->has_response() && config_.output_options_responses != 0 )
    {
        startExtendedResponseGroup();
        writeSections(qr->response(), config_.output_options_responses);
        endExtendedGroup();
    }

    endRecord(qr);
}

void BaseOutputWriter::writeSections(const DNSMessage& dm, int options)
{
    if ( ( options & Configuration::EXTRA_QUESTIONS ) &&
         dm.dns.questions_count() > 1 )
    {
        bool found_one = false;
        bool skip = true;
        for ( const auto& q : dm.dns.queries() )
        {
            // Skip first question. It's only additional questions
            // we're interested in.
            if ( skip )
            {
                skip = false;
                continue;
            }

            if ( !config_.output_rr_type(q.query_type()) )
                continue;

            if ( !found_one )
            {
                found_one = true;
                startQuestionsSection();
            }
            writeQuestionRecord(q);
        }

        endSection();
    }

    if ( ( options & Configuration::ANSWERS ) &&
         dm.dns.answers_count() > 0 )
    {
        bool found_one = false;
        for ( const auto& r : dm.dns.answers() )
        {
            if ( !config_.output_rr_type(r.query_type()) )
                continue;

            if ( !found_one )
            {
                found_one = true;
                startAnswersSection();
            }
            writeResourceRecord(r);
        }
        endSection();
    }

    if ( ( options & Configuration::AUTHORITIES ) &&
         dm.dns.authority_count() > 0 )
    {
        bool found_one = false;
        for ( const auto& r : dm.dns.authority() )
        {
            if ( !config_.output_rr_type(r.query_type()) )
                continue;

            if ( !found_one )
            {
                found_one = true;
                startAuthoritySection();
            }
            writeResourceRecord(r);
        }
        endSection();
    }

    if ( ( options & Configuration::ADDITIONALS ) &&
         dm.dns.additional_count() > 0 )
    {
        bool found_one = false;
        for ( const auto& r : dm.dns.additional() )
        {
            if ( r.query_type() == CaptureDNS::QueryType::OPT &&
                 dm.dns.type() == CaptureDNS::QRType::QUERY )
                continue;

            if ( !config_.output_rr_type(r.query_type()) )
                continue;

            if ( !found_one )
            {
                found_one = true;
                startAdditionalSection();
            }
            writeResourceRecord(r);
        }

        if ( found_one )
            endSection();
    }
}

uint16_t BaseOutputWriter::dnsFlags(const std::shared_ptr<QueryResponse>& qr)
{
    uint16_t res = 0;

    if ( qr->has_query() )
    {
        const DNSMessage &q(qr->query());
        if ( q.dns.checking_disabled() )
            res |= QUERY_CD;
        if ( q.dns.authenticated_data() )
            res |= QUERY_AD;
        if ( q.dns.z() )
            res |= QUERY_Z;
        if ( q.dns.recursion_available() )
            res |= QUERY_RA;
        if ( q.dns.recursion_desired() )
            res |= QUERY_RD;
        if ( q.dns.truncated() )
            res |= QUERY_TC;
        if ( q.dns.authoritative_answer() )
            res |= QUERY_AA;

        auto edns0 = q.dns.edns0();

        if ( edns0 && edns0->do_bit() )
            res |= QUERY_DO;
    }

    if ( qr->has_response() )
    {
        const DNSMessage &r(qr->response());
        if ( r.dns.checking_disabled() )
            res |= RESPONSE_CD;
        if ( r.dns.authenticated_data() )
            res |= RESPONSE_AD;
        if ( r.dns.z() )
            res |= RESPONSE_Z;
        if ( r.dns.recursion_available() )
            res |= RESPONSE_RA;
        if ( r.dns.recursion_desired() )
            res |= RESPONSE_RD;
        if ( r.dns.truncated() )
            res |= RESPONSE_TC;
        if ( r.dns.authoritative_answer() )
            res |= RESPONSE_AA;
    }

    return res;
}

void BaseOutputWriter::setDnsFlags(DNSMessage& msg, uint16_t flags, bool query)
{
    if ( query )
    {
        if ( flags & QUERY_CD )
            msg.dns.checking_disabled(1);
        if ( flags & QUERY_AD )
            msg.dns.authenticated_data(1);
        if ( flags & QUERY_Z )
            msg.dns.z(1);
        if ( flags & QUERY_RA )
            msg.dns.recursion_available(1);
        if ( flags & QUERY_RD )
            msg.dns.recursion_desired(1);
        if ( flags & QUERY_TC )
            msg.dns.truncated(1);
        if ( flags & QUERY_AA )
            msg.dns.authoritative_answer(1);
    }
    else
    {
        if ( flags & RESPONSE_CD )
            msg.dns.checking_disabled(1);
        if ( flags & RESPONSE_AD )
            msg.dns.authenticated_data(1);
        if ( flags & RESPONSE_Z )
            msg.dns.z(1);
        if ( flags & RESPONSE_RA )
            msg.dns.recursion_available(1);
        if ( flags & RESPONSE_RD )
            msg.dns.recursion_desired(1);
        if ( flags & RESPONSE_TC )
            msg.dns.truncated(1);
        if ( flags & RESPONSE_AA )
            msg.dns.authoritative_answer(1);
    }
}

uint8_t BaseOutputWriter::transportFlags(const std::shared_ptr<QueryResponse>& qr)
{
    uint8_t res = 0;
    const DNSMessage& d(qr->has_query() ? qr->query() : qr->response());

    if ( d.tcp )
        res |= TCP;
    if ( d.clientIP.is_ipv6() )
        res |= IPV6;

    if ( qr->has_query() && qr->query().dns.trailing_data_size() > 0 )
        res |= QUERY_TRAILINGDATA;

    return res;
}
