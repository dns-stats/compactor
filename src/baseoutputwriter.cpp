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
    const DNSMessage &d(qr->has_query() ? qr->query() : qr->response());
    if ( !config_.output_opcode(d.dns.opcode()) )
         return;

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
