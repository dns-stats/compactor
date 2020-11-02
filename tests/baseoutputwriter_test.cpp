/*
 * Copyright 2016-2017, 2019, 2020 Internet Corporation for Assigned Names and Numbers.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Developed by Sinodun IT (www.sinodun.com)
 */

#include <chrono>
#include <memory>
#include <sstream>

#include "bytestring.hpp"
#include "catch.hpp"
#include "configuration.hpp"
#include "dnsmessage.hpp"
#include "makeunique.hpp"
#include "queryresponse.hpp"

#include "baseoutputwriter.hpp"

std::ostream& operator<<(std::ostream& output, const std::chrono::system_clock::time_point& timestamp)
{
    std::time_t t = std::chrono::system_clock::to_time_t(timestamp);
    std::tm tm = *std::gmtime(&t);
    char buf[40];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %Hh%Mm%Ss", &tm);
    output << buf;
    return output;
}

class TestBaseOutputWriter : public BaseOutputWriter
{
public:
    TestBaseOutputWriter(const Configuration& config)
        : BaseOutputWriter(config) {}

    virtual void checkForRotation(const std::chrono::system_clock::time_point&)
    {
    }

    virtual void writeAE(const std::shared_ptr<AddressEvent>& /* ae */,
                         const PacketStatistics& /* stats */)
    {
        add_action("writeAE");
    }

    virtual void startRecord(const std::shared_ptr<QueryResponse>& qr)
    {
        std::ostringstream ostr;

        ostr << "startRecord:" << qr->timestamp();
        add_action(ostr.str());
    }

    virtual void endRecord(const std::shared_ptr<QueryResponse>& qr)
    {
        std::ostringstream ostr;

        ostr << "endRecord:" << qr->timestamp();
        add_action(ostr.str());
    }

    virtual void writeBasic(const std::shared_ptr<QueryResponse>& qr,
                            const PacketStatistics& /* stats */)
    {
        std::ostringstream ostr;

        ostr << "writeBasic:" << qr->timestamp();
        add_action(ostr.str());
    }

    virtual void startExtendedQueryGroup()
    {
        add_action("startExtendedQueryGroup");
    }

    virtual void startExtendedResponseGroup()
    {
        add_action("startExtendedResponseGroup");
    }

    virtual void endExtendedGroup()
    {
        add_action("endExtendedGroup");
    }

    virtual void startQuestionsSection()
    {
        add_action("startQuestionsSection");
    }

    virtual void writeQuestionRecord(const CaptureDNS::query& question)
    {
        std::ostringstream ostr;

        ostr << "writeQuestionRecord:" <<
            CaptureDNS::decode_domain_name(question.dname()) <<
            ",type:" << question.query_type();
        add_action(ostr.str());
    }

    virtual void endSection()
    {
        add_action("endSection");
    }

    virtual void startAnswersSection()
    {
        add_action("startAnswersSection");
    }

    virtual void writeResourceRecord(const CaptureDNS::resource& resource)
    {
        std::ostringstream ostr;

        ostr << "writeResourceRecord:" <<
            CaptureDNS::decode_domain_name(resource.dname()) <<
            ",type:" << resource.query_type();
        add_action(ostr.str());
    }

    virtual void startAuthoritySection()
    {
        add_action("startAuthoritySection");
    }

    virtual void startAdditionalSection()
    {
        add_action("startAdditionalSection");
    }

    void add_action(const std::string& act)
    {
        if ( !actions.empty() )
            actions.push_back(',');
        actions.append(act);
    }

    std::string actions;
};

SCENARIO("Generating output", "[output]")
{
    PacketStatistics stats;
    Configuration config;

    config.output_pattern = "output";
    config.rotation_period = std::chrono::seconds(60);
    config.output_options_queries = 0;
    config.output_options_responses = 0;

    GIVEN("A query/response pair")
    {
        DNSMessage q, r;
        q.timestamp = std::chrono::system_clock::time_point(std::chrono::hours(24*365*20));
        q.clientIP = IPAddress(Tins::IPv4Address("192.168.1.2"));
        q.serverIP = IPAddress(Tins::IPv4Address("192.168.1.3"));
        q.clientPort = 12345;
        q.serverPort = 6789;
        q.hoplimit = 254;
        q.tcp = false;
        q.dns.type(CaptureDNS::QUERY);
        q.dns.id(54321);
        q.dns.add_query(CaptureDNS::query("one", CaptureDNS::AAAA, CaptureDNS::IN));

        r = q;

        q.dns.add_additional(CaptureDNS::resource("one", ""_b, CaptureDNS::A, CaptureDNS::IN, 0));
        q.dns.add_additional(CaptureDNS::resource("", ""_b, CaptureDNS::OPT, CaptureDNS::IN, 0));
        q.dns.add_additional(CaptureDNS::resource("three", ""_b, CaptureDNS::AAAA, CaptureDNS::IN, 0));

        r.timestamp += std::chrono::seconds(1);
        r.dns.type(CaptureDNS::RESPONSE);

        std::shared_ptr<QueryResponse> qr = std::make_shared<QueryResponse>(make_unique<DNSMessage>(q));
        qr->set_response(make_unique<DNSMessage>(r));

        WHEN("base output is required")
        {
            config.exclude_hints.set_section_excludes(0, 0);
            TestBaseOutputWriter tbow(config);
            tbow.writeQR(qr, stats);

            THEN("only base output is generated")
            {
                REQUIRE(tbow.actions ==
                        "startRecord:1989-12-27 00h00m00s,"
                        "writeBasic:1989-12-27 00h00m00s,"
                        "endRecord:1989-12-27 00h00m00s");
            }
        }

        AND_WHEN("base output plus extra query questions is required")
        {
            config.output_options_queries = Configuration::EXTRA_QUESTIONS;
            config.exclude_hints.set_section_excludes(config.output_options_queries, 0);
            TestBaseOutputWriter tbow(config);
            tbow.writeQR(qr, stats);

            THEN("only base output plus empty questions section is generated")
            {
                REQUIRE(tbow.actions ==
                        "startRecord:1989-12-27 00h00m00s,"
                        "writeBasic:1989-12-27 00h00m00s,"
                        "startExtendedQueryGroup,"
                        "endExtendedGroup,"
                        "endRecord:1989-12-27 00h00m00s");
            }
        }

        AND_WHEN("base output plus query additionals is required")
        {
            config.output_options_queries = Configuration::ADDITIONALS;
            config.exclude_hints.set_section_excludes(config.output_options_queries, 0);
            TestBaseOutputWriter tbow(config);
            tbow.writeQR(qr, stats);

            THEN("only base output plus additional section is generated")
            {
                REQUIRE(tbow.actions ==
                        "startRecord:1989-12-27 00h00m00s,"
                        "writeBasic:1989-12-27 00h00m00s,"
                        "startExtendedQueryGroup,"
                        "startAdditionalSection,"
                        "writeResourceRecord:one,type:1,"
                        "writeResourceRecord:three,type:28,"
                        "endSection,"
                        "endExtendedGroup,"
                        "endRecord:1989-12-27 00h00m00s");
            }
        }

        AND_WHEN("base output plus response additionals is required")
        {
            config.output_options_responses = Configuration::ADDITIONALS;
            config.exclude_hints.set_section_excludes(0, config.output_options_responses);
            TestBaseOutputWriter tbow(config);
            tbow.writeQR(qr, stats);

            THEN("only base output is generated when there are no response additionals")
            {
                REQUIRE(tbow.actions ==
                        "startRecord:1989-12-27 00h00m00s,"
                        "writeBasic:1989-12-27 00h00m00s,"
                        "startExtendedResponseGroup,"
                        "endExtendedGroup,"
                        "endRecord:1989-12-27 00h00m00s");
            }
        }
    }

    GIVEN("A query/response pair with extra questions")
    {
        DNSMessage q, r;
        q.timestamp = std::chrono::system_clock::time_point(std::chrono::hours(24*365*20));
        q.clientIP = IPAddress(Tins::IPv4Address("192.168.1.2"));
        q.serverIP = IPAddress(Tins::IPv4Address("192.168.1.3"));
        q.clientPort = 12345;
        q.serverPort = 6789;
        q.hoplimit = 254;
        q.tcp = false;
        q.dns.type(CaptureDNS::QUERY);
        q.dns.id(54321);
        q.dns.add_query(CaptureDNS::query("one", CaptureDNS::AAAA, CaptureDNS::IN));
        q.dns.add_query(CaptureDNS::query("two", CaptureDNS::A, CaptureDNS::IN));
        q.dns.add_query(CaptureDNS::query("three", CaptureDNS::AAAA, CaptureDNS::IN));

        r = q;
        r.timestamp += std::chrono::seconds(1);
        r.dns.type(CaptureDNS::RESPONSE);

        std::shared_ptr<QueryResponse> qr = std::make_shared<QueryResponse>(make_unique<DNSMessage>(q));
        qr->set_response(make_unique<DNSMessage>(r));

        WHEN("base output plus extra query questions is required")
        {
            config.output_options_queries = Configuration::EXTRA_QUESTIONS;
            config.exclude_hints.set_section_excludes(config.output_options_queries, 0);
            TestBaseOutputWriter tbow(config);
            tbow.writeQR(qr, stats);

            THEN("only base output plus questions section with second and third questions is generated")
            {
                REQUIRE(tbow.actions ==
                        "startRecord:1989-12-27 00h00m00s,"
                        "writeBasic:1989-12-27 00h00m00s,"
                        "startExtendedQueryGroup,"
                        "startQuestionsSection,"
                        "writeQuestionRecord:two,type:1,"
                        "writeQuestionRecord:three,type:28,"
                        "endSection,"
                        "endExtendedGroup,"
                        "endRecord:1989-12-27 00h00m00s");
            }
        }

        AND_WHEN("base output plus extra query questions is required but one question is ignored")
        {
            config.output_options_queries = Configuration::EXTRA_QUESTIONS;
            config.exclude_hints.set_section_excludes(config.output_options_queries, 0);
            config.ignore_rr_types = { 1 };
            TestBaseOutputWriter tbow(config);
            tbow.writeQR(qr, stats);

            THEN("only base output plus questions section with second question is generated")
            {
                REQUIRE(tbow.actions ==
                        "startRecord:1989-12-27 00h00m00s,"
                        "writeBasic:1989-12-27 00h00m00s,"
                        "startExtendedQueryGroup,"
                        "startQuestionsSection,"
                        "writeQuestionRecord:three,type:28,"
                        "endSection,"
                        "endExtendedGroup,"
                        "endRecord:1989-12-27 00h00m00s");
            }
        }

        AND_WHEN("base output plus extra query questions is required but one question is accepted")
        {
            config.output_options_queries = Configuration::EXTRA_QUESTIONS;
            config.exclude_hints.set_section_excludes(config.output_options_queries, 0);
            config.accept_rr_types = { 1 };
            TestBaseOutputWriter tbow(config);
            tbow.writeQR(qr, stats);

            THEN("only base output plus questions section with second question is generated")
            {
                REQUIRE(tbow.actions ==
                        "startRecord:1989-12-27 00h00m00s,"
                        "writeBasic:1989-12-27 00h00m00s,"
                        "startExtendedQueryGroup,"
                        "startQuestionsSection,"
                        "writeQuestionRecord:two,type:1,"
                        "endSection,"
                        "endExtendedGroup,"
                        "endRecord:1989-12-27 00h00m00s");
            }
        }
    }

    GIVEN("A query/response pair with an answer, authority and additional")
    {
        DNSMessage q, r;
        q.timestamp = std::chrono::system_clock::time_point(std::chrono::hours(24*365*20));
        q.clientIP = IPAddress(Tins::IPv4Address("192.168.1.2"));
        q.serverIP = IPAddress(Tins::IPv4Address("192.168.1.3"));
        q.clientPort = 12345;
        q.serverPort = 6789;
        q.hoplimit = 254;
        q.tcp = false;
        q.dns.type(CaptureDNS::QUERY);
        q.dns.id(54321);
        q.dns.add_query(CaptureDNS::query("one", CaptureDNS::AAAA, CaptureDNS::IN));

        r = q;
        r.timestamp += std::chrono::seconds(1);
        r.dns.type(CaptureDNS::RESPONSE);
        r.dns.add_answer(CaptureDNS::resource("one", ""_b, CaptureDNS::AAAA, CaptureDNS::IN, 0));
        r.dns.add_answer(CaptureDNS::resource("onea", ""_b, CaptureDNS::A, CaptureDNS::IN, 0));
        r.dns.add_authority(CaptureDNS::resource("two", ""_b, CaptureDNS::AAAA, CaptureDNS::IN, 0));
        r.dns.add_authority(CaptureDNS::resource("twoa", ""_b, CaptureDNS::A, CaptureDNS::IN, 0));
        r.dns.add_additional(CaptureDNS::resource("", ""_b, CaptureDNS::OPT, CaptureDNS::IN, 0));
        r.dns.add_additional(CaptureDNS::resource("threea", ""_b, CaptureDNS::A, CaptureDNS::IN, 0));

        std::shared_ptr<QueryResponse> qr = std::make_shared<QueryResponse>(make_unique<DNSMessage>(q));
        qr->set_response(make_unique<DNSMessage>(r));

        WHEN("base output plus response answer is required if answers requested")
        {
            config.output_options_responses = Configuration::ANSWERS;
            config.exclude_hints.set_section_excludes(0, config.output_options_responses);
            TestBaseOutputWriter tbow(config);
            tbow.writeQR(qr, stats);

            THEN("only base output plus response section is generated")
            {
                REQUIRE(tbow.actions ==
                        "startRecord:1989-12-27 00h00m00s,"
                        "writeBasic:1989-12-27 00h00m00s,"
                        "startExtendedResponseGroup,"
                        "startAnswersSection,"
                        "writeResourceRecord:one,type:28,"
                        "writeResourceRecord:onea,type:1,"
                        "endSection,"
                        "endExtendedGroup,"
                        "endRecord:1989-12-27 00h00m00s");
            }
        }

        AND_WHEN("base output plus response authority is required if authority requested")
        {
            config.output_options_responses = Configuration::AUTHORITIES;
            config.exclude_hints.set_section_excludes(0, config.output_options_responses);
            TestBaseOutputWriter tbow(config);
            tbow.writeQR(qr, stats);

            THEN("only base output plus response section is generated")
            {
                REQUIRE(tbow.actions ==
                        "startRecord:1989-12-27 00h00m00s,"
                        "writeBasic:1989-12-27 00h00m00s,"
                        "startExtendedResponseGroup,"
                        "startAuthoritySection,"
                        "writeResourceRecord:two,type:28,"
                        "writeResourceRecord:twoa,type:1,"
                        "endSection,"
                        "endExtendedGroup,"
                        "endRecord:1989-12-27 00h00m00s");
            }
        }

        AND_WHEN("base output plus response additional is required if additional requested")
        {
            config.output_options_responses = Configuration::ADDITIONALS;
            config.exclude_hints.set_section_excludes(0, config.output_options_responses);
            TestBaseOutputWriter tbow(config);
            tbow.writeQR(qr, stats);

            THEN("only base output plus response section is generated")
            {
                REQUIRE(tbow.actions ==
                        "startRecord:1989-12-27 00h00m00s,"
                        "writeBasic:1989-12-27 00h00m00s,"
                        "startExtendedResponseGroup,"
                        "startAdditionalSection,"
                        "writeResourceRecord:,type:41,"
                        "writeResourceRecord:threea,type:1,"
                        "endSection,"
                        "endExtendedGroup,"
                        "endRecord:1989-12-27 00h00m00s");
            }
        }

        AND_WHEN("response answer omits ignored RR type")
        {
            config.output_options_responses = Configuration::ANSWERS;
            config.exclude_hints.set_section_excludes(0, config.output_options_responses);
            config.ignore_rr_types = { 1 };
            TestBaseOutputWriter tbow(config);
            tbow.writeQR(qr, stats);

            THEN("only base output plus response section is generated")
            {
                REQUIRE(tbow.actions ==
                        "startRecord:1989-12-27 00h00m00s,"
                        "writeBasic:1989-12-27 00h00m00s,"
                        "startExtendedResponseGroup,"
                        "startAnswersSection,"
                        "writeResourceRecord:one,type:28,"
                        "endSection,"
                        "endExtendedGroup,"
                        "endRecord:1989-12-27 00h00m00s");
            }
        }

        AND_WHEN("response answer only has accepted RR type")
        {
            config.output_options_responses = Configuration::ANSWERS;
            config.exclude_hints.set_section_excludes(0, config.output_options_responses);
            config.accept_rr_types = { 1 };
            TestBaseOutputWriter tbow(config);
            tbow.writeQR(qr, stats);

            THEN("only base output plus response section is generated")
            {
                REQUIRE(tbow.actions ==
                        "startRecord:1989-12-27 00h00m00s,"
                        "writeBasic:1989-12-27 00h00m00s,"
                        "startExtendedResponseGroup,"
                        "startAnswersSection,"
                        "writeResourceRecord:onea,type:1,"
                        "endSection,"
                        "endExtendedGroup,"
                        "endRecord:1989-12-27 00h00m00s");
            }
        }

        AND_WHEN("response authority omits ignored RR type")
        {
            config.output_options_responses = Configuration::AUTHORITIES;
            config.exclude_hints.set_section_excludes(0, config.output_options_responses);
            config.ignore_rr_types = { 1 };
            TestBaseOutputWriter tbow(config);
            tbow.writeQR(qr, stats);

            THEN("only base output plus response section is generated")
            {
                REQUIRE(tbow.actions ==
                        "startRecord:1989-12-27 00h00m00s,"
                        "writeBasic:1989-12-27 00h00m00s,"
                        "startExtendedResponseGroup,"
                        "startAuthoritySection,"
                        "writeResourceRecord:two,type:28,"
                        "endSection,"
                        "endExtendedGroup,"
                        "endRecord:1989-12-27 00h00m00s");
            }
        }

        AND_WHEN("response authority only has accepted RR type")
        {
            config.output_options_responses = Configuration::AUTHORITIES;
            config.exclude_hints.set_section_excludes(0, config.output_options_responses);
            config.accept_rr_types = { 1 };
            TestBaseOutputWriter tbow(config);
            tbow.writeQR(qr, stats);

            THEN("only base output plus response section is generated")
            {
                REQUIRE(tbow.actions ==
                        "startRecord:1989-12-27 00h00m00s,"
                        "writeBasic:1989-12-27 00h00m00s,"
                        "startExtendedResponseGroup,"
                        "startAuthoritySection,"
                        "writeResourceRecord:twoa,type:1,"
                        "endSection,"
                        "endExtendedGroup,"
                        "endRecord:1989-12-27 00h00m00s");
            }
        }

        AND_WHEN("response additional omits ignored RR type")
        {
            config.output_options_responses = Configuration::ADDITIONALS;
            config.exclude_hints.set_section_excludes(0, config.output_options_responses);
            config.ignore_rr_types = { 1 };
            TestBaseOutputWriter tbow(config);
            tbow.writeQR(qr, stats);

            THEN("only base output plus response section is generated")
            {
                REQUIRE(tbow.actions ==
                        "startRecord:1989-12-27 00h00m00s,"
                        "writeBasic:1989-12-27 00h00m00s,"
                        "startExtendedResponseGroup,"
                        "startAdditionalSection,"
                        "writeResourceRecord:,type:41,"
                        "endSection,"
                        "endExtendedGroup,"
                        "endRecord:1989-12-27 00h00m00s");
            }
        }

        AND_WHEN("response authority only has accepted RR type")
        {
            config.output_options_responses = Configuration::ADDITIONALS;
            config.exclude_hints.set_section_excludes(0, config.output_options_responses);
            config.accept_rr_types = { 1 };
            TestBaseOutputWriter tbow(config);
            tbow.writeQR(qr, stats);

            THEN("only base output plus response section is generated")
            {
                REQUIRE(tbow.actions ==
                        "startRecord:1989-12-27 00h00m00s,"
                        "writeBasic:1989-12-27 00h00m00s,"
                        "startExtendedResponseGroup,"
                        "startAdditionalSection,"
                        "writeResourceRecord:threea,type:1,"
                        "endSection,"
                        "endExtendedGroup,"
                        "endRecord:1989-12-27 00h00m00s");
            }
        }
    }
}
