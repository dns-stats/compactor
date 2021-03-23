/*
 * Copyright 2016-2017, 2021 Internet Corporation for Assigned Names and Numbers.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Developed by Sinodun IT (www.sinodun.com)
 */

#include <chrono>
#include <vector>

#include "catch.hpp"
#include "makeunique.hpp"
#include "matcher.hpp"
#include "transporttype.hpp"

SCENARIO("Matcher correctly matches responses to queries", "[matcher]")
{
    GIVEN("Simple matching query and response messages")
    {
        DNSMessage query, response;

        query.timestamp = std::chrono::system_clock::time_point(std::chrono::hours(24*365*20));
        query.clientIP = IPAddress(Tins::IPv4Address("192.168.1.2"));
        query.serverIP = IPAddress(Tins::IPv4Address("192.168.1.3"));
        query.clientPort = 12345;
        query.serverPort = 6789;
        query.hoplimit = 254;
        query.transport_type = TransportType::UDP;
        query.dns.type(CaptureDNS::QUERY);
        query.dns.id(54321);
        query.dns.add_query(CaptureDNS::query("one", CaptureDNS::AAAA, CaptureDNS::IN));

        response = query;
        response.timestamp += std::chrono::seconds(1);
        response.dns.type(CaptureDNS::RESPONSE);

        std::vector<std::shared_ptr<QueryResponse>> matches;
        QueryResponseMatcher matcher(
            [&](std::shared_ptr<QueryResponse> qr)
            {
                matches.push_back(qr);
            });

        WHEN("compared within timeout")
        {
            matcher.set_query_timeout(std::chrono::seconds(5));

            matcher.add(make_unique<DNSMessage>(query));
            matcher.add(make_unique<DNSMessage>(response));

            THEN("query is matched with response")
            {
                REQUIRE(matches.size() == 1);

                REQUIRE(matches[0]->has_query());
                REQUIRE(matches[0]->has_response());
                REQUIRE(matches[0]->timestamp() == query.timestamp);
                REQUIRE(matches[0]->query().timestamp == query.timestamp);
                REQUIRE(matches[0]->response().timestamp == response.timestamp);
            }
        }

        WHEN("compared outside timeout")
        {
            matcher.set_query_timeout(std::chrono::seconds(5));
            response.timestamp = query.timestamp + std::chrono::seconds(10);

            matcher.add(make_unique<DNSMessage>(query));
            matcher.add(make_unique<DNSMessage>(response));
            matcher.flush();

            THEN("query is not matched with response")
            {
                REQUIRE(matches.size() == 2);

                REQUIRE(matches[0]->has_query());
                REQUIRE(!matches[0]->has_response());
                REQUIRE(matches[0]->timestamp() == query.timestamp);
                REQUIRE(matches[0]->query().timestamp == query.timestamp);

                REQUIRE(!matches[1]->has_query());
                REQUIRE(matches[1]->has_response());
                REQUIRE(matches[1]->timestamp() == response.timestamp);
                REQUIRE(matches[1]->response().timestamp == response.timestamp);
            }
        }
    }

    GIVEN("Multiple queries, differening in QNAME, and response for one")
    {
        DNSMessage query1, query2, response1, response2, response3;

        query1.timestamp = std::chrono::system_clock::time_point(std::chrono::hours(24*365*20));
        query1.clientIP = IPAddress(Tins::IPv4Address("192.168.1.2"));
        query1.serverIP = IPAddress(Tins::IPv4Address("192.168.1.3"));
        query1.clientPort = 12345;
        query1.serverPort = 6789;
        query1.hoplimit = 254;
        query1.transport_type = TransportType::UDP;
        query1.dns.type(CaptureDNS::QUERY);
        query1.dns.id(54321);

        response3 = query2 = query1;
        query2.timestamp += std::chrono::seconds(1);
        query1.dns.add_query(CaptureDNS::query("one", CaptureDNS::AAAA, CaptureDNS::IN));
        query2.dns.add_query(CaptureDNS::query("two", CaptureDNS::AAAA, CaptureDNS::IN));

        response1 = query1;
        response1.timestamp += std::chrono::seconds(2);
        response1.dns.type(CaptureDNS::RESPONSE);

        response2 = query2;
        response2.timestamp += std::chrono::seconds(2);
        response2.dns.type(CaptureDNS::RESPONSE);

        response3.timestamp += std::chrono::seconds(3);
        response3.dns.type(CaptureDNS::RESPONSE);

        std::vector<std::shared_ptr<QueryResponse>> matches;
        QueryResponseMatcher matcher(
            [&](std::shared_ptr<QueryResponse> qr)
            {
                matches.push_back(qr);
            });

        WHEN("first response sent is for second query")
        {
            matcher.add(make_unique<DNSMessage>(query1));
            matcher.add(make_unique<DNSMessage>(query2));
            matcher.add(make_unique<DNSMessage>(response2));
            matcher.flush();

            THEN("second query is matched with response, first is unmatched")
            {
                REQUIRE(matches.size() == 2);

                REQUIRE(matches[0]->has_query());
                REQUIRE(!matches[0]->has_response());
                REQUIRE(matches[0]->timestamp() == query1.timestamp);
                REQUIRE(matches[0]->query().timestamp == query1.timestamp);

                REQUIRE(matches[1]->has_query());
                REQUIRE(matches[1]->has_response());
                REQUIRE(matches[1]->timestamp() == query2.timestamp);
                REQUIRE(matches[1]->query().timestamp == query2.timestamp);
                REQUIRE(matches[1]->response().timestamp == response2.timestamp);
            }
        }

        WHEN("first response sent is for first query")
        {
            matcher.add(make_unique<DNSMessage>(query1));
            matcher.add(make_unique<DNSMessage>(query2));
            matcher.add(make_unique<DNSMessage>(response1));
            matcher.flush();

            THEN("first query is matched with response, second is unmatched")
            {
                REQUIRE(matches.size() == 2);

                REQUIRE(matches[0]->has_query());
                REQUIRE(matches[0]->has_response());
                REQUIRE(matches[0]->timestamp() == query1.timestamp);
                REQUIRE(matches[0]->query().timestamp == query1.timestamp);
                REQUIRE(matches[0]->response().timestamp == response1.timestamp);

                REQUIRE(matches[1]->has_query());
                REQUIRE(!matches[1]->has_response());
                REQUIRE(matches[1]->timestamp() == query2.timestamp);
                REQUIRE(matches[1]->query().timestamp == query2.timestamp);
            }
        }

        WHEN("response has no question")
        {
            matcher.add(make_unique<DNSMessage>(query1));
            matcher.add(make_unique<DNSMessage>(query2));
            matcher.add(make_unique<DNSMessage>(response3));
            matcher.flush();

            THEN("response matches first query")
            {
                REQUIRE(matches.size() == 2);

                REQUIRE(matches[0]->has_query());
                REQUIRE(matches[0]->has_response());
                REQUIRE(matches[0]->timestamp() == query1.timestamp);
                REQUIRE(matches[0]->query().timestamp == query1.timestamp);
                REQUIRE(matches[0]->response().timestamp == response3.timestamp);

                REQUIRE(matches[1]->has_query());
                REQUIRE(!matches[1]->has_response());
                REQUIRE(matches[1]->timestamp() == query2.timestamp);
                REQUIRE(matches[1]->query().timestamp == query2.timestamp);
            }
        }
    }
}

SCENARIO("Matcher outputs results in query submission order", "[matcher]")
{
    GIVEN("Multiple query and response messages")
    {
        DNSMessage query1, query2, query3, response1, response2, response3;

        query1.timestamp = std::chrono::system_clock::time_point(std::chrono::hours(24*365*20));
        query1.clientIP = IPAddress(Tins::IPv4Address("192.168.1.2"));
        query1.serverIP = IPAddress(Tins::IPv4Address("192.168.1.3"));
        query1.clientPort = 12345;
        query1.serverPort = 6789;
        query1.hoplimit = 254;
        query1.transport_type = TransportType::UDP;
        query1.dns.type(CaptureDNS::QUERY);
        query1.dns.id(54321);

        response3 = query2 = query1;
        query2.timestamp += std::chrono::seconds(1);
        query1.dns.add_query(CaptureDNS::query("one", CaptureDNS::AAAA, CaptureDNS::IN));
        query2.dns.add_query(CaptureDNS::query("two", CaptureDNS::AAAA, CaptureDNS::IN));
        query3 = query1;
        query3.timestamp += std::chrono::seconds(5);

        response1 = query1;
        response1.timestamp += std::chrono::seconds(2);
        response1.dns.type(CaptureDNS::RESPONSE);

        response2 = query2;
        response2.timestamp += std::chrono::seconds(2);
        response2.dns.type(CaptureDNS::RESPONSE);

        response3.timestamp += std::chrono::seconds(6);
        response3.dns.type(CaptureDNS::RESPONSE);

        std::vector<std::shared_ptr<QueryResponse>> matches;
        QueryResponseMatcher matcher(
            [&](std::shared_ptr<QueryResponse> qr)
            {
                matches.push_back(qr);
            });

        matcher.set_query_timeout(std::chrono::seconds(5));

        matcher.add(make_unique<DNSMessage>(query1));
        matcher.add(make_unique<DNSMessage>(query2));

        WHEN("first response sent is for second query")
        {
            matcher.add(make_unique<DNSMessage>(response2));

            THEN("nothing is output on match of second query until first times out")
            {
                REQUIRE(matches.size() == 0);
            }

            matcher.add(make_unique<DNSMessage>(query3));

            AND_THEN("timeout of first query outputs first (timed out) and matched second (not timed out) in that order")
            {
                REQUIRE(matches.size() == 2);

                REQUIRE(matches[0]->has_query());
                REQUIRE(!matches[0]->has_response());
                REQUIRE(matches[0]->timestamp() == query1.timestamp);
                REQUIRE(matches[0]->query().timestamp == query1.timestamp);

                REQUIRE(matches[1]->has_query());
                REQUIRE(matches[1]->has_response());
                REQUIRE(matches[1]->timestamp() == query2.timestamp);
                REQUIRE(matches[1]->query().timestamp == query2.timestamp);
                REQUIRE(matches[1]->response().timestamp == response2.timestamp);
            }

            matches.clear();
            matcher.add(make_unique<DNSMessage>(response3));

            AND_THEN("third response produces final match")
            {
                REQUIRE(matches.size() == 1);

                REQUIRE(matches[0]->has_query());
                REQUIRE(matches[0]->has_response());
                REQUIRE(matches[0]->timestamp() == query3.timestamp);
                REQUIRE(matches[0]->query().timestamp == query3.timestamp);
                REQUIRE(matches[0]->response().timestamp == response3.timestamp);
            }
        }
    }
}

SCENARIO("Matches copes with queries and responses presented out of time order", "[matcher]")
{
    GIVEN("Multiple query and response messages")
    {
        DNSMessage query1, query2, query3, query4, response1, response2, response3, response4;

        query1.timestamp = std::chrono::system_clock::time_point(std::chrono::hours(24*365*20));
        query1.clientIP = IPAddress(Tins::IPv4Address("192.168.1.2"));
        query1.serverIP = IPAddress(Tins::IPv4Address("192.168.1.3"));
        query1.clientPort = 12345;
        query1.serverPort = 6789;
        query1.hoplimit = 254;
        query1.transport_type = TransportType::UDP;
        query1.dns.type(CaptureDNS::QUERY);
        query1.dns.id(54321);

        query4 = query3 = query2 = query1;
        query2.timestamp += std::chrono::seconds(3);
        query3.timestamp += std::chrono::seconds(6);
        query1.dns.add_query(CaptureDNS::query("one", CaptureDNS::AAAA, CaptureDNS::IN));
        query2.dns.add_query(CaptureDNS::query("two", CaptureDNS::AAAA, CaptureDNS::IN));
        query3.dns.add_query(CaptureDNS::query("three", CaptureDNS::AAAA, CaptureDNS::IN));
        query4.dns.add_query(CaptureDNS::query("four", CaptureDNS::AAAA, CaptureDNS::IN));

        response1 = query1;
        response1.timestamp += std::chrono::seconds(1);
        response1.dns.type(CaptureDNS::RESPONSE);

        query4.timestamp = response1.timestamp + std::chrono::microseconds(3);

        response2 = query2;
        response2.timestamp += std::chrono::seconds(1);
        response2.dns.type(CaptureDNS::RESPONSE);

        response3 = query3;
        response3.timestamp += std::chrono::seconds(1);
        response3.dns.type(CaptureDNS::RESPONSE);

        response4 = query4;
        response4.timestamp += std::chrono::microseconds(1);
        response4.dns.type(CaptureDNS::RESPONSE);

        std::vector<std::shared_ptr<QueryResponse>> matches;
        QueryResponseMatcher matcher(
            [&](std::shared_ptr<QueryResponse> qr)
            {
                matches.push_back(qr);
            });

        matcher.set_query_timeout(std::chrono::seconds(10));
        matcher.set_skew_timeout(std::chrono::microseconds(10));

        WHEN("unmatched response arrives with a later query around")
        {
            matcher.add(make_unique<DNSMessage>(query2));
            matcher.add(make_unique<DNSMessage>(response1));
            matcher.add(make_unique<DNSMessage>(response2));

            THEN("unmatched response is output immediately")
            {
                REQUIRE(matches.size() == 2);

                REQUIRE(matches[0]->has_query());
                REQUIRE(matches[0]->has_response());
                REQUIRE(matches[0]->timestamp() == query2.timestamp);
                REQUIRE(matches[0]->query().timestamp == query2.timestamp);
                REQUIRE(matches[0]->response().timestamp == response2.timestamp);

                REQUIRE(!matches[1]->has_query());
                REQUIRE(matches[1]->has_response());
                REQUIRE(matches[1]->timestamp() == response1.timestamp);
                REQUIRE(matches[1]->response().timestamp == response1.timestamp);
            }
        }

        WHEN("unmatched response arrives with no later query around")
        {
            matcher.add(make_unique<DNSMessage>(response1));

            THEN("response is not output immediately")
            {
                REQUIRE(matches.size() == 0);
            }

            AND_THEN("response is output on arrival of later response")
            {
                matcher.add(make_unique<DNSMessage>(response2));

                REQUIRE(matches.size() == 1);

                REQUIRE(!matches[0]->has_query());
                REQUIRE(matches[0]->has_response());
                REQUIRE(matches[0]->timestamp() == response1.timestamp);
                REQUIRE(matches[0]->response().timestamp == response1.timestamp);
            }

            AND_THEN("response is not output on arrival of unmatching query that is later but within timeout")
            {
                // Note the query must be accompanied by a response to
                // provoke output, because the query is entered into the
                // output queue before the unmatched response.
                matcher.add(make_unique<DNSMessage>(query4));
                matcher.add(make_unique<DNSMessage>(response4));

                REQUIRE(matches.size() == 1);

                REQUIRE(matches[0]->has_query());
                REQUIRE(matches[0]->has_response());
                REQUIRE(matches[0]->timestamp() == query4.timestamp);
                REQUIRE(matches[0]->query().timestamp == query4.timestamp);
                REQUIRE(matches[0]->response().timestamp == response4.timestamp);
            }

            AND_THEN("response is output unmatched on arrival of later unmatching query outside timeout")
            {
                matcher.add(make_unique<DNSMessage>(query3));
                matcher.add(make_unique<DNSMessage>(response3));

                REQUIRE(matches.size() == 2);

                REQUIRE(!matches[0]->has_query());
                REQUIRE(matches[0]->has_response());
                REQUIRE(matches[0]->timestamp() == response1.timestamp);
                REQUIRE(matches[0]->response().timestamp == response1.timestamp);

                REQUIRE(matches[1]->has_query());
                REQUIRE(matches[1]->has_response());
                REQUIRE(matches[1]->timestamp() == query3.timestamp);
                REQUIRE(matches[1]->query().timestamp == query3.timestamp);
                REQUIRE(matches[1]->response().timestamp == response3.timestamp);
            }
        }

        WHEN("unmatched response arrives with no later query around")
        {
            matcher.add(make_unique<DNSMessage>(response4));

            THEN("response is not output immediately")
            {
                REQUIRE(matches.size() == 0);
            }

            AND_THEN("response is output matched on arrival of later matching query")
            {
                matcher.add(make_unique<DNSMessage>(query4));

                REQUIRE(matches.size() == 1);

                REQUIRE(matches[0]->has_query());
                REQUIRE(matches[0]->has_response());
                REQUIRE(matches[0]->timestamp() == query4.timestamp);
                REQUIRE(matches[0]->query().timestamp == query4.timestamp);
                REQUIRE(matches[0]->response().timestamp == response4.timestamp);
            }
        }

        WHEN("unmatched responses are out of chronological order and before queries")
        {
            query3.timestamp = query4.timestamp;
            query4.timestamp += std::chrono::microseconds(1);

            response3.timestamp = query3.timestamp;
            response4.timestamp = query4.timestamp;
            response3.timestamp += std::chrono::microseconds(5);
            response4.timestamp += std::chrono::microseconds(1);

            matcher.add(make_unique<DNSMessage>(response3));
            matcher.add(make_unique<DNSMessage>(response4));

            THEN("matching happens correctly")
            {
                REQUIRE(matches.size() == 0);

                matcher.add(make_unique<DNSMessage>(query4));
                matcher.add(make_unique<DNSMessage>(query3));

                REQUIRE(matches.size() == 2);
                REQUIRE(matches[0]->has_query());
                REQUIRE(matches[0]->has_response());
                REQUIRE(matches[0]->timestamp() == query4.timestamp);
                REQUIRE(matches[0]->response().timestamp == response4.timestamp);

                REQUIRE(matches[1]->has_query());
                REQUIRE(matches[1]->has_response());
                REQUIRE(matches[1]->timestamp() == query3.timestamp);
                REQUIRE(matches[1]->response().timestamp == response3.timestamp);
            }

            AND_THEN("matching happens correctly when query order is reversed")
            {
                REQUIRE(matches.size() == 0);

                matcher.add(make_unique<DNSMessage>(query3));
                matcher.add(make_unique<DNSMessage>(query4));

                REQUIRE(matches.size() == 2);
                REQUIRE(matches[0]->has_query());
                REQUIRE(matches[0]->has_response());
                REQUIRE(matches[0]->timestamp() == query3.timestamp);
                REQUIRE(matches[0]->response().timestamp == response3.timestamp);

                REQUIRE(matches[1]->has_query());
                REQUIRE(matches[1]->has_response());
                REQUIRE(matches[1]->timestamp() == query4.timestamp);
                REQUIRE(matches[1]->response().timestamp == response4.timestamp);
            }
        }

        WHEN("unmatched responses are stashed")
        {
            matcher.add(make_unique<DNSMessage>(response1));
            matcher.add(make_unique<DNSMessage>(response4));

            THEN("they are output when the matcher is flushed")
            {
                matcher.flush();

                REQUIRE(matches.size() == 2);

                REQUIRE(!matches[0]->has_query());
                REQUIRE(matches[0]->has_response());
                REQUIRE(matches[0]->timestamp() == response1.timestamp);
                REQUIRE(matches[0]->response().timestamp == response1.timestamp);

                REQUIRE(!matches[1]->has_query());
                REQUIRE(matches[1]->has_response());
                REQUIRE(matches[1]->timestamp() == response4.timestamp);
                REQUIRE(matches[1]->response().timestamp == response4.timestamp);
            }
        }
    }
}
