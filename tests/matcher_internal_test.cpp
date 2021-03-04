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

// Make sure all headers required by matcher.[ch]pp are included before
// we pervert private and include matcher.hpp and matcher.cpp.
#include <chrono>
#include <deque>
#include <functional>
#include <memory>
#include <unordered_map>
#include <utility>

#include "catch.hpp"

#include "dnsmessage.hpp"
#include "queryresponse.hpp"
#include "makeunique.hpp"
#include "transporttype.hpp"

#define private public
#include "matcher.hpp"
#include "matcher.cpp"
#undef private

namespace {
    int CountQueries(const LiveQueries& lq)
    {
        int res = 0;

        for ( const auto& dq : lq.map_ )
            res += dq.second.size();

        return res;
    }

}

SCENARIO("Tins DNS queries can be compared for equality" ,"[Tins]")
{
    GIVEN("Some sample DNS queries")
    {
        CaptureDNS::query q1("one", CaptureDNS::AAAA, CaptureDNS::IN);
        CaptureDNS::query q2("two", CaptureDNS::AAAA, CaptureDNS::IN);
        CaptureDNS::query q3("one", CaptureDNS::AAAA, CaptureDNS::CH);
        CaptureDNS::query q4("one", CaptureDNS::A, CaptureDNS::IN);

        WHEN("identical queries are compared")
        {
            THEN("the queries compare equal")
            {
                REQUIRE(q1 == q1);
                REQUIRE(q2 == q2);
                REQUIRE(q3 == q3);
                REQUIRE(q4 == q4);
            }
        }

        WHEN("different queries are compared")
        {
            THEN("the queries do not compare equal")
            {
                REQUIRE(!(q1 == q2));
                REQUIRE(!(q1 == q3));
                REQUIRE(!(q1 == q4));
                REQUIRE(!(q2 == q3));
                REQUIRE(!(q2 == q4));
            }
        }
    }
}

SCENARIO("LiveQueries adds/removes QueryResponse pairs", "[matcher]")
{
    GIVEN("Some simple query and response messages")
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

        LiveQueries lq;

        WHEN("single query added")
        {
            lq.add(std::make_shared<QueryResponseInProgress>(make_unique<DNSMessage>(query1)));

            THEN("single item in live queries")
            {
                REQUIRE(CountQueries(lq) == 1);
            }
        }

        AND_WHEN("two queries added")
        {
            lq.add(std::make_shared<QueryResponseInProgress>(make_unique<DNSMessage>(query1)));
            lq.add(std::make_shared<QueryResponseInProgress>(make_unique<DNSMessage>(query2)));

            THEN("two items in live queries")
            {
                REQUIRE(CountQueries(lq) == 2);
            }
        }

        AND_WHEN("two queries added, and one response")
        {
            lq.add(std::make_shared<QueryResponseInProgress>(make_unique<DNSMessage>(query1)));
            lq.add(std::make_shared<QueryResponseInProgress>(make_unique<DNSMessage>(query2)));
            lq.matchResponse(response2);

            THEN("one item in live queries")
            {
                REQUIRE(CountQueries(lq) == 1);
            }
        }

        AND_WHEN("three queries added, and one response without question")
        {
            lq.add(std::make_shared<QueryResponseInProgress>(make_unique<DNSMessage>(query1)));
            lq.add(std::make_shared<QueryResponseInProgress>(make_unique<DNSMessage>(query2)));
            lq.add(std::make_shared<QueryResponseInProgress>(make_unique<DNSMessage>(query3)));
            lq.matchResponse(response3);

            THEN("two items in live queries")
            {
                REQUIRE(CountQueries(lq) == 2);
            }
        }
    }
}

SCENARIO("Matcher removes items from queue on posting to sink", "[matcher]")
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

        WHEN("query and response matched")
        {
            matcher.set_query_timeout(std::chrono::seconds(5));

            matcher.add(make_unique<DNSMessage>(query));

            THEN("with query only, queue is 1 long")
            {
                REQUIRE(matches.size() == 0);
                REQUIRE(matcher.data_->output.size() == 1);
            }

            matcher.add(make_unique<DNSMessage>(response));

            AND_THEN("after response, output queue is empty")
            {
                REQUIRE(matches.size() == 1);
                REQUIRE(matcher.data_->output.size() == 0);
            }
        }

        WHEN("match fails, outside timeout")
        {
            matcher.set_query_timeout(std::chrono::seconds(5));
            response.timestamp = query.timestamp + std::chrono::seconds(10);

            matcher.add(make_unique<DNSMessage>(query));
            matcher.add(make_unique<DNSMessage>(response));

            THEN("timed out query is output")
            {
                REQUIRE(matches.size() == 1);
                REQUIRE(matcher.data_->output.size() == 0);
                REQUIRE(matcher.data_->response_queue.size() == 1);
            }
        }

    }
}
