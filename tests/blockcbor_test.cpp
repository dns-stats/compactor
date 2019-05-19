/*
 * Copyright 2019 Internet Corporation for Assigned Names and Numbers.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Developed by Sinodun IT (www.sinodun.com)
 */

#include <chrono>

#include "catch.hpp"

#include "blockcbor.hpp"
#include "makeunique.hpp"

using namespace block_cbor;

SCENARIO("DNS flags are encoded correctly", "[block flags]")
{
    GIVEN("A sample QueryResponse")
    {
        DNSMessage q, r;
        q.timestamp = std::chrono::system_clock::time_point(std::chrono::hours(24*365*20));
        q.clientIP = IPAddress(Tins::IPv4Address("192.0.2.1"));
        q.serverIP = IPAddress(Tins::IPv4Address("192.0.2.2"));
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

        WHEN("No DNS flags set")
        {
            QueryResponse qr(make_unique<DNSMessage>(q));
            qr.set_response(make_unique<DNSMessage>(r));

            THEN("Flags are correct")
            {
                REQUIRE(dns_flags(qr) == 0);
            }
        }

        AND_WHEN("Query CD flag set")
        {
            q.dns.checking_disabled(1);

            QueryResponse qr(make_unique<DNSMessage>(q));
            qr.set_response(make_unique<DNSMessage>(r));

            THEN("Flags are correct")
            {
                REQUIRE(dns_flags(qr) == QUERY_CD);
            }
        }

        AND_WHEN("Query AD flag set")
        {
            q.dns.authenticated_data(1);

            QueryResponse qr(make_unique<DNSMessage>(q));
            qr.set_response(make_unique<DNSMessage>(r));

            THEN("Flags are correct")
            {
                REQUIRE(dns_flags(qr) == QUERY_AD);
            }
        }

        AND_WHEN("Query Z flag set")
        {
            q.dns.z(1);

            QueryResponse qr(make_unique<DNSMessage>(q));
            qr.set_response(make_unique<DNSMessage>(r));

            THEN("Flags are correct")
            {
                REQUIRE(dns_flags(qr) == QUERY_Z);
            }
        }

        AND_WHEN("Query RA flag set")
        {
            q.dns.recursion_available(1);

            QueryResponse qr(make_unique<DNSMessage>(q));
            qr.set_response(make_unique<DNSMessage>(r));

            THEN("Flags are correct")
            {
                REQUIRE(dns_flags(qr) == QUERY_RA);
            }
        }

        AND_WHEN("Query RD flag set")
        {
            q.dns.recursion_desired(1);

            QueryResponse qr(make_unique<DNSMessage>(q));
            qr.set_response(make_unique<DNSMessage>(r));

            THEN("Flags are correct")
            {
                REQUIRE(dns_flags(qr) == QUERY_RD);
            }
        }

        AND_WHEN("Query TC flag set")
        {
            q.dns.truncated(1);

            QueryResponse qr(make_unique<DNSMessage>(q));
            qr.set_response(make_unique<DNSMessage>(r));

            THEN("Flags are correct")
            {
                REQUIRE(dns_flags(qr) == QUERY_TC);
            }
        }

        AND_WHEN("Query AA flag set")
        {
            q.dns.authoritative_answer(1);

            QueryResponse qr(make_unique<DNSMessage>(q));
            qr.set_response(make_unique<DNSMessage>(r));

            THEN("Flags are correct")
            {
                REQUIRE(dns_flags(qr) == QUERY_AA);
            }
        }

        AND_WHEN("Query DO flag set")
        {
            q.dns.add_additional(CaptureDNS::EDNS0(2048, true, 0).rr());

            QueryResponse qr(make_unique<DNSMessage>(q));
            qr.set_response(make_unique<DNSMessage>(r));

            THEN("Flags are correct")
            {
                REQUIRE(dns_flags(qr) == QUERY_DO);
            }
        }

        AND_WHEN("Response CD flag set")
        {
            r.dns.checking_disabled(1);

            QueryResponse qr(make_unique<DNSMessage>(q));
            qr.set_response(make_unique<DNSMessage>(r));

            THEN("Flags are correct")
            {
                REQUIRE(dns_flags(qr) == RESPONSE_CD);
            }
        }

        AND_WHEN("Response AD flag set")
        {
            r.dns.authenticated_data(1);

            QueryResponse qr(make_unique<DNSMessage>(q));
            qr.set_response(make_unique<DNSMessage>(r));

            THEN("Flags are correct")
            {
                REQUIRE(dns_flags(qr) == RESPONSE_AD);
            }
        }

        AND_WHEN("Response Z flag set")
        {
            r.dns.z(1);

            QueryResponse qr(make_unique<DNSMessage>(q));
            qr.set_response(make_unique<DNSMessage>(r));

            THEN("Flags are correct")
            {
                REQUIRE(dns_flags(qr) == RESPONSE_Z);
            }
        }

        AND_WHEN("Response RA flag set")
        {
            r.dns.recursion_available(1);

            QueryResponse qr(make_unique<DNSMessage>(q));
            qr.set_response(make_unique<DNSMessage>(r));

            THEN("Flags are correct")
            {
                REQUIRE(dns_flags(qr) == RESPONSE_RA);
            }
        }

        AND_WHEN("Response RD flag set")
        {
            r.dns.recursion_desired(1);

            QueryResponse qr(make_unique<DNSMessage>(q));
            qr.set_response(make_unique<DNSMessage>(r));

            THEN("Flags are correct")
            {
                REQUIRE(dns_flags(qr) == RESPONSE_RD);
            }
        }

        AND_WHEN("Response TC flag set")
        {
            r.dns.truncated(1);

            QueryResponse qr(make_unique<DNSMessage>(q));
            qr.set_response(make_unique<DNSMessage>(r));

            THEN("Flags are correct")
            {
                REQUIRE(dns_flags(qr) == RESPONSE_TC);
            }
        }

        AND_WHEN("Response AA flag set")
        {
            r.dns.authoritative_answer(1);

            QueryResponse qr(make_unique<DNSMessage>(q));
            qr.set_response(make_unique<DNSMessage>(r));

            THEN("Flags are correct")
            {
                REQUIRE(dns_flags(qr) == RESPONSE_AA);
            }
        }

        AND_WHEN("Query and Response AA and TC flags set")
        {
            q.dns.authoritative_answer(1);
            r.dns.authoritative_answer(1);
            q.dns.truncated(1);
            r.dns.truncated(1);

            QueryResponse qr(make_unique<DNSMessage>(q));
            qr.set_response(make_unique<DNSMessage>(r));

            THEN("Flags are correct")
            {
                REQUIRE(dns_flags(qr) == (QUERY_AA | QUERY_TC | RESPONSE_AA | RESPONSE_TC));
            }
        }
    }
}

SCENARIO("Transport flags are encoded correctly", "[block flags]")
{
    GIVEN("A sample QueryResponse")
    {
        DNSMessage q, r;
        q.timestamp = std::chrono::system_clock::time_point(std::chrono::hours(24*365*20));
        q.clientIP = IPAddress(Tins::IPv4Address("192.0.2.1"));
        q.serverIP = IPAddress(Tins::IPv4Address("192.0.2.2"));
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

        WHEN("Transport is UDP IPv4 with no trailing data")
        {
            QueryResponse qr(make_unique<DNSMessage>(q));
            qr.set_response(make_unique<DNSMessage>(r));

            THEN("Flags are correct")
            {
                REQUIRE(transport_flags(qr) == 0);
            }
        }

        AND_WHEN("Transport is UDP IPv6 with no trailing data")
        {
            q.clientIP = IPAddress(Tins::IPv6Address("2001:db8::1"));
            q.serverIP = IPAddress(Tins::IPv6Address("2001:db8::2"));
            r.clientIP = q.serverIP;
            r.serverIP = q.clientIP;

            QueryResponse qr(make_unique<DNSMessage>(q));
            qr.set_response(make_unique<DNSMessage>(r));

            THEN("Flags are correct")
            {
                REQUIRE(transport_flags(qr) == IPV6);
            }
        }

        AND_WHEN("Transport is TCP IPv4 with no trailing data")
        {
            q.tcp = true;
            r.tcp = true;
            QueryResponse qr(make_unique<DNSMessage>(q));
            qr.set_response(make_unique<DNSMessage>(r));

            THEN("Flags are correct")
            {
                REQUIRE(transport_flags(qr) == TCP);
            }
        }

        AND_WHEN("Transport is TCP IPv6 with no trailing data")
        {
            q.clientIP = IPAddress(Tins::IPv6Address("2001:db8::1"));
            q.serverIP = IPAddress(Tins::IPv6Address("2001:db8::2"));
            r.clientIP = q.serverIP;
            r.serverIP = q.clientIP;
            q.tcp = true;
            r.tcp = true;
            QueryResponse qr(make_unique<DNSMessage>(q));
            qr.set_response(make_unique<DNSMessage>(r));

            THEN("Flags are correct")
            {
                REQUIRE(transport_flags(qr) == (IPV6 | TCP));
            }
        }
    }
}

SCENARIO("Previous version transport flags are encoded correctly", "[block flags]")
{
    GIVEN("Format 0.5 transport flags")
    {
        WHEN("Flags UDP, TCP and QUERY_TRAILINGDATA are set")
        {
            THEN("Flags are correct")
            {
                REQUIRE(convert_transport_flags(0, FileFormatVersion::format_05) == UDP);
                REQUIRE(convert_transport_flags(2, FileFormatVersion::format_05) == IPV6);
                REQUIRE(convert_transport_flags(1, FileFormatVersion::format_05) == TCP);
                REQUIRE(convert_transport_flags(4, FileFormatVersion::format_05) == QUERY_TRAILINGDATA);
                REQUIRE(convert_transport_flags(7, FileFormatVersion::format_05) == (IPV6 | TCP | QUERY_TRAILINGDATA));
            }
        }
    }
}
