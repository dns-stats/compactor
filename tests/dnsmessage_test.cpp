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

#include <chrono>
#include <sstream>

#include "bytestring.hpp"
#include "catch.hpp"
#include "packetstatistics.hpp"
#include "packetstream.hpp"
#include "dnsmessage.hpp"

SCENARIO("DNSMessage will report values", "[dump]")
{
    GIVEN("Some sample DNS message items")
    {
        DNSMessage d1;
        DNSMessage d2;

        d1.timestamp = std::chrono::system_clock::time_point(std::chrono::hours(24*365*20));
        d1.clientIP = IPAddress(Tins::IPv4Address("192.168.1.2"));
        d1.serverIP = IPAddress(Tins::IPv4Address("192.168.1.3"));
        d1.clientPort = 12345;
        d1.serverPort = 6789;
        d1.hoplimit = 254;
        d1.tcp = false;
        d1.dns.type(CaptureDNS::QUERY);
        d1.dns.id(54321);
        d1.dns.add_query(CaptureDNS::query("one", CaptureDNS::AAAA, CaptureDNS::IN));

        d2 = d1;
        d2.dns.type(CaptureDNS::RESPONSE);

        THEN("the dump output is correct")
        {
            std::ostringstream oss;
            oss << d1;
            std::string expected1 =
                "1989-12-27 00h00m00s0us UTC:\n"
                "\tClient IP: 192.168.1.2\n"
                "\tServer IP: 192.168.1.3\n"
                "\tTransport: UDP\n"
                "\tClient port: 12345\n"
                "\tServer port: 6789\n"
                "\tHop limit: 254\n"
                "\tDNS QR: Query\n"
                "\tID: 54321\n"
                "\tOpcode: 0\n"
                "\tRcode: 0\n"
                "\tFlags: \n"
                "\tQdCount: 1\n"
                "\tAnCount: 0\n"
                "\tNsCount: 0\n"
                "\tArCount: 0\n"
                "\tName: one\n"
                "\tType: 28\n"
                "\tClass: 1\n";

            REQUIRE(oss.str() == expected1);

            std::ostringstream oss2;
            oss2 << d2;
            std::string expected2 =
                "1989-12-27 00h00m00s0us UTC:\n"
                "\tClient IP: 192.168.1.2\n"
                "\tServer IP: 192.168.1.3\n"
                "\tTransport: UDP\n"
                "\tClient port: 12345\n"
                "\tServer port: 6789\n"
                "\tHop limit: 254\n"
                "\tDNS QR: Response\n"
                "\tID: 54321\n"
                "\tOpcode: 0\n"
                "\tRcode: 0\n"
                "\tFlags: \n"
                "\tQdCount: 1\n"
                "\tAnCount: 0\n"
                "\tNsCount: 0\n"
                "\tArCount: 0\n"
                "\tName: one\n"
                "\tType: 28\n"
                "\tClass: 1\n";

            REQUIRE(oss2.str() == expected2);
        }
    }
}

SCENARIO("DNSMessage correctly parses packet", "[parse]")
{
    GIVEN("A sample DNS query message")
    {
        const uint8_t msg_raw[] =
            { 0x0F,0x93,0x00,0x10,0x00,0x01,0x00,0x00,
              0x00,0x00,0x00,0x01,0x08,0x72,0x69,0x39,
              0x35,0x6E,0x73,0x30,0x31,0x08,0x77,0x6B,
              0x67,0x6C,0x6F,0x62,0x61,0x6C,0x03,0x6E,
              0x65,0x74,0x00,0x00,0x01,0x00,0x01,0x00,
              0x00,0x29,0x10,0x00,0x00,0x00,0x80,0x00,
              0x00,0x00 };
        DNSMessage msg(Tins::RawPDU(msg_raw, sizeof(msg_raw)),
                       std::chrono::system_clock::time_point(std::chrono::hours(24*365*20)),
                       IPAddress(Tins::IPv4Address("192.168.1.2")),
                       IPAddress(Tins::IPv4Address("192.168.1.3")),
                       12345, 6789,
                       254, false);

        THEN("Query is interpreted correctly")
        {
            std::ostringstream oss;
            oss << msg;
            std::string expected =
                "1989-12-27 00h00m00s0us UTC:\n"
                "\tClient IP: 192.168.1.2\n"
                "\tServer IP: 192.168.1.3\n"
                "\tTransport: UDP\n"
                "\tClient port: 12345\n"
                "\tServer port: 6789\n"
                "\tHop limit: 254\n"
                "\tDNS QR: Query\n"
                "\tID: 3987\n"
                "\tOpcode: 0\n"
                "\tRcode: 0\n"
                "\tFlags: CD \n"
                "\tQdCount: 1\n"
                "\tAnCount: 0\n"
                "\tNsCount: 0\n"
                "\tArCount: 1\n"
                "\tName: ri95ns01.wkglobal.net\n"
                "\tType: 1\n"
                "\tClass: 1\n";

            REQUIRE(oss.str() == expected);
            REQUIRE(msg.dns.questions_count() == 1);
            REQUIRE(msg.dns.answers_count() == 0);
            REQUIRE(msg.dns.authority_count() == 0);
            REQUIRE(msg.dns.additional_count() == 1);
            REQUIRE(msg.dns.trailing_data_size() == 0);

            CaptureDNS::query q = msg.dns.queries().front();
            REQUIRE(q.query_type() == CaptureDNS::A);
            REQUIRE(q.query_class() == CaptureDNS::IN);

            CaptureDNS::resource r = msg.dns.additional().front();
            REQUIRE(r.query_type() == CaptureDNS::OPT);
        }
    }

    GIVEN("A sample DNS query message with trailing data")
    {
        const uint8_t msg_raw[] =
            { 0x0F,0x93,0x00,0x10,0x00,0x01,0x00,0x00,
              0x00,0x00,0x00,0x01,0x08,0x72,0x69,0x39,
              0x35,0x6E,0x73,0x30,0x31,0x08,0x77,0x6B,
              0x67,0x6C,0x6F,0x62,0x61,0x6C,0x03,0x6E,
              0x65,0x74,0x00,0x00,0x01,0x00,0x01,0x00,
              0x00,0x29,0x10,0x00,0x00,0x00,0x80,0x00,
              0x00,0x00,0x01,0x02,0x03 };
        DNSMessage msg(Tins::RawPDU(msg_raw, sizeof(msg_raw)),
                       std::chrono::system_clock::time_point(std::chrono::hours(24*365*20)),
                       IPAddress(Tins::IPv4Address("192.168.1.2")),
                       IPAddress(Tins::IPv4Address("192.168.1.3")),
                       12345, 6789,
                       254, false);

        THEN("Query is interpreted correctly")
        {
            std::ostringstream oss;
            oss << msg;
            std::string expected =
                "1989-12-27 00h00m00s0us UTC:\n"
                "\tClient IP: 192.168.1.2\n"
                "\tServer IP: 192.168.1.3\n"
                "\tTransport: UDP\n"
                "\tClient port: 12345\n"
                "\tServer port: 6789\n"
                "\tHop limit: 254\n"
                "\tDNS QR: Query\n"
                "\tID: 3987\n"
                "\tOpcode: 0\n"
                "\tRcode: 0\n"
                "\tFlags: CD \n"
                "\tQdCount: 1\n"
                "\tAnCount: 0\n"
                "\tNsCount: 0\n"
                "\tArCount: 1\n"
                "\tName: ri95ns01.wkglobal.net\n"
                "\tType: 1\n"
                "\tClass: 1\n";

            REQUIRE(oss.str() == expected);
            REQUIRE(msg.dns.questions_count() == 1);
            REQUIRE(msg.dns.answers_count() == 0);
            REQUIRE(msg.dns.authority_count() == 0);
            REQUIRE(msg.dns.additional_count() == 1);
            REQUIRE(msg.dns.trailing_data_size() == 3);

            CaptureDNS::query q = msg.dns.queries().front();
            REQUIRE(q.query_type() == CaptureDNS::A);
            REQUIRE(q.query_class() == CaptureDNS::IN);

            CaptureDNS::resource r = msg.dns.additional().front();
            REQUIRE(r.query_type() == CaptureDNS::OPT);
        }
    }

    GIVEN("A malformed DNS query message")
    {
        const uint8_t msg_raw[] =
            { 0x50,0x05,0x00,0x35,0x00,0x30,
              0x79,0xB2,0xBE,0x6D,0x68,0x74,0x74,0x70,
              0x3A,0x2F,0x2F,0x61,0x74,0x6C,0x61,0x73,
              0x2E,0x72,0x69,0x70,0x65,0x2E,0x6E,0x65,
              0x74,0x20,0x41,0x74,0x6C,0x61,0x73,0x20,
              0x73,0x61,0x79,0x73,0x20,0x48,0x69,0x21,
              0x00,0x00 };

        THEN("Message is malformed")
        {
            REQUIRE_THROWS_AS(
                DNSMessage msg(Tins::RawPDU(msg_raw, sizeof(msg_raw)),
                               std::chrono::system_clock::time_point(std::chrono::hours(24*365*20)),
                               IPAddress(Tins::IPv4Address("192.168.1.2")),
                               IPAddress(Tins::IPv4Address("192.168.1.3")),
                               12345, 6789,
                               254, false),
                malformed_packet);
        }
    }

    GIVEN("A DNS query message with two step compression loop in the QNAME")
    {
        const uint8_t msg_raw[] =
            { 0x0F,0x93,0x00,0x10,0x00,0x01,0x00,0x00,
              0x00,0x00,0x00,0x01,0x08,0x72,0x69,0x39,
              0x35,0x6E,0x73,0x30,0x31,0xc0,0x17,0xc0,
              0x15,0x6C,0x6F,0x62,0x61,0x6C,0x03,0x6E,
              0x65,0x74,0x00,0x00,0x01,0x00,0x01,0x00,
              0x00,0x29,0x10,0x00,0x00,0x00,0x80,0x00,
              0x00,0x00 };

        THEN("Message is malformed")
        {
            REQUIRE_THROWS_AS(
                DNSMessage msg(Tins::RawPDU(msg_raw, sizeof(msg_raw)),
                               std::chrono::system_clock::time_point(std::chrono::hours(24*365*20)),
                               IPAddress(Tins::IPv4Address("192.168.1.2")),
                               IPAddress(Tins::IPv4Address("192.168.1.3")),
                               12345, 6789,
                               254, false),
                malformed_packet);
        }
    }

    GIVEN("A DNS query message with one step compression loop in the QNAME")
    {
        const uint8_t msg_raw[] =
            { 0x0F,0x93,0x00,0x10,0x00,0x01,0x00,0x00,
              0x00,0x00,0x00,0x01,0x08,0x72,0x69,0x39,
              0x35,0x6E,0x73,0x30,0x31,0xc0,0x15,0xc0,
              0x15,0x6C,0x6F,0x62,0x61,0x6C,0x03,0x6E,
              0x65,0x74,0x00,0x00,0x01,0x00,0x01,0x00,
              0x00,0x29,0x10,0x00,0x00,0x00,0x80,0x00,
              0x00,0x00 };

        THEN("Message is malformed")
        {
            REQUIRE_THROWS_AS(
                DNSMessage msg(Tins::RawPDU(msg_raw, sizeof(msg_raw)),
                               std::chrono::system_clock::time_point(std::chrono::hours(24*365*20)),
                               IPAddress(Tins::IPv4Address("192.168.1.2")),
                               IPAddress(Tins::IPv4Address("192.168.1.3")),
                               12345, 6789,
                               254, false),
                malformed_packet);
        }
    }

    GIVEN("A sample DNS response message")
    {
        const uint8_t msg_raw[] =
            { 0x0F,0x93,
              0x80,0x10,0x00,0x01,0x00,0x00,0x00,0x0F,
              0x00,0x10,0x08,0x72,0x69,0x39,0x35,0x6E,
              0x73,0x30,0x31,0x08,0x77,0x6B,0x67,0x6C,
              0x6F,0x62,0x61,0x6C,0x03,0x6E,0x65,0x74,
              0x00,0x00,0x01,0x00,0x01,0xC0,0x1E,0x00,
              0x02,0x00,0x01,0x00,0x02,0xA3,0x00,0x00,
              0x11,0x01,0x61,0x0C,0x67,0x74,0x6C,0x64,
              0x2D,0x73,0x65,0x72,0x76,0x65,0x72,0x73,
              0xC0,0x1E,0xC0,0x27,0x00,0x02,0x00,0x01,
              0x00,0x02,0xA3,0x00,0x00,0x04,0x01,0x62,
              0xC0,0x35,0xC0,0x27,0x00,0x02,0x00,0x01,
              0x00,0x02,0xA3,0x00,0x00,0x04,0x01,0x63,
              0xC0,0x35,0xC0,0x27,0x00,0x02,0x00,0x01,
              0x00,0x02,0xA3,0x00,0x00,0x04,0x01,0x64,
              0xC0,0x35,0xC0,0x27,0x00,0x02,0x00,0x01,
              0x00,0x02,0xA3,0x00,0x00,0x04,0x01,0x65,
              0xC0,0x35,0xC0,0x27,0x00,0x02,0x00,0x01,
              0x00,0x02,0xA3,0x00,0x00,0x04,0x01,0x66,
              0xC0,0x35,0xC0,0x27,0x00,0x02,0x00,0x01,
              0x00,0x02,0xA3,0x00,0x00,0x04,0x01,0x67,
              0xC0,0x35,0xC0,0x27,0x00,0x02,0x00,0x01,
              0x00,0x02,0xA3,0x00,0x00,0x04,0x01,0x68,
              0xC0,0x35,0xC0,0x27,0x00,0x02,0x00,0x01,
              0x00,0x02,0xA3,0x00,0x00,0x04,0x01,0x69,
              0xC0,0x35,0xC0,0x27,0x00,0x02,0x00,0x01,
              0x00,0x02,0xA3,0x00,0x00,0x04,0x01,0x6A,
              0xC0,0x35,0xC0,0x27,0x00,0x02,0x00,0x01,
              0x00,0x02,0xA3,0x00,0x00,0x04,0x01,0x6B,
              0xC0,0x35,0xC0,0x27,0x00,0x02,0x00,0x01,
              0x00,0x02,0xA3,0x00,0x00,0x04,0x01,0x6C,
              0xC0,0x35,0xC0,0x27,0x00,0x02,0x00,0x01,
              0x00,0x02,0xA3,0x00,0x00,0x04,0x01,0x6D,
              0xC0,0x35,0xC0,0x1E,0x00,0x2B,0x00,0x01,
              0x00,0x01,0x51,0x80,0x00,0x24,0x8C,0x2E,
              0x08,0x02,0x78,0x62,0xB2,0x7F,0x5F,0x51,
              0x6E,0xBE,0x19,0x68,0x04,0x44,0xD4,0xCE,
              0x5E,0x76,0x29,0x81,0x93,0x18,0x42,0xC4,
              0x65,0xF0,0x02,0x36,0x40,0x1D,0x8B,0xD9,
              0x73,0xEE,0xC1,0x04,0x00,0x2E,0x00,0x01,
              0x00,0x01,0x51,0x80,0x00,0x93,0x00,0x2B,
              0x08,0x01,0x00,0x01,0x51,0x80,0x57,0x11,
              0x1E,0x10,0x57,0x03,0xE1,0x00,0xEC,0xC7,
              0x00,0x46,0x28,0x86,0x90,0xB6,0xEA,0xD1,
              0x70,0xB0,0xED,0xF4,0xD8,0xF2,0x61,0xED,
              0x65,0x70,0xF1,0x16,0xEB,0x43,0xCA,0x74,
              0x85,0xE8,0x69,0x59,0x8C,0xF5,0xB0,0xAC,
              0xB2,0xF6,0x35,0xCE,0xFB,0x78,0xB9,0xF3,
              0xB2,0xD5,0x6F,0x13,0x27,0x5B,0x33,0xA7,
              0x82,0x59,0x80,0x9F,0x19,0x03,0x9D,0x1C,
              0x03,0x12,0xBB,0xA1,0x00,0xD3,0xC0,0x40,
              0xED,0x5C,0xB0,0xE6,0xC0,0xB8,0x5E,0x69,
              0x61,0x15,0x46,0x47,0x96,0x63,0xF5,0xFB,
              0xBD,0x87,0xA0,0x7A,0xF6,0x94,0xD8,0xBC,
              0x60,0x22,0x7F,0x89,0x34,0x50,0xF8,0x2D,
              0x77,0xE9,0x6D,0x87,0x29,0x7D,0xE6,0x81,
              0xE2,0xF0,0x1D,0xCA,0x41,0x05,0x62,0x85,
              0x0B,0xA0,0x72,0x4F,0x02,0x08,0xCA,0x7C,
              0x7F,0xA8,0xCF,0x2F,0xCB,0x6A,0x33,0xD7,
              0x9E,0xC0,0x33,0x00,0x01,0x00,0x01,0x00,
              0x02,0xA3,0x00,0x00,0x04,0xC0,0x05,0x06,
              0x1E,0xC0,0x33,0x00,0x1C,0x00,0x01,0x00,
              0x02,0xA3,0x00,0x00,0x10,0x20,0x01,0x05,
              0x03,0xA8,0x3E,0x00,0x00,0x00,0x00,0x00,
              0x00,0x00,0x02,0x00,0x30,0xC0,0x50,0x00,
              0x01,0x00,0x01,0x00,0x02,0xA3,0x00,0x00,
              0x04,0xC0,0x21,0x0E,0x1E,0xC0,0x50,0x00,
              0x1C,0x00,0x01,0x00,0x02,0xA3,0x00,0x00,
              0x10,0x20,0x01,0x05,0x03,0x23,0x1D,0x00,
              0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,
              0x30,0xC0,0x60,0x00,0x01,0x00,0x01,0x00,
              0x02,0xA3,0x00,0x00,0x04,0xC0,0x1A,0x5C,
              0x1E,0xC0,0x70,0x00,0x01,0x00,0x01,0x00,
              0x02,0xA3,0x00,0x00,0x04,0xC0,0x1F,0x50,
              0x1E,0xC0,0x80,0x00,0x01,0x00,0x01,0x00,
              0x02,0xA3,0x00,0x00,0x04,0xC0,0x0C,0x5E,
              0x1E,0xC0,0x90,0x00,0x01,0x00,0x01,0x00,
              0x02,0xA3,0x00,0x00,0x04,0xC0,0x23,0x33,
              0x1E,0xC0,0xA0,0x00,0x01,0x00,0x01,0x00,
              0x02,0xA3,0x00,0x00,0x04,0xC0,0x2A,0x5D,
              0x1E,0xC0,0xB0,0x00,0x01,0x00,0x01,0x00,
              0x02,0xA3,0x00,0x00,0x04,0xC0,0x36,0x70,
              0x1E,0xC0,0xC0,0x00,0x01,0x00,0x01,0x00,
              0x02,0xA3,0x00,0x00,0x04,0xC0,0x2B,0xAC,
              0x1E,0xC0,0xD0,0x00,0x01,0x00,0x01,0x00,
              0x02,0xA3,0x00,0x00,0x04,0xC0,0x30,0x4F,
              0x1E,0xC0,0xE0,0x00,0x01,0x00,0x01,0x00,
              0x02,0xA3,0x00,0x00,0x04,0xC0,0x34,0xB2,
              0x1E,0xC0,0xF0,0x00,0x01,0x00,0x01,0x00,
              0x02,0xA3,0x00,0x00,0x04,0xC0,0x29,0xA2,
              0x1E,0xC1,0x00,0x00,0x01,0x00,0x01,0x00,
              0x02,0xA3,0x00,0x00,0x04,0xC0,0x37,0x53,
              0x1E,0x00,0x00,0x29,0x10,0x00,0x00,0x00,
              0x80,0x00,0x00,0x00 };
        DNSMessage msg(Tins::RawPDU(msg_raw, sizeof(msg_raw)),
                       std::chrono::system_clock::time_point(std::chrono::hours(24*365*20)),
                       IPAddress(Tins::IPv4Address("192.168.1.2")),
                       IPAddress(Tins::IPv4Address("192.168.1.3")),
                       12345, 6789,
                       254, false);
        THEN("Response is interpreted correctly")
        {
            std::ostringstream oss;
            oss << msg;
            std::string expected =
                "1989-12-27 00h00m00s0us UTC:\n"
                "\tClient IP: 192.168.1.3\n"
                "\tServer IP: 192.168.1.2\n"
                "\tTransport: UDP\n"
                "\tClient port: 6789\n"
                "\tServer port: 12345\n"
                "\tHop limit: 254\n"
                "\tDNS QR: Response\n"
                "\tID: 3987\n"
                "\tOpcode: 0\n"
                "\tRcode: 0\n"
                "\tFlags: CD \n"
                "\tQdCount: 1\n"
                "\tAnCount: 0\n"
                "\tNsCount: 15\n"
                "\tArCount: 16\n"
                "\tName: ri95ns01.wkglobal.net\n"
                "\tType: 1\n"
                "\tClass: 1\n";

            REQUIRE(oss.str() == expected);

            REQUIRE(msg.dns.questions_count() == 1);
            REQUIRE(msg.dns.answers_count() == 0);
            REQUIRE(msg.dns.authority_count() == 15);
            REQUIRE(msg.dns.additional_count() == 16);

            CaptureDNS::query q = msg.dns.queries().front();
            REQUIRE(q.query_type() == CaptureDNS::A);
            REQUIRE(q.query_class() == CaptureDNS::IN);

            CaptureDNS::resource r = msg.dns.additional().back();
            REQUIRE(r.query_type() == CaptureDNS::OPT);
        }
    }
}

SCENARIO("DNSMessage correctly parses RDATA", "[parse]")
{
    GIVEN("A sample MX response DNS message")
    {
        const uint8_t msg_raw[] =
            { 0x50,0x12,0x81,0x80,0x00,0x01,
              0x00,0x01,0x00,0x02,0x00,0x02,0x07,0x73,
              0x69,0x6e,0x6f,0x64,0x75,0x6e,0x03,0x63,
              0x6f,0x6d,0x00,0x00,0x0f,0x00,0x01,0xc0,
              0x0c,0x00,0x0f,0x00,0x01,0x00,0x00,0x01,
              0x2c,0x00,0x0a,0x00,0x0a,0x05,0x63,0x6f,
              0x72,0x65,0x31,0xc0,0x0c,0xc0,0x0c,0x00,
              0x02,0x00,0x01,0x00,0x00,0x00,0xe9,0x00,
              0x07,0x04,0x63,0x6f,0x72,0x65,0xc0,0x0c,
              0xc0,0x0c,0x00,0x02,0x00,0x01,0x00,0x00,
              0x00,0xe9,0x00,0x02,0xc0,0x2b,0xc0,0x2b,
              0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x23,
              0x00,0x04,0xc0,0xa8,0x01,0x94,0xc0,0x3f,
              0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x23,
              0x00,0x04,0xc0,0xa8,0x01,0x83 };
        DNSMessage msg(Tins::RawPDU(msg_raw, sizeof(msg_raw)),
                       std::chrono::system_clock::time_point(std::chrono::hours(24*365*20)),
                       IPAddress(Tins::IPv4Address("192.168.1.2")),
                       IPAddress(Tins::IPv4Address("192.168.1.3")),
                       12345, 6789,
                       254, false);

        THEN("Message is interpreted correctly")
        {
            std::ostringstream oss;
            oss << msg;
            std::string expected =
                "1989-12-27 00h00m00s0us UTC:\n"
                "\tClient IP: 192.168.1.3\n"
                "\tServer IP: 192.168.1.2\n"
                "\tTransport: UDP\n"
                "\tClient port: 6789\n"
                "\tServer port: 12345\n"
                "\tHop limit: 254\n"
                "\tDNS QR: Response\n"
                "\tID: 20498\n"
                "\tOpcode: 0\n"
                "\tRcode: 0\n"
                "\tFlags: RD RA \n"
                "\tQdCount: 1\n"
                "\tAnCount: 1\n"
                "\tNsCount: 2\n"
                "\tArCount: 2\n"
                "\tName: sinodun.com\n"
                "\tType: 15\n"
                "\tClass: 1\n";

            REQUIRE(oss.str() == expected);
            REQUIRE(msg.dns.answers_count() == 1);
            REQUIRE(msg.dns.authority_count() == 2);
            REQUIRE(msg.dns.additional_count() == 2);

            auto answer = msg.dns.answers().front();
            REQUIRE(answer.query_type() == CaptureDNS::MX);
            REQUIRE(answer.query_class() == CaptureDNS::IN);
            REQUIRE(answer.ttl() == 300);

            // Note in the original the name is compressed;
            // 'core1' is present, but is followed by a pointer to
            // an earlier 'sinodun.com'.
            byte_string EXPECTED_ANS_DATA =
                { 0x00, 0x0a,
                  0x05, 'c', 'o', 'r', 'e', '1',
                  0x07, 's', 'i', 'n', 'o', 'd', 'u', 'n',
                  0x03, 'c', 'o', 'm',
                  0x00
                };
            REQUIRE(answer.data() == EXPECTED_ANS_DATA);

            auto auth = msg.dns.authority().front();
            REQUIRE(auth.query_type() == CaptureDNS::NS);
            REQUIRE(auth.query_class() == CaptureDNS::IN);
            REQUIRE(auth.ttl() == 233);

            byte_string EXPECTED_AUTH_DATA =
                { 0x04, 'c', 'o', 'r', 'e',
                  0x07, 's', 'i', 'n', 'o', 'd', 'u', 'n',
                  0x03, 'c', 'o', 'm',
                  0x00
                };
            REQUIRE(auth.data() == EXPECTED_AUTH_DATA);

            auto add = msg.dns.additional().front();
            REQUIRE(add.query_type() == CaptureDNS::A);
            REQUIRE(add.query_class() == CaptureDNS::IN);
            REQUIRE(add.ttl() == 35);

            byte_string EXPECTED_ADD_DATA = { 0xc0, 0xa8, 0x01, 0x94 };
            REQUIRE(add.data() == EXPECTED_ADD_DATA);
        }
    }

    GIVEN("A sample TXT response DNS message")
    {
        const uint8_t msg_raw[] =
            { 0xd9,0x0a,0x80,0x00,0x00,0x01,
              0x00,0x01,0x00,0x00,0x00,0x00,0x08,0x68,
              0x6f,0x73,0x74,0x6e,0x61,0x6d,0x65,0x04,
              0x62,0x69,0x6e,0x64,0x00,0x00,0x10,0x00,
              0x03,0xc0,0x0c,0x00,0x10,0x00,0x03,0x00,
              0x00,0x00,0x00,0x00,0x19,0x18,0x74,0x65,
              0x73,0x74,0x73,0x2e,0x63,0x6f,0x6d,0x70,
              0x61,0x63,0x74,0x6f,0x72,0x74,0x65,0x73,
              0x74,0x73,0x2e,0x6f,0x72,0x67 };
        DNSMessage msg(Tins::RawPDU(msg_raw, sizeof(msg_raw)),
                       std::chrono::system_clock::time_point(std::chrono::hours(24*365*20)),
                       IPAddress(Tins::IPv4Address("192.168.1.2")),
                       IPAddress(Tins::IPv4Address("192.168.1.3")),
                       12345, 6789,
                       254, false);

        THEN("Message is interpreted correctly")
        {
            std::ostringstream oss;
            oss << msg;
            std::string expected =
                "1989-12-27 00h00m00s0us UTC:\n"
                "\tClient IP: 192.168.1.3\n"
                "\tServer IP: 192.168.1.2\n"
                "\tTransport: UDP\n"
                "\tClient port: 6789\n"
                "\tServer port: 12345\n"
                "\tHop limit: 254\n"
                "\tDNS QR: Response\n"
                "\tID: 55562\n"
                "\tOpcode: 0\n"
                "\tRcode: 0\n"
                "\tFlags: \n"
                "\tQdCount: 1\n"
                "\tAnCount: 1\n"
                "\tNsCount: 0\n"
                "\tArCount: 0\n"
                "\tName: hostname.bind\n"
                "\tType: 16\n"
                "\tClass: 3\n";

            REQUIRE(oss.str() == expected);
            REQUIRE(msg.dns.answers_count() == 1);
            REQUIRE(msg.dns.authority_count() == 0);
            REQUIRE(msg.dns.additional_count() == 0);

            auto answer = msg.dns.answers().front();
            REQUIRE(answer.query_type() == CaptureDNS::TXT);
            REQUIRE(answer.query_class() == CaptureDNS::CH);
            REQUIRE(answer.ttl() == 0);

            REQUIRE(answer.data() == "\x18tests.compactortests.org"_b);
        }
    }

    GIVEN("A sample SOA response DNS message")
    {
        const uint8_t msg_raw[] =
            { 0x22,0xee,0x81,0x80,0x00,0x01,0x00,0x01,
              0x00,0x02,0x00,0x02,0x07,0x73,0x69,0x6e,
              0x6f,0x64,0x75,0x6e,0x03,0x63,0x6f,0x6d,
              0x00,0x00,0x06,0x00,0x01,0xc0,0x0c,0x00,
              0x06,0x00,0x01,0x00,0x00,0x00,0xf4,0x00,
              0x23,0x04,0x63,0x6f,0x72,0x65,0xc0,0x0c,
              0x05,0x61,0x64,0x6d,0x69,0x6e,0xc0,0x0c,
              0x78,0x2a,0xcd,0xbe,0x00,0x00,0x75,0x30,
              0x00,0x00,0x01,0x2c,0x00,0x09,0x3a,0x80,
              0x00,0x00,0x01,0x2c,0xc0,0x0c,0x00,0x02,
              0x00,0x01,0x00,0x00,0x00,0xcf,0x00,0x02,
              0xc0,0x29,0xc0,0x0c,0x00,0x02,0x00,0x01,
              0x00,0x00,0x00,0xcf,0x00,0x08,0x05,0x63,
              0x6f,0x72,0x65,0x31,0xc0,0x0c,0xc0,0x29,
              0x00,0x01,0x00,0x01,0x00,0x00,0x00,0xcf,
              0x00,0x04,0xc0,0xa8,0x01,0x83,0xc0,0x66,
              0x00,0x01,0x00,0x01,0x00,0x00,0x00,0xcf,
              0x00,0x04,0xc0,0xa8,0x01,0x94 };
        DNSMessage msg(Tins::RawPDU(msg_raw, sizeof(msg_raw)),
                       std::chrono::system_clock::time_point(std::chrono::hours(24*365*20)),
                       IPAddress(Tins::IPv4Address("192.168.1.2")),
                       IPAddress(Tins::IPv4Address("192.168.1.3")),
                       12345, 6789,
                       254, false);

        THEN("Message is interpreted correctly")
        {
            std::ostringstream oss;
            oss << msg;
            std::string expected =
                "1989-12-27 00h00m00s0us UTC:\n"
                "\tClient IP: 192.168.1.3\n"
                "\tServer IP: 192.168.1.2\n"
                "\tTransport: UDP\n"
                "\tClient port: 6789\n"
                "\tServer port: 12345\n"
                "\tHop limit: 254\n"
                "\tDNS QR: Response\n"
                "\tID: 8942\n"
                "\tOpcode: 0\n"
                "\tRcode: 0\n"
                "\tFlags: RD RA \n"
                "\tQdCount: 1\n"
                "\tAnCount: 1\n"
                "\tNsCount: 2\n"
                "\tArCount: 2\n"
                "\tName: sinodun.com\n"
                "\tType: 6\n"
                "\tClass: 1\n";

            REQUIRE(oss.str() == expected);
            REQUIRE(msg.dns.answers_count() == 1);
            REQUIRE(msg.dns.authority_count() == 2);
            REQUIRE(msg.dns.additional_count() == 2);

            auto answer = msg.dns.answers().front();
            REQUIRE(answer.query_type() == CaptureDNS::SOA);
            REQUIRE(answer.query_class() == CaptureDNS::IN);
            REQUIRE(answer.ttl() == 244);

            // Note in the original the names are compressed.
            byte_string EXPECTED_ANS_DATA =
                { 0x04, 'c', 'o', 'r', 'e',
                  0x07, 's', 'i', 'n', 'o', 'd', 'u', 'n',
                  0x03, 'c', 'o', 'm',
                  0x00,
                  0x05, 'a', 'd', 'm', 'i', 'n',
                  0x07, 's', 'i', 'n', 'o', 'd', 'u', 'n',
                  0x03, 'c', 'o', 'm',
                  0x00,
                  0x78,0x2a,0xcd,0xbe,
                  0x00,0x00,0x75,0x30,
                  0x00,0x00,0x01,0x2c,
                  0x00,0x09,0x3a,0x80,
                  0x00,0x00,0x01,0x2c,
                };
            REQUIRE(answer.data() == EXPECTED_ANS_DATA);

            auto auth = msg.dns.authority().front();
            REQUIRE(auth.query_type() == CaptureDNS::NS);
            REQUIRE(auth.query_class() == CaptureDNS::IN);
            REQUIRE(auth.ttl() == 207);

            byte_string EXPECTED_AUTH_DATA =
                { 0x04, 'c', 'o', 'r', 'e',
                  0x07, 's', 'i', 'n', 'o', 'd', 'u', 'n',
                  0x03, 'c', 'o', 'm',
                  0x00
                };
            REQUIRE(auth.data() == EXPECTED_AUTH_DATA);

            auto add = msg.dns.additional().front();
            REQUIRE(add.query_type() == CaptureDNS::A);
            REQUIRE(add.query_class() == CaptureDNS::IN);
            REQUIRE(add.ttl() == 207);

            byte_string EXPECTED_ADD_DATA = { 0xc0, 0xa8, 0x01, 0x83 };
            REQUIRE(add.data() == EXPECTED_ADD_DATA);
        }
    }
}
