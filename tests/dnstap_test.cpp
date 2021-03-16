/*
 * Copyright 2021 Internet Corporation for Assigned Names and Numbers.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Developed by Sinodun IT (www.sinodun.com)
 */

#include <sstream>

#include "catch.hpp"

#define protected public
#include "dnstap.hpp"
#undef protected

enum FstrmControlFrame
{
    ACCEPT = 1,
    START  = 2,
    STOP   = 3,
    READY  = 4,
    FINISH = 5,
};

SCENARIO("DnsTap generates control frames", "[dnstap]")
{
    GIVEN("An ACCEPT frame as input")
    {
        auto dnstap_sink =
            [&](std::unique_ptr<DNSMessage>& dns)
            {
            };
        std::string accept = DnsTap::make_accept();
        std::stringstream str(accept);
        DnsTap tap(dnstap_sink);

        THEN("ACCEPT frame is correct")
        {
            REQUIRE(tap.get_value(str) == 0);
            REQUIRE(tap.read_control_frame(str) == ACCEPT);
        }
    }

    GIVEN("A FINISH frame as input")
    {
        auto dnstap_sink =
            [&](std::unique_ptr<DNSMessage>& dns)
            {
            };
        std::string finish = DnsTap::make_finish();
        std::stringstream str(finish);
        DnsTap tap(dnstap_sink);

        THEN("FINISH frame is correct")
        {
            REQUIRE(tap.get_value(str) == 0);
            REQUIRE(tap.read_control_frame(str) == FINISH);
        }
    }
}

SCENARIO("DnsTap parses control frames", "[dnstap]")
{
    GIVEN("An ACCEPT frame as input")
    {
        const char accept_raw[] =
            "\0\0\0\x22" // Overall length
            "\0\0\0\1"   // control type
            "\0\0\0\1"   // control field type
            "\0\0\0\x16" // control field length
            "protobuf:dnstap.Dnstap";

        auto dnstap_sink =
            [&](std::unique_ptr<DNSMessage>& dns)
            {
            };
        std::string accept(accept_raw, sizeof(accept_raw));
        std::stringstream str(accept);
        DnsTap tap(dnstap_sink);

        THEN("ACCEPT frame is correct")
        {
            REQUIRE(tap.read_control_frame(str) == ACCEPT);
        }
    }

    GIVEN("A START frame as input")
    {
        const char start_raw[] =
            "\0\0\0\x22" // Overall length
            "\0\0\0\2"   // control type
            "\0\0\0\1"   // control field type
            "\0\0\0\x16" // control field length
            "protobuf:dnstap.Dnstap";

        auto dnstap_sink =
            [&](std::unique_ptr<DNSMessage>& dns)
            {
            };
        std::string start(start_raw, sizeof(start_raw));
        std::stringstream str(start);
        DnsTap tap(dnstap_sink);

        THEN("START frame is correct")
        {
            REQUIRE(tap.read_control_frame(str) == START);
        }
    }

    GIVEN("A READY frame as input")
    {
        const char ready_raw[] =
            "\0\0\0\x22" // Overall length
            "\0\0\0\4"   // control type
            "\0\0\0\1"   // control field type
            "\0\0\0\x16" // control field length
            "protobuf:dnstap.Dnstap";

        auto dnstap_sink =
            [&](std::unique_ptr<DNSMessage>& dns)
            {
            };
        std::string ready(ready_raw, sizeof(ready_raw));
        std::stringstream str(ready);
        DnsTap tap(dnstap_sink);

        THEN("READY frame is correct")
        {
            REQUIRE(tap.read_control_frame(str) == READY);
        }
    }

    GIVEN("A STOP frame as input")
    {
        const char stop_raw[] =
            { 0x00, 0x00, 0x00, 0x04,
              0x00, 0x00, 0x00, 0x03
            };

        auto dnstap_sink =
            [&](std::unique_ptr<DNSMessage>& dns)
            {
            };
        std::string stop(stop_raw, sizeof(stop_raw));
        std::stringstream str(stop);
        DnsTap tap(dnstap_sink);

        THEN("STOP frame is correct")
        {
            REQUIRE(tap.read_control_frame(str) == STOP);
        }
    }

    GIVEN("A FINISH frame as input")
    {
        const char finish_raw[] =
            { 0x00, 0x00, 0x00, 0x04,
              0x00, 0x00, 0x00, 0x05
            };

        auto dnstap_sink =
            [&](std::unique_ptr<DNSMessage>& dns)
            {
            };
        std::string finish(finish_raw, sizeof(finish_raw));
        std::stringstream str(finish);
        DnsTap tap(dnstap_sink);

        THEN("FINISH frame is correct")
        {
            REQUIRE(tap.read_control_frame(str) == FINISH);
        }
    }

    GIVEN("A unknown control frame as input")
    {
        const char frame_raw[] =
            { 0x00, 0x00, 0x00, 0x04,
              0x00, 0x00, 0x00, 0x06
            };

        auto dnstap_sink =
            [&](std::unique_ptr<DNSMessage>& dns)
            {
            };
        std::string frame(frame_raw, sizeof(frame_raw));
        std::stringstream str(frame);
        DnsTap tap(dnstap_sink);

        THEN("Frame is read but rejected")
        {
            REQUIRE(tap.read_control_frame(str) == 6);
            REQUIRE_THROWS_AS(
                tap.process_control_frame(str, 6),
                dnstap_invalid);
        }
    }

    GIVEN("A READY control frame with invalid control field type as input")
    {
        const char ready_raw[] =
            "\0\0\0\x22" // Overall length
            "\0\0\0\4"   // control type
            "\0\0\0\2"   // control field type
            "\0\0\0\x16" // control field length
            "protobuf:dnstap.Dnstap";

        auto dnstap_sink =
            [&](std::unique_ptr<DNSMessage>& dns)
            {
            };
        std::string ready(ready_raw, sizeof(ready_raw));
        std::stringstream str(ready);
        DnsTap tap(dnstap_sink);

        THEN("READY frame is correct")
        {
            REQUIRE_THROWS_AS(tap.read_control_frame(str), dnstap_invalid);
        }
    }

    GIVEN("A READY control frame with invalid content type as input")
    {
        const char ready_raw[] =
            "\0\0\0\x22" // Overall length
            "\0\0\0\4"   // control type
            "\0\0\0\1"   // control field type
            "\0\0\0\x16" // control field length
            "protobuf:dnsxxx.Dnstap";

        auto dnstap_sink =
            [&](std::unique_ptr<DNSMessage>& dns)
            {
            };
        std::string ready(ready_raw, sizeof(ready_raw));
        std::stringstream str(ready);
        DnsTap tap(dnstap_sink);

        THEN("READY frame is correct")
        {
            REQUIRE_THROWS_AS(tap.read_control_frame(str), dnstap_invalid);
        }
    }
}

SCENARIO("DnsTap parses data frames", "[dnstap]")
{
    GIVEN("A data frame as input")
    {
        const uint8_t data_raw[] =
            { 0x00, 0x00, 0x00, 0x6d,
              0x0a, 0x08, 0x72, 0x65, 0x73, 0x6f, 0x6c, 0x76,
              0x65, 0x72, 0x12, 0x0e, 0x4b, 0x6e, 0x6f, 0x74,
              0x20, 0x44, 0x4e, 0x53, 0x20, 0x32, 0x2e, 0x39,
              0x2e, 0x38, 0x72, 0x4f, 0x08, 0x01, 0x10, 0x01,
              0x18, 0x01, 0x22, 0x04, 0x0a, 0x00, 0x02, 0x28,
              0x30, 0xf8, 0xf7, 0x02, 0x40, 0x96, 0xcc, 0xf9,
              0x81, 0x06, 0x4d, 0x00, 0x00, 0x00, 0x00, 0x52,
              0x32, 0xdf, 0x04, 0x00, 0x10, 0x00, 0x01, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x01, 0x04, 0x66, 0x72,
              0x65, 0x64, 0x04, 0x69, 0x70, 0x76, 0x34, 0x07,
              0x73, 0x69, 0x6e, 0x6f, 0x64, 0x75, 0x6e, 0x03,
              0x63, 0x6f, 0x6d, 0x00, 0x00, 0x02, 0x00, 0x01,
              0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x80,
              0x00, 0x00, 0x00, 0x78, 0x01
            };

        auto dnstap_sink =
            [&](std::unique_ptr<DNSMessage>& dns)
            {
            };
        std::string data(reinterpret_cast<const char*>(data_raw), sizeof(data_raw));
        std::stringstream str(data, std::ios_base::in);
        DnsTap tap(dnstap_sink);

        THEN("Data frame is correct")
        {
            REQUIRE(tap.get_value(str) == 0x6d);
            std::unique_ptr<DNSMessage> dns = tap.read_data_frame(str, 0x6d);
            std::ostringstream oss;
            oss << *dns;
            std::string expected =
                "2021-03-02 16h21m42s0us UTC\n"
                "\tClient IP: 10.0.2.40\n"
                "\tTransport: UDP\n"
                "\tClient port: 48120\n"
                "\tTransaction type: Auth query\n"
                "\tDNS QR: Query\n"
                "\tID: 57092\n"
                "\tOpcode: 0\n"
                "\tRcode: 0\n"
                "\tFlags: CD \n"
                "\tQdCount: 1\n"
                "\tAnCount: 0\n"
                "\tNsCount: 0\n"
                "\tArCount: 1\n"
                "\tName: fred.ipv4.sinodun.com\n"
                "\tType: 2\n"
                "\tClass: 1\n";

            REQUIRE(oss.str() == expected);
        }
    }

    GIVEN("An invalid data frame as input")
    {
        const uint8_t data_raw[] =
            { 0x00, 0x00, 0x00, 0x6d,
              0xff, 0xff, 0xff, 0xff, 0x73, 0x6f, 0x6c, 0x76,
              0x65, 0x72, 0x12, 0x0e, 0x4b, 0x6e, 0x6f, 0x74,
              0x20, 0x44, 0x4e, 0x53, 0x20, 0x32, 0x2e, 0x39,
              0x2e, 0x38, 0x72, 0x4f, 0x08, 0x01, 0x10, 0x01,
              0x18, 0x01, 0x22, 0x04, 0x0a, 0x00, 0x02, 0x28,
              0x30, 0xf8, 0xf7, 0x02, 0x40, 0x96, 0xcc, 0xf9,
              0x81, 0x06, 0x4d, 0x00, 0x00, 0x00, 0x00, 0x52,
              0x32, 0xdf, 0x04, 0x00, 0x10, 0x00, 0x01, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x01, 0x04, 0x66, 0x72,
              0x65, 0x64, 0x04, 0x69, 0x70, 0x76, 0x34, 0x07,
              0x73, 0x69, 0x6e, 0x6f, 0x64, 0x75, 0x6e, 0x03,
              0x63, 0x6f, 0x6d, 0x00, 0x00, 0x02, 0x00, 0x01,
              0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x80,
              0x00, 0x00, 0x00, 0x78, 0x01
            };

        auto dnstap_sink =
            [&](std::unique_ptr<DNSMessage>& dns)
            {
            };
        std::string data(reinterpret_cast<const char*>(data_raw), sizeof(data_raw));
        std::stringstream str(data);
        DnsTap tap(dnstap_sink);

        THEN("Data frame is rejected")
        {
            REQUIRE(tap.get_value(str) == 0x6d);
            REQUIRE_THROWS_AS(tap.read_data_frame(str, 0x6d), dnstap_invalid);
        }
    }
}

SCENARIO("DnsTap control sequence", "[dnstap]")
{
    GIVEN("A unidirectional control sequence")
    {
        auto dnstap_sink =
            [&](std::unique_ptr<DNSMessage>& dns)
            {
            };
        std::stringstream ss;
        DnsTap tap(dnstap_sink);

        THEN("Correct unidirectional sequence is processed as expected")
        {
            REQUIRE(tap.process_control_frame(ss, START));
            REQUIRE_FALSE(tap.process_control_frame(ss, STOP));
            REQUIRE(ss.str().empty());
        }

        AND_THEN("START must precede data")
        {
            REQUIRE_THROWS_AS(tap.process_data_frame(std::make_unique<DNSMessage>()), dnstap_invalid);
        }

        AND_THEN("START must precede STOP")
        {
            REQUIRE_THROWS_AS(tap.process_control_frame(ss, STOP), dnstap_invalid);
        }

        AND_THEN("Cannot have START repeated")
        {
            REQUIRE(tap.process_control_frame(ss, START));
            REQUIRE_THROWS_AS(tap.process_control_frame(ss, START), dnstap_invalid);
        }
    }

    GIVEN("A bidirectional control sequence")
    {
        auto dnstap_sink =
            [&](std::unique_ptr<DNSMessage>& dns)
            {
            };
        std::stringstream ss;
        DnsTap tap(dnstap_sink);

        THEN("Correct bidirectional sequence is processed as expected")
        {
            REQUIRE(tap.process_control_frame(ss, READY));
            REQUIRE(tap.process_control_frame(ss, START));
            REQUIRE_FALSE(tap.process_control_frame(ss, STOP));
            REQUIRE_FALSE(ss.str().empty());
        }

        AND_THEN("Must start with READY and then START")
        {
            REQUIRE(tap.process_control_frame(ss, START));
            REQUIRE_THROWS_AS(tap.process_control_frame(ss, READY), dnstap_invalid);
        }

        AND_THEN("Must start with READY and then START")
        {
            REQUIRE(tap.process_control_frame(ss, READY));
            REQUIRE_THROWS_AS(tap.process_control_frame(ss, STOP), dnstap_invalid);
        }

        AND_THEN("START must precede data")
        {
            REQUIRE(tap.process_control_frame(ss, READY));
            REQUIRE_THROWS_AS(tap.process_data_frame(std::make_unique<DNSMessage>()), dnstap_invalid);
        }
    }
}
