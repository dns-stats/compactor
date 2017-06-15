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

#include <vector>

#include "catch.hpp"

#define private public
#include "capturedns.hpp"
#undef private

SCENARIO("Serialising DNS packets", "[dnspacket]")
{
    GIVEN("A sample DNS message with one compression")
    {
        CaptureDNS msg;
        msg.id(0x6692);
        msg.type(CaptureDNS::RESPONSE);
        msg.add_query(
            CaptureDNS::query(
                CaptureDNS::encode_domain_name("sec2.apnic.com"),
                CaptureDNS::A,
                CaptureDNS::IN
                )
            );
        msg.add_authority(
            CaptureDNS::resource(
                CaptureDNS::encode_domain_name("com"),
                CaptureDNS::encode_domain_name("a.gtld-servers.net"),
                CaptureDNS::NS,
                CaptureDNS::IN,
                172800)
            );

        THEN("Message is serialised with compressed name")
        {
            std::vector<uint8_t> EXPECTED
                { 0x66,0x92,0x80,0x00,0x00,0x01,0x00,0x00,
                  0x00,0x01,0x00,0x00,0x04,0x73,0x65,0x63,
                  0x32,0x05,0x61,0x70,0x6e,0x69,0x63,0x03,
                  0x63,0x6f,0x6d,0x00,0x00,0x01,0x00,0x01,
                  0xc0,0x17,0x00,0x02,0x00,0x01,0x00,0x02,
                  0xa3,0x00,0x00,0x14,0x01,0x61,0x0c,0x67,
                  0x74,0x6c,0x64,0x2d,0x73,0x65,0x72,0x76,
                  0x65,0x72,0x73,0x03,0x6e,0x65,0x74,0x00
                };
            uint32_t pkt_size = msg.header_size();
            REQUIRE(pkt_size == EXPECTED.size());

            std::vector<uint8_t> buf(pkt_size);
            msg.write_serialization(buf.data(), pkt_size, nullptr);
            REQUIRE(buf == EXPECTED);
        }
    }

    GIVEN("A sample DNS message with several single level compressions")
    {
        CaptureDNS msg;
        msg.id(0x6692);
        msg.type(CaptureDNS::RESPONSE);
        msg.add_query(
            CaptureDNS::query(
                CaptureDNS::encode_domain_name("sec2.apnic.com"),
                CaptureDNS::A,
                CaptureDNS::IN
                )
            );
        msg.add_authority(
            CaptureDNS::resource(
                CaptureDNS::encode_domain_name("com"),
                CaptureDNS::encode_domain_name("a.gtld-servers.net"),
                CaptureDNS::NS,
                CaptureDNS::IN,
                172800)
            );
        msg.add_authority(
            CaptureDNS::resource(
                CaptureDNS::encode_domain_name("com"),
                CaptureDNS::encode_domain_name("b.gtld-servers.net"),
                CaptureDNS::NS,
                CaptureDNS::IN,
                172800)
            );

        THEN("Message is serialised with compressed name")
        {
            std::vector<uint8_t> EXPECTED
                { 0x66,0x92,0x80,0x00,0x00,0x01,0x00,0x00,
                  0x00,0x02,0x00,0x00,0x04,0x73,0x65,0x63,
                  0x32,0x05,0x61,0x70,0x6e,0x69,0x63,0x03,
                  0x63,0x6f,0x6d,0x00,0x00,0x01,0x00,0x01,
                  0xc0,0x17,0x00,0x02,0x00,0x01,0x00,0x02,
                  0xa3,0x00,0x00,0x14,0x01,0x61,0x0c,0x67,
                  0x74,0x6c,0x64,0x2d,0x73,0x65,0x72,0x76,
                  0x65,0x72,0x73,0x03,0x6e,0x65,0x74,0x00,
                  0xc0,0x17,0x00,0x02,0x00,0x01,0x00,0x02,
                  0xa3,0x00,0x00,0x04,0x01,0x62,0xc0,0x2e
                };
            uint32_t pkt_size = msg.header_size();
            REQUIRE(pkt_size == EXPECTED.size());

            std::vector<uint8_t> buf(pkt_size);
            msg.write_serialization(buf.data(), pkt_size, nullptr);
            REQUIRE(buf == EXPECTED);
        }
    }

    GIVEN("A sample DNS message with two level compressions")
    {
        CaptureDNS msg;
        msg.id(0x6692);
        msg.type(CaptureDNS::RESPONSE);
        msg.add_query(
            CaptureDNS::query(
                CaptureDNS::encode_domain_name("sec2.apnic.net"),
                CaptureDNS::A,
                CaptureDNS::IN
                )
            );
        msg.add_authority(
            CaptureDNS::resource(
                CaptureDNS::encode_domain_name("net"),
                CaptureDNS::encode_domain_name("a.gtld-servers.net"),
                CaptureDNS::NS,
                CaptureDNS::IN,
                172800)
            );
        msg.add_authority(
            CaptureDNS::resource(
                CaptureDNS::encode_domain_name("net"),
                CaptureDNS::encode_domain_name("b.gtld-servers.net"),
                CaptureDNS::NS,
                CaptureDNS::IN,
                172800)
            );

        THEN("Message is serialised with compressed name")
        {
            std::vector<uint8_t> EXPECTED
                { 0x66,0x92,0x80,0x00,0x00,0x01,0x00,0x00,
                  0x00,0x02,0x00,0x00,0x04,0x73,0x65,0x63,
                  0x32,0x05,0x61,0x70,0x6e,0x69,0x63,0x03,
                  0x6e,0x65,0x74,0x00,0x00,0x01,0x00,0x01,
                  0xc0,0x17,0x00,0x02,0x00,0x01,0x00,0x02,
                  0xa3,0x00,0x00,0x11,0x01,0x61,0x0c,0x67,
                  0x74,0x6c,0x64,0x2d,0x73,0x65,0x72,0x76,
                  0x65,0x72,0x73,0xc0,0x17,0xc0,0x17,0x00,
                  0x02,0x00,0x01,0x00,0x02,0xa3,0x00,0x00,
                  0x04,0x01,0x62,0xc0,0x2e
                };
            uint32_t pkt_size = msg.header_size();
            REQUIRE(pkt_size == EXPECTED.size());

            std::vector<uint8_t> buf(pkt_size);
            msg.write_serialization(buf.data(), pkt_size, nullptr);
            REQUIRE(buf == EXPECTED);
        }
    }
}
