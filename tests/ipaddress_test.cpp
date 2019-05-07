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

#include <sstream>

#include "catch.hpp"
#include "ipaddress.hpp"

SCENARIO("IPAddress wrapper for v4 and v6 addresses does the right thing",
         "[ipaddress]")
{
    GIVEN("Some sample IP addresses")
    {
        Tins::IPv4Address a4("193.0.29.226");
        Tins::IPv6Address a6("2001:67c:64:42:bdcd:34ce:2801:9686");

        WHEN("IPv4 is used")
        {
            IPAddress a(a4);

            THEN("the address and data are correct for IPv4")
            {
                REQUIRE(!a.is_ipv6());

                byte_string a_bin = a.asNetworkBinary();

                REQUIRE(a_bin.size() == 4);
                REQUIRE(a_bin[0] == 193);
                REQUIRE(a_bin[1] == 0);
                REQUIRE(a_bin[2] == 29);
                REQUIRE(a_bin[3] == 226);

                REQUIRE(a.str() == "193.0.29.226");

                std::ostringstream oss;
                oss << a;
                REQUIRE(oss.str() == "193.0.29.226");
            }

            AND_THEN("the network binary export can be re-imported")
            {
                byte_string a_bin = a.asNetworkBinary();
                IPAddress a2(a_bin);
                REQUIRE(a == a2);
            }

            AND_THEN("the IPv6 representation is correct")
            {
                Tins::IPv6Address a4_a6 = a;

                std::ostringstream oss;
                oss << a4_a6;
                REQUIRE(oss.str() == "::ffff:193.0.29.226");
            }
        }

        WHEN("IPv6 is used")
        {
            IPAddress a(a6);

            THEN("the address and data are correct for IPv6")
            {
                REQUIRE(a.is_ipv6());

                byte_string a_bin = a.asNetworkBinary();

                REQUIRE(a_bin.size() == 16);
                REQUIRE((a_bin[0] << 8 | a_bin[1]) == 0x2001);
                REQUIRE((a_bin[2] << 8 | a_bin[3]) == 0x067c);
                REQUIRE((a_bin[4] << 8 | a_bin[5]) == 0x0064);
                REQUIRE((a_bin[6] << 8 | a_bin[7]) == 0x0042);
                REQUIRE((a_bin[8] << 8 | a_bin[9]) == 0xbdcd);
                REQUIRE((a_bin[10] << 8 | a_bin[11]) == 0x34ce);
                REQUIRE((a_bin[12] << 8 | a_bin[13]) == 0x2801);
                REQUIRE((a_bin[14] << 8 | a_bin[15]) == 0x9686);

                REQUIRE(a.str() == "2001:67c:64:42:bdcd:34ce:2801:9686");

                std::ostringstream oss;
                oss << a;
                REQUIRE(oss.str() == "2001:67c:64:42:bdcd:34ce:2801:9686");
            }

            AND_THEN("the network binary export can be re-imported")
            {
                byte_string a_bin = a.asNetworkBinary();
                IPAddress a2(a_bin);
                REQUIRE(a == a2);
            }
        }
    }
}

SCENARIO("IPAddress string constructor does the right thing",
         "[ipaddress]")
{
    GIVEN("Some sample IP addresses")
    {
        IPAddress a4("193.0.29.226");
        IPAddress a6("2001:67c:64:42:bdcd:34ce:2801:9686");

        WHEN("IPv4 is used")
        {
            THEN("the address and data are correct for IPv4")
            {
                REQUIRE(!a4.is_ipv6());

                byte_string a_bin = a4.asNetworkBinary();

                REQUIRE(a_bin.size() == 4);
                REQUIRE(a_bin[0] == 193);
                REQUIRE(a_bin[1] == 0);
                REQUIRE(a_bin[2] == 29);
                REQUIRE(a_bin[3] == 226);
            }
        }

        WHEN("IPv6 is used")
        {
            THEN("the address and data are correct for IPv6")
            {
                REQUIRE(a6.is_ipv6());

                byte_string a_bin = a6.asNetworkBinary();

                REQUIRE(a_bin.size() == 16);
                REQUIRE((a_bin[0] << 8 | a_bin[1]) == 0x2001);
                REQUIRE((a_bin[2] << 8 | a_bin[3]) == 0x067c);
                REQUIRE((a_bin[4] << 8 | a_bin[5]) == 0x0064);
                REQUIRE((a_bin[6] << 8 | a_bin[7]) == 0x0042);
                REQUIRE((a_bin[8] << 8 | a_bin[9]) == 0xbdcd);
                REQUIRE((a_bin[10] << 8 | a_bin[11]) == 0x34ce);
                REQUIRE((a_bin[12] << 8 | a_bin[13]) == 0x2801);
                REQUIRE((a_bin[14] << 8 | a_bin[15]) == 0x9686);
            }
        }
    }

    GIVEN("Some bad sample IP addresse")
    {
        WHEN("they are given to IPAddress constructor")
        {
            THEN("it throws")
            {
                REQUIRE_THROWS_AS(IPAddress("192.168.1.xx"), Tins::invalid_address);
                REQUIRE_THROWS_AS(IPAddress("xyzzy"), Tins::invalid_address);
                REQUIRE_THROWS_AS(IPAddress("2001:67c:64::42::0"), Tins::invalid_address);
                REQUIRE_THROWS_AS(IPAddress("2001:67c:64::42:fred"), Tins::invalid_address);
            }
        }
    }
}
