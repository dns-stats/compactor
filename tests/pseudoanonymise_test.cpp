/*
 * Copyright 2018-2019 Internet Corporation for Assigned Names and Numbers.
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

#include "pseudoanonymise.hpp"

SCENARIO("Pseudo-Anonymising IP addresses", "[pseudoanonymise]")
{
    GIVEN("ipcipher phrase and salt")
    {
        THEN("Derived keys match")
        {
            std::vector<std::pair<std::string, byte_string>> TESTS
            {
                { "", "\xbb\x8d\xcd\x7b\xe9\xa6\xf4\x3b\x33\x04\xc6\x40\xd7\xd7\x10\x3c"_b },
                { "3.141592653589793", "\x37\x05\xbd\x6c\x0e\x26\xa1\xa8\x39\x89\x8f\x1f\xa0\x16\xa3\x74"_b },
                { "crypto is not a coin", "\x06\xc4\xba\xd2\x3a\x38\xb9\xe0\xad\x9d\x05\x90\xb0\xa3\xd9\x3a"_b },

            };

            for (auto t : TESTS)
            {
                CHECK(t.second == PseudoAnonymise::generate_key(t.first.c_str(), "ipcipheripcipher"));
            }
        }
    }

    GIVEN("Pseudo-Anonymising engine with key and ipcipher test vector")
    {
        PseudoAnonymise anon("some 16-byte key"_b);

        THEN("Addresses map to expected values")
        {
            std::vector<std::pair<std::string, std::string>> TESTS
            {
                { "::1", "3718:8853:1723:6c88:7e5f:2e60:c79a:2bf" },
                { "2001:503:ba3e::2:30", "64d2:883d:ffb5:dd79:24b:943c:22aa:4ae7" },
                { "2001:DB8::", "ce7e:7e39:d282:e7b1:1d6d:5ca1:d4de:246f" },
            };

            for (auto t : TESTS)
            {
                IPAddress out = anon.address(IPAddress(t.first));
                IPAddress exp(t.second);

                CHECK(exp == out);
            }
        }
    }

    GIVEN("Pseudo-Anonymising engine with ipcipher test vector phrase and salt")
    {
        PseudoAnonymise anon("crypto is not a coin", "ipcipheripcipher");

        THEN("Addresses map to expected values")
        {
            std::vector<std::pair<std::string, std::string>> TESTS
            {
                { "::1", "a551:9cb0:c9b:f6e1:6112:58a:af29:3a6c" },
                { "2001:503:ba3e::2:30", "6e60:2674:2fac:d383:f9d5:dcfe:fc53:328e" },
                { "2001:DB8::", "a8f5:16c8:e2ea:23b9:748d:67a2:4107:9d2e" },
            };

            for (auto t : TESTS)
            {
                IPAddress out = anon.address(IPAddress(t.first));
                IPAddress exp(t.second);

                CHECK(exp == out);
            }
        }
    }

    GIVEN("Pseudo-Anonymising engine with key and IPv4 test vector")
    {
        PseudoAnonymise anon("some 16-byte key"_b);

        THEN("Addresses map to expected values")
        {
            std::vector<std::pair<std::string, std::string>> TESTS
            {
                { "127.0.0.1", "211.226.57.195" },
                { "192.168.0.1", "19.85.103.53" },
                { "10.0.0.1", "115.233.85.39" },
                { "8.8.8.8", "38.134.79.111" },
                { "8.8.4.4", "193.102.237.172" },
                { "8.8.8.0", "71.43.186.141" },
            };

            for (auto t : TESTS)
            {
                IPAddress out = anon.address(IPAddress(t.first));
                IPAddress exp(t.second);

                CHECK(exp == out);
            }
        }
    }
}

SCENARIO("Pseudo-Anonymising OPT RDATA", "[pseudoanonymise]")
{
    GIVEN("OPT RDATA with ECS option")
    {
        PseudoAnonymise anon("some 16-byte key"_b);

        THEN("Addresses map to expected values")
        {
            std::vector<std::pair<byte_string, byte_string>> TESTS
            {
                { "\x00\x08\x00\x08\x00\x01\x20\x00\x08\x08\x08\x08"_b,
                  "\x00\x08\x00\x08\x00\x01\x20\x00\x26\x86\x4f\x6f"_b },
                { "\x00\x08\x00\x07\x00\x01\x18\x00\x08\x08\x08"_b,
                  "\x00\x08\x00\x07\x00\x01\x18\x00\x47\x2b\xba"_b },
                { "\x00\x08\x00\x08\x00\x01\x19\x00\x08\x08\x08\x7f"_b,
                  "\x00\x08\x00\x08\x00\x01\x19\x00\x47\x2b\xba\x80"_b },
                { "\x00\x08\x00\x08\x00\x01\x1a\x00\x08\x08\x08\x3f"_b,
                  "\x00\x08\x00\x08\x00\x01\x1a\x00\x47\x2b\xba\x80"_b },
                { "\x00\x08\x00\x08\x00\x01\x1b\x00\x08\x08\x08\x1f"_b,
                  "\x00\x08\x00\x08\x00\x01\x1b\x00\x47\x2b\xba\x80"_b },
                { "\x00\x08\x00\x08\x00\x01\x1c\x00\x08\x08\x08\xaf"_b,
                  "\x00\x08\x00\x08\x00\x01\x1c\x00\xfa\xd5\x52\xe0"_b },
            };

            for (auto t : TESTS)
            {
                byte_string out = anon.edns0(t.first);
                CHECK(out == t.second);
            }
        }
    }
}
