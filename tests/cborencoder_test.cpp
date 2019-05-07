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

#include <vector>

#include "catch.hpp"

#include "cborencoder.hpp"

namespace {
    class TestCborEncoder : public CborBaseEncoder
    {
    public:
        TestCborEncoder() : CborBaseEncoder() {}

        void clear()
        {
            bytes.clear();
        }

        bool compareBytes(const uint8_t *buf, std::size_t buflen)
        {
            if ( buflen != bytes.size() )
                return false;

            for ( auto b : bytes )
                if ( b != *buf++ )
                    return false;

            return true;
        }

    protected:
        virtual void writeBytes(const uint8_t *p, std::ptrdiff_t nBytes)
        {
            while ( nBytes-- > 0 )
                bytes.push_back(*p++);
        }

    private:
        std::vector<uint8_t> bytes;
    };
}

SCENARIO("Check CBOR encoder encodes correct basic values", "[cbor]")
{
    GIVEN("A test CBOR encoder")
    {
        TestCborEncoder tcbe;

        WHEN("unsigned numeric values are encoded")
        {
            tcbe.write(23u);
            tcbe.write(0xffu);
            tcbe.write(0x100u);
            tcbe.write(0xffffu);
            tcbe.write(0x10000u);
            tcbe.write(0xffffffffu);
            tcbe.write(0x100000000ull);
            tcbe.write(0xffffffffffffffffull);
            tcbe.flush();

            THEN("encoder output is correct")
            {
                const uint8_t EXPECTED[] =
                    {
                        23,
                        24, 0xff,
                        25, 1, 0,
                        25, 0xff, 0xff,
                        26, 0, 1, 0, 0,
                        26, 0xff, 0xff, 0xff, 0xff,
                        27, 0, 0, 0, 1, 0, 0, 0, 0,
                        27, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    };

                REQUIRE(tcbe.compareBytes(EXPECTED, sizeof(EXPECTED)));
            }
        }

        WHEN("signed numeric values are encoded")
        {
            tcbe.write(-24);
            tcbe.write(-256);
            tcbe.write(-257);
            tcbe.write(-65536);
            tcbe.write(-65537);
            tcbe.write(-4294967296);
            tcbe.write(-4294967297ll);
            tcbe.write(-9223372036854775807ll - 1);
            tcbe.flush();

            THEN("encoder output is correct")
            {
                const uint8_t EXPECTED[] =
                    {
                        0x20 | 23,
                        0x20 | 24, 0xff,
                        0x20 | 25, 1, 0,
                        0x20 | 25, 0xff, 0xff,
                        0x20 | 26, 0, 1, 0, 0,
                        0x20 | 26, 0xff, 0xff, 0xff, 0xff,
                        0x20 | 27, 0, 0, 0, 1, 0, 0, 0, 0,
                        0x20 | 27, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    };

                REQUIRE(tcbe.compareBytes(EXPECTED, sizeof(EXPECTED)));
            }
        }

        WHEN("boolean values are encoded")
        {
            tcbe.write(false);
            tcbe.write(true);
            tcbe.flush();

            THEN("encoder output is correct")
            {
                const uint8_t EXPECTED[] =
                    {
                        0xE0 | 20,
                        0xE0 | 21
                    };

                REQUIRE(tcbe.compareBytes(EXPECTED, sizeof(EXPECTED)));
            }
        }

        WHEN("strings are encoded")
        {
            tcbe.write("Hello");
            tcbe.write("Hello", false);
            tcbe.write("A string longer than 24 characters");
            tcbe.flush();

            THEN("encoder output is as expected")
            {
                const uint8_t EXPECTED[] =
                    {
                        0x60 | 5, 'H', 'e', 'l', 'l', 'o',
                        0x40 | 5, 'H', 'e', 'l', 'l', 'o',
                        0x60 | 24, 34,
                        'A', ' ', 's', 't', 'r', 'i', 'n', 'g', ' ', 'l',
                        'o', 'n', 'g', 'e', 'r', ' ', 't', 'h', 'a', 'n',
                        ' ', '2', '4', ' ', 'c', 'h', 'a', 'r', 'a', 'c',
                        't', 'e', 'r', 's',
                    };

                REQUIRE(tcbe.compareBytes(EXPECTED, sizeof(EXPECTED)));
            }
        }

        WHEN("time values are encoded")
        {
            tcbe.write(std::chrono::system_clock::time_point(std::chrono::microseconds(1)));
            tcbe.write(std::chrono::system_clock::time_point(std::chrono::seconds(1)));
            tcbe.flush();

            THEN("encoder output is correct")
            {
                const uint8_t EXPECTED[] =
                    {
                        (4 << 5) | 2, 0, 1,
                        (4 << 5) | 2, 1, 0
                    };

                REQUIRE(tcbe.compareBytes(EXPECTED, sizeof(EXPECTED)));
            }
        }

        WHEN("other values are encoded")
        {
            tcbe.writeArrayHeader(12);
            tcbe.writeArrayHeader();
            tcbe.writeMapHeader(12);
            tcbe.writeMapHeader();
            tcbe.writeBreak();
            tcbe.flush();

            THEN("encoder output is correct")
            {
                const uint8_t EXPECTED[] =
                    {
                        0x80 | 12,
                        0x80 | 31,
                        0xA0 | 12,
                        0xA0 | 31,
                        0xff,
                    };

                REQUIRE(tcbe.compareBytes(EXPECTED, sizeof(EXPECTED)));
            }
        }
    }
}
