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

#include "cbordecoder.hpp"

namespace {
    class TestCborDecoder : public CborBaseDecoder
    {
    public:
        TestCborDecoder()
            : CborBaseDecoder() {}

        TestCborDecoder(const std::vector<uint8_t>& bytes)
            : CborBaseDecoder(), bytes_(bytes) {}

        void set_bytes(const std::vector<uint8_t>& bytes)
        {
            bytes_ = bytes;
        }

    protected:
        virtual unsigned readBytes(uint8_t* p, std::ptrdiff_t n_bytes)
        {
            if ( bytes_.empty() )
                throw cbor_end_of_input();

            // Return input a bit at a time to test the refill logic.
            int res = bytes_.size() / 2;
            if ( res == 0 && !bytes_.empty() )
                res = 1;
            if ( res > n_bytes )
                res = n_bytes;
            for ( int i = 0; i < res; ++i )
                *p++ = bytes_[i];
            bytes_.erase(bytes_.begin(), bytes_.begin() + res);
            return res;
        }

    private:
        std::vector<uint8_t> bytes_;
    };
}

SCENARIO("Check CBOR decoder decodes correct basic values", "[cbor]")
{
    GIVEN("A test CBOR decoder")
    {
        TestCborDecoder tcbd;

        WHEN("unsigned numeric values are decoded")
        {
            const std::vector<uint8_t> INPUT =
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
            tcbd.set_bytes(INPUT);

            THEN("decoder output is correct")
            {
                REQUIRE(tcbd.type() == CborBaseDecoder::TYPE_UNSIGNED);
                REQUIRE(tcbd.read_unsigned() == 23u);
                REQUIRE(tcbd.type() == CborBaseDecoder::TYPE_UNSIGNED);
                REQUIRE(tcbd.read_unsigned() == 0xffu);
                REQUIRE(tcbd.type() == CborBaseDecoder::TYPE_UNSIGNED);
                REQUIRE(tcbd.read_unsigned() == 0x100u);
                REQUIRE(tcbd.type() == CborBaseDecoder::TYPE_UNSIGNED);
                REQUIRE(tcbd.read_unsigned() == 0xffffu);
                REQUIRE(tcbd.type() == CborBaseDecoder::TYPE_UNSIGNED);
                REQUIRE(tcbd.read_unsigned() == 0x10000u);
                REQUIRE(tcbd.type() == CborBaseDecoder::TYPE_UNSIGNED);
                REQUIRE(tcbd.read_unsigned() == 0xffffffffu);
                REQUIRE(tcbd.type() == CborBaseDecoder::TYPE_UNSIGNED);
                REQUIRE(tcbd.read_unsigned() == 0x100000000ull);
                REQUIRE(tcbd.type() == CborBaseDecoder::TYPE_UNSIGNED);
                REQUIRE(tcbd.read_unsigned() == 0xffffffffffffffffull);
                REQUIRE_THROWS_AS(tcbd.type(), cbor_end_of_input);
            }

            AND_THEN("decoder checks types")
            {
                REQUIRE(tcbd.type() == CborBaseDecoder::TYPE_UNSIGNED);
                REQUIRE_THROWS_AS(tcbd.read_string(), std::logic_error);
            }

            AND_THEN("decoder skips properly")
            {
                for ( int i = 0; i < 8; ++i )
                    tcbd.skip();
                REQUIRE_THROWS_AS(tcbd.type(), cbor_end_of_input);
            }
        }

        WHEN("signed numeric values are decoded")
        {
            const std::vector<uint8_t> INPUT =
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
            tcbd.set_bytes(INPUT);

            THEN("decoder output is correct")
            {
                REQUIRE(tcbd.type() == CborBaseDecoder::TYPE_SIGNED);
                REQUIRE(tcbd.read_signed() == -24);
                REQUIRE(tcbd.type() == CborBaseDecoder::TYPE_SIGNED);
                REQUIRE(tcbd.read_signed() == -256);
                REQUIRE(tcbd.type() == CborBaseDecoder::TYPE_SIGNED);
                REQUIRE(tcbd.read_signed() == -257);
                REQUIRE(tcbd.type() == CborBaseDecoder::TYPE_SIGNED);
                REQUIRE(tcbd.read_signed() == -65536);
                REQUIRE(tcbd.type() == CborBaseDecoder::TYPE_SIGNED);
                REQUIRE(tcbd.read_signed() == -65537);
                REQUIRE(tcbd.type() == CborBaseDecoder::TYPE_SIGNED);
                REQUIRE(tcbd.read_signed() == -4294967296);
                REQUIRE(tcbd.type() == CborBaseDecoder::TYPE_SIGNED);
                REQUIRE(tcbd.read_signed() == -4294967297ll);
                REQUIRE(tcbd.type() == CborBaseDecoder::TYPE_SIGNED);
                REQUIRE(tcbd.read_signed() == -9223372036854775807ll - 1);
                REQUIRE_THROWS_AS(tcbd.type(), cbor_end_of_input);
            }

            AND_THEN("decoder checks types")
            {
                REQUIRE(tcbd.type() == CborBaseDecoder::TYPE_SIGNED);
                REQUIRE_THROWS_AS(tcbd.read_unsigned(), std::logic_error);
            }

            AND_THEN("decoder skips properly")
            {
                for ( int i = 0; i < 8; ++i )
                    tcbd.skip();
                REQUIRE_THROWS_AS(tcbd.type(), cbor_end_of_input);
            }
        }

        WHEN("string values are decoded")
        {
            const std::vector<uint8_t> INPUT =
                {
                    0x60 | 5, 'H', 'e', 'l', 'l', 'o',
                    0x40 | 5, 'H', 'e', 'l', 'l', 'o',
                    0x60 | 24, 34,
                    'A', ' ', 's', 't', 'r', 'i', 'n', 'g', ' ', 'l',
                    'o', 'n', 'g', 'e', 'r', ' ', 't', 'h', 'a', 'n',
                    ' ', '2', '4', ' ', 'c', 'h', 'a', 'r', 'a', 'c',
                    't', 'e', 'r', 's',
                };
            tcbd.set_bytes(INPUT);

            THEN("decoder output is correct")
            {
                REQUIRE(tcbd.type() == CborBaseDecoder::TYPE_STRING);
                REQUIRE(tcbd.read_string() == "Hello");
                REQUIRE(tcbd.type() == CborBaseDecoder::TYPE_BINARY);
                REQUIRE(tcbd.read_binary() == byte_string(reinterpret_cast<const unsigned char*>("Hello")));
                REQUIRE(tcbd.type() == CborBaseDecoder::TYPE_STRING);
                REQUIRE(tcbd.read_string() == "A string longer than 24 characters");
                REQUIRE_THROWS_AS(tcbd.type(), cbor_end_of_input);
            }

            AND_THEN("string decoder checks types")
            {
                REQUIRE(tcbd.type() == CborBaseDecoder::TYPE_STRING);
                REQUIRE_THROWS_AS(tcbd.read_binary(), std::logic_error);
            }

            AND_THEN("binary decoder checks types")
            {
                bool indef;

                REQUIRE(tcbd.type() == CborBaseDecoder::TYPE_STRING);
                tcbd.skip();
                REQUIRE(tcbd.type() == CborBaseDecoder::TYPE_BINARY);
                REQUIRE_THROWS_AS(tcbd.read_unsigned(), std::logic_error);
            }

            AND_THEN("decoder skips properly")
            {
                for ( int i = 0; i < 3; ++i )
                    tcbd.skip();
                REQUIRE_THROWS_AS(tcbd.type(), cbor_end_of_input);
            }
        }

        WHEN("map values are decoded")
        {
            const std::vector<uint8_t> INPUT =
                {
                    (5 << 5) | 1, 0, 1,
                    (5 << 5) | 31, 1, 0, 0xff
                };
            tcbd.set_bytes(INPUT);

            THEN("decoder output is correct")
            {
                bool indef;

                REQUIRE(tcbd.type() == CborBaseDecoder::TYPE_MAP);
                REQUIRE(tcbd.readMapHeader(indef) == 1);
                REQUIRE_FALSE(indef);
                tcbd.skip();
                tcbd.skip();
                REQUIRE(tcbd.type() == CborBaseDecoder::TYPE_MAP);
                tcbd.readMapHeader(indef);
                REQUIRE(indef);
                tcbd.skip();
                tcbd.skip();
                REQUIRE(tcbd.type() == CborBaseDecoder::TYPE_BREAK);
                tcbd.readBreak();
                REQUIRE_THROWS_AS(tcbd.type(), cbor_end_of_input);
            }

            AND_THEN("map decoder checks types")
            {
                REQUIRE(tcbd.type() == CborBaseDecoder::TYPE_MAP);
                REQUIRE_THROWS_AS(tcbd.read_binary(), std::logic_error);
            }

            AND_THEN("decoder skips properly")
            {
                for ( int i = 0; i < 2; ++i )
                    tcbd.skip();
                REQUIRE_THROWS_AS(tcbd.type(), cbor_end_of_input);
            }
        }

        WHEN("time values are decoded")
        {
            const std::vector<uint8_t> INPUT =
                {
                    (4 << 5) | 2, 0, 1,
                    (4 << 5) | 2, 1, 0
                };
            tcbd.set_bytes(INPUT);

            THEN("decoder output is correct")
            {
                std::chrono::system_clock::time_point t;
                REQUIRE(tcbd.type() == CborBaseDecoder::TYPE_ARRAY);
                t = tcbd.read_time();
                REQUIRE(t == std::chrono::system_clock::time_point(std::chrono::microseconds(1)));
                t = tcbd.read_time();
                REQUIRE(t == std::chrono::system_clock::time_point(std::chrono::seconds(1)));
            }

            AND_THEN("time decoder checks types")
            {
                REQUIRE(tcbd.type() == CborBaseDecoder::TYPE_ARRAY);
                REQUIRE_THROWS_AS(tcbd.read_binary(), std::logic_error);
            }

            AND_THEN("decoder skips properly")
            {
                for ( int i = 0; i < 2; ++i )
                    tcbd.skip();
                REQUIRE_THROWS_AS(tcbd.type(), cbor_end_of_input);
            }
        }

        WHEN("other values are decoded")
        {
            const std::vector<uint8_t> INPUT =
                {
                    0x80 | 12,
                    0x80 | 31,
                    0xA0 | 12,
                    0xA0 | 31,
                    0xff,
                };
            tcbd.set_bytes(INPUT);

            THEN("decoder output is correct")
            {
                bool indefLen;
                uint64_t nelems;

                REQUIRE(tcbd.type() == CborBaseDecoder::TYPE_ARRAY);
                nelems = tcbd.readArrayHeader(indefLen);
                REQUIRE_FALSE(indefLen);
                REQUIRE(nelems == 12);
                nelems = tcbd.readArrayHeader(indefLen);
                REQUIRE(indefLen);

                REQUIRE(tcbd.type() == CborBaseDecoder::TYPE_MAP);
                nelems = tcbd.readMapHeader(indefLen);
                REQUIRE_FALSE(indefLen);
                REQUIRE(nelems == 12);
                nelems = tcbd.readMapHeader(indefLen);
                REQUIRE(indefLen);

                REQUIRE(tcbd.type() == CborBaseDecoder::TYPE_BREAK);
                tcbd.readBreak();
            }

            AND_THEN("array decoder checks types")
            {
                REQUIRE(tcbd.type() == CborBaseDecoder::TYPE_ARRAY);
                REQUIRE_THROWS_AS(tcbd.read_binary(), std::logic_error);
            }

            AND_THEN("map decoder checks types")
            {
                bool indef;

                tcbd.readArrayHeader(indef);
                tcbd.readArrayHeader(indef);
                REQUIRE(tcbd.type() == CborBaseDecoder::TYPE_MAP);
                REQUIRE_THROWS_AS(tcbd.read_binary(), std::logic_error);
            }

            AND_THEN("break decoder checks types")
            {
                bool indef;

                tcbd.readArrayHeader(indef);
                tcbd.readArrayHeader(indef);
                tcbd.readMapHeader(indef);
                tcbd.readMapHeader(indef);
                REQUIRE(tcbd.type() == CborBaseDecoder::TYPE_BREAK);
                REQUIRE_THROWS_AS(tcbd.read_binary(), std::logic_error);
            }
        }
    }
}
