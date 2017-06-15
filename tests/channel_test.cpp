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

#include <string>

#include "catch.hpp"
#include "channel.hpp"

SCENARIO("Channels can have data added, removed and closed", "[channel]")
{
    GIVEN("String and integer channels")
    {
        Channel<std::string> str_chan;
        Channel<int> int_chan;

        WHEN("channels are created")
        {
            THEN("the channels are open")
            {
                REQUIRE(!str_chan.is_closed());
                REQUIRE(!int_chan.is_closed());
            }
        }

        WHEN("data is sent down channels")
        {
            THEN("data is received")
            {
                REQUIRE(str_chan.put("hello"));
                REQUIRE(str_chan.put("world"));
                REQUIRE(int_chan.put(100));
                REQUIRE(int_chan.put(200));

                std::string s;
                int i;

                REQUIRE(str_chan.get(s));
                REQUIRE(s == "hello");
                REQUIRE(str_chan.get(s));
                REQUIRE(s == "world");
                REQUIRE(int_chan.get(i));
                REQUIRE(i == 100);
                REQUIRE(int_chan.get(i));
                REQUIRE(i == 200);
            }
        }

        WHEN("channels are empty")
        {
            THEN("non-wait get() return false")
            {
                std::string s;
                int i;

                REQUIRE(!str_chan.get(s, false));
                REQUIRE(!int_chan.get(i, false));
            }
        }

        WHEN("channels are closed")
        {
            THEN("the channels are closed")
            {
                std::string s;
                int i;

                str_chan.close();
                int_chan.close();

                REQUIRE(str_chan.is_closed());
                REQUIRE(int_chan.is_closed());
                REQUIRE(!str_chan.get(s));
                REQUIRE(!int_chan.get(i));
            }
        }
    }

    GIVEN("Integer channel of limited capacity")
    {
        Channel<int> int_chan(5);

        WHEN("data is sent down the channel")
        {
            THEN("channel reports it is full")
            {
                REQUIRE(int_chan.put(1, false));
                REQUIRE(int_chan.put(2, false));
                REQUIRE(int_chan.put(3, false));
                REQUIRE(int_chan.put(4, false));
                REQUIRE(int_chan.put(5, false));
                REQUIRE(!int_chan.put(6, false));
                REQUIRE(!int_chan.put(7, false));
            }
        }
    }
}
