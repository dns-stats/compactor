/*
 * Copyright 2016-2018 Internet Corporation for Assigned Names and Numbers.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Developed by Sinodun IT (www.sinodun.com)
 */

#include "catch.hpp"

#include "rotatingfilename.hpp"

class TestRotatingFileName : public RotatingFileName
{
public:
    TestRotatingFileName(const std::string& pattern,
                         const std::chrono::seconds& period)
        : RotatingFileName(pattern, period), exists_after_(0) {}

    unsigned exists_after_;

protected:
    virtual bool fileExists(const std::string&)
    {
        if ( exists_after_ == 0 )
            return false;

        exists_after_--;
        return true;
    }
};


SCENARIO("Rotating file name changes", "[rotation]")
{
    GIVEN("A rotating file name pattern and rotation period")
    {
        TestRotatingFileName rfn("%Y%m%d-%H%M%S.test", std::chrono::seconds(30));
        std::chrono::system_clock::time_point t(std::chrono::hours(24*365*20));
        Configuration config;

        THEN("on creation a rotation is always needed")
        {
            REQUIRE(rfn.need_rotate(t, config));
        }

        AND_THEN("check the right first filename is generated")
        {
            REQUIRE(rfn.filename(t, config) == "19891227-000000.test");
        }

        AND_THEN("check rotation not needed in time period")
        {
            REQUIRE(rfn.filename(t, config) == "19891227-000000.test");
            t += std::chrono::seconds(20);
            REQUIRE(!rfn.need_rotate(t, config));
        }
        AND_THEN("check rotation is needed in time period if forced")
        {
            REQUIRE(rfn.filename(t, config) == "19891227-000000.test");
            t += std::chrono::seconds(20);
            REQUIRE(rfn.need_rotate(t, config, true));
        }

        AND_THEN("check rotation is needed after time period")
        {
            REQUIRE(rfn.filename(t, config) == "19891227-000000.test");
            t += std::chrono::seconds(30);
            REQUIRE(rfn.need_rotate(t, config));
        }

        AND_THEN("check filename after time period")
        {
            REQUIRE(rfn.filename(t, config) == "19891227-000000.test");
            t += std::chrono::seconds(30);
            REQUIRE(rfn.need_rotate(t, config));
            REQUIRE(rfn.filename(t, config) == "19891227-000030.test");
        }

        AND_THEN("check right filename is generated if files exist")
        {
            REQUIRE(rfn.filename(t, config) == "19891227-000000.test");

            rfn.exists_after_ = 1;
            REQUIRE(rfn.filename(t, config) == "19891227-000000.test-1");
            rfn.exists_after_ = 2;
            REQUIRE(rfn.filename(t, config) == "19891227-000000.test-2");
            rfn.exists_after_ = 10;
            REQUIRE(rfn.filename(t, config) == "19891227-000000.test-10");
        }
    }

    GIVEN("A rotating file name pattern and rotation period, where filename pattern does not change in one period")
    {
        TestRotatingFileName rfn("%Y%m%d-%H%M.test", std::chrono::seconds(30));
        std::chrono::system_clock::time_point t(std::chrono::hours(24*365*20));
        Configuration config;

        THEN("on creation a rotation is always needed")
        {
            REQUIRE(rfn.need_rotate(t, config));
        }

        AND_THEN("check the right first filename is generated")
        {
            REQUIRE(rfn.filename(t, config) == "19891227-0000.test");
        }

        AND_THEN("check rotation not needed in time period")
        {
            REQUIRE(rfn.filename(t, config) == "19891227-0000.test");
            t += std::chrono::seconds(20);
            REQUIRE(!rfn.need_rotate(t, config));
        }

        AND_THEN("check rotation not needed after one time period")
        {
            REQUIRE(rfn.filename(t, config) == "19891227-0000.test");
            t += std::chrono::seconds(40);
            REQUIRE(!rfn.need_rotate(t, config));
        }

        AND_THEN("check rotation is needed after two time periods")
        {
            REQUIRE(rfn.filename(t, config) == "19891227-0000.test");
            t += std::chrono::seconds(70);
            REQUIRE(rfn.need_rotate(t, config));
        }

        AND_THEN("check filename after two time periods")
        {
            REQUIRE(rfn.filename(t, config) == "19891227-0000.test");
            t += std::chrono::seconds(70);
            REQUIRE(rfn.need_rotate(t, config));
            REQUIRE(rfn.filename(t, config) == "19891227-0001.test");
        }
    }

    GIVEN("A rotating file name pattern and rotation period")
    {
        TestRotatingFileName rfn("%Y%m%d-%H%M%S_%{interface}_%{rotate-period}_%{snaplen}_%{query-timeout}_%{skew-timeout}_%{promiscuous-mode}.test", std::chrono::seconds(30));
        std::chrono::system_clock::time_point t(std::chrono::hours(24*365*20));
        Configuration config;
        config.network_interfaces = { "interface0" };
        config.rotation_period = 300;
        config.snaplen = 65;
        config.query_timeout = 10;
        config.skew_timeout = 20;
        config.promisc_mode = true;

        THEN("check the right filename is generated")
        {
            REQUIRE(rfn.filename(t, config) == "19891227-000000_interface0_300_65_10_20_1.test");
        }

        AND_THEN("config is changed and right filename still generated after time period")
        {
            config.promisc_mode = false;
            t += std::chrono::seconds(40);
            REQUIRE(rfn.filename(t, config) == "19891227-000040_interface0_300_65_10_20_0.test");
        }
    }
}
