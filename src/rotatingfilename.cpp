/*
 * Copyright 2016-2019, 2021 Internet Corporation for Assigned Names and Numbers.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Developed by Sinodun IT (www.sinodun.com)
 */

#include <sstream>

#include <boost/filesystem.hpp>

#include "rotatingfilename.hpp"

namespace {
    /**
     * \brief Replace all instances of %{<key>} in pattern with value.
     *
     * \param pattern filename pattern.
     * \param key     item to replace.
     * \param value   value to replace it with.
     * \returns pattern with replacements performed.
     */
    template<typename ValT>
    std::string replace_config(const std::string& pattern,
                               const std::string& key,
                               const ValT& value)
    {
        std::string key_pattern = "%{" + key + "}";
        std::ostringstream oss;
        std::string::size_type start = 0;
        for (;;)
        {
            std::string::size_type pos = pattern.find(key_pattern, start);
            if ( pos == std::string::npos && start == 0 )
                return pattern;     // Not found at all.

            // Write from start to found item.
            oss << pattern.substr(start, pos);

            // If we didn't find, we're done.
            if ( pos == std::string::npos )
                return oss.str();

            oss << value;

            // Move start to past the find and go round for more.
            start = pos + key_pattern.length();
        }
    }
}

bool RotatingFileName::need_rotate(const std::chrono::system_clock::time_point& t,
                                   const Configuration& config)
{
    if ( t < next_check_ )
        return false;

    if ( t >= next_rot_ )
    {
        // Generate new base filename and see if it's changed.
        std::string new_base = baseFilename(t, config);
        if ( new_base == filename_base_ )
        {
            // A rotation is required, but not possible because the
            // base is unchanged. Don't check for another second.
            next_check_ = t + std::chrono::seconds(1);
            return false;
        }
        return true;
    }
    return false;
}

std::string RotatingFileName::filename(const std::chrono::system_clock::time_point& t,
                                       const Configuration& config)
{
    filename_base_ = baseFilename(t, config);
    int count = 0;

    next_rot_ = t + period_;

    for(;;)
    {
        std::ostringstream oss;
        oss << filename_base_;
        if ( count > 0 )
            oss << "-" << count;
        if ( !fileExists(oss.str()) )
            return oss.str();
        count++;
    }
}

bool RotatingFileName::fileExists(const std::string& fname)
{
    return ( boost::filesystem::exists(fname) );
}

std::string RotatingFileName::baseFilename(const std::chrono::system_clock::time_point& t,
                                           const Configuration& config)
{
    std::string sft_pattern = pattern_;
    if ( !config.network_interfaces.empty() )
    {
        std::string all_if;
        for ( unsigned i = 0; i < config.network_interfaces.size(); ++i )
        {
            std::ostringstream oss;
            oss << "interface" << i + 1;
            sft_pattern = replace_config(sft_pattern, oss.str(), config.network_interfaces[i]);

            if ( i > 0 )
                all_if.append("-");
            all_if.append(config.network_interfaces[i]);
        }
        sft_pattern = replace_config(sft_pattern, "interface", all_if);
    }
#if ENABLE_DNSTAP
    else if ( !config.dnstap_socket.empty() )
        sft_pattern = replace_config(sft_pattern, "interface", "dnstap");
#endif
    sft_pattern = replace_config(sft_pattern, "rotate-period", config.rotation_period.count());
    sft_pattern = replace_config(sft_pattern, "snaplen", config.snaplen);
    sft_pattern = replace_config(sft_pattern, "query-timeout", config.query_timeout.count() / 1000.0);
    sft_pattern = replace_config(sft_pattern, "skew-timeout", config.skew_timeout.count());
    sft_pattern = replace_config(sft_pattern, "promiscuous-mode", config.promisc_mode);
    if ( !config.vlan_ids.empty() )
    {
        std::ostringstream all_vlan;
        for ( unsigned i = 0; i < config.vlan_ids.size(); ++i )
        {
            std::ostringstream oss;
            oss << "vlan-id" << i + 1;
            sft_pattern = replace_config(sft_pattern, oss.str(), config.vlan_ids[i]);

            if ( i > 0 )
                all_vlan << "-";
            all_vlan << config.vlan_ids[i];
        }
        sft_pattern = replace_config(sft_pattern, "vlan-id", all_vlan.str());
    }

    char buf[4096];
    std::time_t tt = std::chrono::system_clock::to_time_t(t);
    std::tm tm = *std::gmtime(&tt);
    std::strftime(buf, sizeof(buf), sft_pattern.c_str(), &tm);
    return buf;
}
