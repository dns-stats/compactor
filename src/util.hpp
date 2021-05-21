/*
 * Copyright 2019, 2021 Internet Corporation for Assigned Names and Numbers.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Developed by Sinodun IT (www.sinodun.com)
 */

/**
 * \file util.hpp
 * \brief Miscellaneous utility functions.
 */

#ifndef UTIL_HPP
#define UTIL_HPP

#include <chrono>
#include <string>

#include <tins/tins.h>

/**
 * \brief Set file ownership and write permissions.
 *
 * Attempts to set the owning user and group, and the write
 * permissions. If any parameter is empty, don't set
 * that particular item.
 *
 * \param path  the file path.
 * \param owner the owning username.
 * \param group the owning group.
 * \param write "owner", "group" or "all".
 * \throws on error.
 */
void set_file_owner_perms(const std::string& path,
                          const std::string& owner,
                          const std::string& group,
                          const std::string& write);

/**
 * \brief Set the name of the current thread.
 *
 * The passed name may be truncated, or this may do
 * nothing, depending on the underlying system.
 *
 * \param name  the name to set.
 */
void set_thread_name(const char* name);

/**
 * \brief Convert a standard C++ time point to a Tins::Timestamp.
 *
 * \param t     timestamp to convert.
 * \returns timestamp in Tins form.
 */
Tins::Timestamp tsToTins(const std::chrono::system_clock::time_point& t);

#endif
