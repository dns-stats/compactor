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

#ifndef BYTESTRING_HPP
#define BYTESTRING_HPP

#include <string>

/**
 * \typedef byte_string
 * \brief A string of unsigned char.
 */
using byte_string = std::basic_string<unsigned char>;

/**
 * \brief A byte string literal
 */
byte_string operator "" _b(const char* s, std::size_t len);

/**
 * \brief Convert string to a byte_string.
 */
byte_string to_byte_string(const std::string& s);

/**
 * \brief Convert byte_string to string.
 */
std::string to_string(const byte_string& b);

#endif
