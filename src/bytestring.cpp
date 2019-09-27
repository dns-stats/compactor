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

#include "bytestring.hpp"

byte_string operator "" _b(const char* s, std::size_t len)
{
    return byte_string(reinterpret_cast<const unsigned char*>(s), len);
}

byte_string to_byte_string(const std::string& s)
{
    return byte_string(reinterpret_cast<const unsigned char *>(s.data()), s.size());
}

std::string to_string(const byte_string& b)
{
    return std::string(reinterpret_cast<const char *>(b.data()), b.size());
}
