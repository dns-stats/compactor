/*
 * Copyright 2021 Internet Corporation for Assigned Names and Numbers.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Developed by Sinodun IT (www.sinodun.com)
 */

#include <cstdio>

#include "parallelwriter.hpp"

template<>
void ParallelWriterPool<StreamWriter>::compressFile(const std::string& input, const std::string& output)
{
    if ( std::rename(input.c_str(), output.c_str()) != 0 )
        throw std::runtime_error("Can't rename " + input + " to " + output);
}
