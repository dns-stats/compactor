/*
 * Copyright 2016-2017, 2021 Internet Corporation for Assigned Names and Numbers.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Developed by Sinodun IT (www.sinodun.com)
 */

/**
 * \file log.hpp
 * \brief Application logging interface.
 */

#ifndef LOG_HPP
#define LOG_HPP

#include "no-register-warning.hpp"
#include <boost/log/trivial.hpp>

#define LOG_ERROR       BOOST_LOG_TRIVIAL(error)
#define LOG_WARN        BOOST_LOG_TRIVIAL(warning)
#define LOG_INFO        BOOST_LOG_TRIVIAL(info)

void init_logging();

#endif
