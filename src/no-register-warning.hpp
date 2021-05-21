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
 * \file no-register-warning.hpp
 * \brief The `register` keyword is deprecated in C++11.
 *
 * The logging module can trigger a warning to this effect.
 * Work around this with preprocessor evil.
 */

#ifndef NO_REGISTER_WARNING_HPP
#define NO_REGISTER_WARNING_HPP

#if __cplusplus > 199711L
#define register      // Deprecated in C++11.
#endif

#endif
