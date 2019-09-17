/*
 * Copyright 2019 Internet Corporation for Assigned Names and Numbers.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Developed by Sinodun IT (www.sinodun.com)
 */

#ifndef UTIL_HPP
#define UTIL_HPP

/**
 * \brief Set the name of the current thread.
 *
 * The passed name may be truncated, or this may do
 * nothing, depending on the underlying system.
 *
 * \param name  the name to set.
 */
void set_thread_name(const char* name);

#endif
