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

#include <thread>

#include "config.h"

#ifdef HAVE_PTHREAD
#include <pthread.h>
#ifdef HAVE_PTHREAD_NP_H
#include <pthread_np.h>
#endif
#endif

#include "util.hpp"

void set_thread_name(const char* name)
{
#if HAVE_PTHREAD_SETNAME_NP
  #ifdef __APPLE__
    pthread_setname_np(name);
  #else
    pthread_setname_np(pthread_self(), name);
  #endif
#else
    (void) name;
#endif
}
