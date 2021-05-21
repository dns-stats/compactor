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
 * \file makeunique.hpp
 * \brief Make up for the lack of `std::make_unique` in C++11.
 */

#ifndef MAKEUNIQUE_HPP
#define MAKEUNIQUE_HPP

#include <memory>

// Provide make_unique(), which is either std::make_unique() for
// C++14 or a C++11 filler. See https://herbsutter.com/gotw/_102/.

/**
 * \fn make_unique
 * \brief An equivalent of C++14 `std::make_unique()`.
 *
 * This imports `std::make_unique()` to the current namespace if
 * building on a recent enough compiler, and provides a C++11
 * implementation if not.
 *
 * Requires C++11.
 */
#if __cplusplus <= 201103L
template<class T, class ...Args>
std::unique_ptr<T> make_unique(Args&& ...args)
{
  return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}
#else
  using std::make_unique;
#endif

#endif
