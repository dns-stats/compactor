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

#ifndef ROTATINGFILENAME_HPP
#define ROTATINGFILENAME_HPP

#include <chrono>
#include <ctime>
#include <string>

#include <boost/filesystem.hpp>

#include "configuration.hpp"

/**
 * \class RotatingFileName
 * \brief A filename that includes time-dependent components and is
 *        periodically changed.
 *
 * An output filename pattern. The pattern may contain elements that
 * refer to configuration items and also items are expanded to a
 * date/time value using `strftime`. Configuration items are specified
 * with %{configname}.
 *
 * Every rotation period, the file should be closed, the filename
 * regenerated, and the file reopened.
 */
class RotatingFileName
{
public:
    /**
     * \brief Constructor.
     *
     * \param pattern the filename pattern.
     * \param period  the rotation period.
     */
    RotatingFileName(const std::string& pattern,
                     const std::chrono::seconds& period)
        : period_(period), pattern_(pattern)
    {
    }

    /**
     * \brief Is a file rotation is needed?
     *
     * If the rotation period has expired, a rotation is needed if the
     * filename generated from the pattern has changed. If the filename
     * has not changed, allow another rotation period to elapse before
     * checking again.
     *
     * \param t      the new time point.
     * \param config the current configuration.
     * \returns `true` if a file rotation is required.
     */
    bool need_rotate(const std::chrono::system_clock::time_point& t,
                     const Configuration& config);

    /**
     * \brief Generate the filename with time/date items at the specified time.
     *
     * The pattern is expanded using `strftime`. This, unfortunately, uses
     * a fixed buffer, so specify a buffer of a slightly arbitary length of
     * 4k. This is only slightly arbitary. It's longer that the traditional
     * Windows 260 character limit and should also cope with the various
     * MAX_PATH_LENGTH specifications for sundry Unixes.
     *
     * If a file with the generated name already exists, then append '-1'
     * to the name and try again. If that exists, use '-2' etc. until a
     * name is found that doesn't exist.
     *
     * \param t      the time point for time/date items in the filename pattern.
     * \param config the current configuration.
     * \returns string with the expanded filename.
     */
    std::string filename(const std::chrono::system_clock::time_point& t,
                         const Configuration& config);

protected:
    /**
     * \brief Report if a filename exists.
     *
     * Check whether a filename exists. This is a testing hook.
     *
     * \param fname the filename.
     * \returns `true` if the filename exists.
     */
    virtual bool fileExists(const std::string& fname);

    /**
     * \brief Generate the base filename from the pattern.
     *
     * \param t      the time point for time/date items in the filename pattern.
     * \param config the current configuration for config items in the filename pattern.
     * \returns string with the expanded filename.
     */
    virtual std::string baseFilename(const std::chrono::system_clock::time_point& t,
                                     const Configuration& config);

private:
    /**
     * \brief time for the next rotation check.
     */
    std::chrono::system_clock::time_point next_rot_;

    /**
     * \brief the rotation period.
     */
    std::chrono::seconds period_;

    /**
     * \brief the filename pattern.
     */
    std::string pattern_;

    /**
     * \brief the current filename base (i.e. pattern expansion).
     */
    std::string filename_base_;
};

#endif
