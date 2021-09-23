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

#define BOOST_LOG_USE_NATIVE_SYSLOG 1

#include "no-register-warning.hpp"
#include <boost/shared_ptr.hpp>
#include <boost/make_shared.hpp>
#include <boost/log/sinks/sync_frontend.hpp>
#include <boost/log/sinks/syslog_backend.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>
#include <boost/variant.hpp>

#include "log.hpp"

namespace logging = boost::log;
namespace src = boost::log::sources;
namespace sinks = boost::log::sinks;
namespace keywords = boost::log::keywords;
namespace expr = boost::log::expressions;

// #ifdef __APPLE__
// void init_logging() {}
// #else
void init_logging()
{
    using sink_t = sinks::synchronous_sink<sinks::syslog_backend>;

    auto core = logging::core::get();

    // Create a backend
    boost::shared_ptr<sinks::syslog_backend> backend(
        new sinks::syslog_backend(
            keywords::facility = sinks::syslog::user,
            keywords::use_impl = sinks::syslog::native
            ));

    // Set the straightforward level translator for the "Severity" attribute of type int
    backend->set_severity_mapper(sinks::syslog::direct_severity_mapping<int>("Severity"));

    boost::shared_ptr< sink_t > frontend(new sink_t(backend));

    // This makes the sink to write log records that look like this:
    // 1: [info] An info severity message
    // 2: [error] An error severity message
    frontend->set_formatter
    (
        expr::format("[%1%] %2%")
            % logging::trivial::severity
            % expr::smessage
     );

    // Wrap it into the frontend and register in the core.
    // The backend requires synchronization in the frontend.
    core->add_sink(frontend);
 
}
//#endif
