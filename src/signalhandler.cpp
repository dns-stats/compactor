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

#include <atomic>
#include <csignal>
#include <cstring>
#include <mutex>
#include <set>
#include <string>
#include <thread>

#include <sched.h>

#include "log.hpp"
#include "util.hpp"

#include "signalhandler.hpp"

/**
 * \brief the range of signal numbers.
 */
const int FIRST_SIGNAL = 1;
const int LAST_SIGNAL = 31;

namespace {
    /**
     * \brief the set of handlers we're servicing.
     *
     * Untested with >1 handler.
     */
    std::set<SignalHandler*> handlers;

    /**
     * \brief mutex protecting the set of handlers.
     */
    std::recursive_mutex handler_mutex;
    /**
     * \brief the thread watching for signals and processing them.
     */
    std::thread signal_thread;

    /**
     * \brief last signal in current set, to be sent to stop thread.
     */
    std::atomic<int> cancel_signal;

    /**
     * \brief set to the cancel signal if thread is to be cancelled.
     */
    std::atomic<int> active_cancel_signal;

    /**
     * \brief determine if a signal set has any active signals.
     *
     * \param set       the signal set.
     * \returns `true` if set is empty.
     */
    bool is_sigset_empty(const sigset_t& set)
    {
        for ( int i = FIRST_SIGNAL; i <= LAST_SIGNAL; ++i )
            if ( sigismember(&set, i) )
                return false;

        return true;
    }

    /**
     * \brief Thread watching for signals.
     *
     * Watch for incoming signals on our current block list, and if
     * found fire the signal handlers.
     *
     * One of those signals can be used to indicate that the thread
     * should terminate, so watch out for that.
     */
    void signal_thread_main(sigset_t signals)
    {
        set_thread_name("comp:signal-handler");

        for (;;)
        {
            int sig = 0;
            sigwait(&signals, &sig);
            if ( sig > 0 )
            {
                if ( sig == active_cancel_signal )
                {
                    active_cancel_signal = 0;
                    break;
                }

                std::lock_guard<std::recursive_mutex> local(handler_mutex);
                for ( const auto& h : handlers )
                    h->invoke_handlers(sig);
            }
        }
    }

    /**
     * \brief Update list of signals being watched for.
     *
     * Stop the signal monitoring thread, if it's running, by sending it
     * an expected signal. Then build a new set of signals to watch for,
     * block everything on that list and unblock everything not on the list,
     * and restart the signal watch thread with the new set of blocks,
     * provided there's at least 1 signal to watch for.
     */
    void update_signal_set()
    {
        sigset_t set, inverse_set;
        sigemptyset(&set);
        sigfillset(&inverse_set);

        // Stop old signal thread, if active.
        if ( signal_thread.joinable() )
        {
            // The signal thread is running, so it's waiting for a signal.
            // Give it one to force it to stop.
            active_cancel_signal = cancel_signal.load();
            ::kill(::getpid(), active_cancel_signal);

            signal_thread.join();
        }

        cancel_signal = 0;
        {
            std::lock_guard<std::recursive_mutex> local(handler_mutex);
            for ( const auto& h : handlers )
            {
                sigset_t handler_set = h->signals();
                for ( int i = FIRST_SIGNAL; i <= LAST_SIGNAL; ++i )
                    if ( sigismember(&handler_set, i) )
                    {
                        sigaddset(&set, i);
                        sigdelset(&inverse_set, i);
                        cancel_signal = i;
                    }
            }
        }

        int s = ::pthread_sigmask(SIG_BLOCK, &set, nullptr);
        if ( s != 0 )
            throw signal_handler_error(std::string("pthread_sigmask: ") + std::strerror(s));
        s = ::pthread_sigmask(SIG_UNBLOCK, &inverse_set, nullptr);
        if ( s != 0 )
            throw signal_handler_error(std::string("pthread_sigmask: ") + std::strerror(s));

        if ( !is_sigset_empty(set) )
            signal_thread = std::thread(signal_thread_main, set);
    }
}

SignalHandler::SignalHandler(std::initializer_list<int> signals)
    : sinks_()
{
    if ( signals.size() == 0 )
        throw signal_handler_error("no signals specified");

    sigemptyset(&signals_);
    for ( int i : signals )
        if ( sigaddset(&signals_, i) != 0 )
            throw signal_handler_error("Bad signal " + std::to_string(i));

    {
        std::lock_guard<std::recursive_mutex> local(handler_mutex);
        handlers.insert(this);
    }
    update_signal_set();
}

SignalHandler::~SignalHandler()
{
    {
        std::lock_guard<std::recursive_mutex> local(handler_mutex);
        handlers.erase(this);
    }
    update_signal_set();
}

void SignalHandler::add_handler(SignalSink sink)
{
    std::lock_guard<std::recursive_mutex> local(handler_mutex);
    sinks_.emplace_back(sink);
}

void SignalHandler::invoke_handlers(int signal) const
{
    std::lock_guard<std::recursive_mutex> local(handler_mutex);
    for ( const auto& s : sinks_ )
        s(signal);
}

sigset_t SignalHandler::signals() const
{
    return signals_;
}

void SignalHandler::wait_for_signals()
{
    sigset_t set;

    for(;;)
    {
        sigpending(&set);
        if ( is_sigset_empty(set) )
            break;
        sched_yield();
    }
}
