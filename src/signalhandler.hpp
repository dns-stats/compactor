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

/**
 * \file signalhandler.hpp
 * \brief The statistics kept on packet/message processing.
 */

#ifndef SIGNALHANDLER_HPP
#define SIGNALHANDLER_HPP

#include <functional>
#include <initializer_list>
#include <stdexcept>
#include <vector>

/**
 * \class SignalHandlerException
 * \brief Base exception for signal handler errors.
 */
class signal_handler_error : public std::runtime_error
{
    /**
     * \brief Use parent constructors.
     */
    using std::runtime_error::runtime_error;
};

/**
 * \class SignalHandler
 * \brief Machinery for handling signals.
 *
 * To avoid restrictions of what can be called from signal handlers,
 * we use a separate signal handling thread.
 */
class SignalHandler
{
public:
    /**
     * \typedef SignalSink
     * \brief Sink functions for signal handlers.
     *
     * \param signal    the signal received.
     */
    using SignalSink = std::function<void (int signal)>;

    /**
     * \brief Constructor.
     *
     * \param signals   signals to handle.
     */
    explicit SignalHandler(std::initializer_list<int> signals);

    /**
     * \brief Destructor.
     */
    virtual ~SignalHandler();

    /**
     * \brief Add a new signal sink function to be called on signal.
     *
     * \param sink      the new signal sink.
     */
    void add_handler(SignalSink sink);

    /**
     * \brief Invoke handlers for given signal.
     *
     * \param signal    the signal.
     */
    void invoke_handlers(int signal) const;

    /**
     * \brief Return the signal set we're interested in.
     *
     * \returns signal set.
     */
    sigset_t signals() const;

    /**
     * \brief Wait until any pending signals are processed.
     */
    static void wait_for_signals();

    /**
     * \brief Copy and assignment deleted.
     */
    SignalHandler(const SignalHandler& other) = delete;
    SignalHandler(SignalHandler&& other) = delete;
    SignalHandler& operator=(const SignalHandler& other) = delete;
    SignalHandler& operator=(SignalHandler&& other) = delete;

private:
    /**
     * \brief set of signals we're intercepting.
     */
    sigset_t signals_;

    /**
     * \brief the sink to fire on a signal.
     */
    std::vector<SignalSink> sinks_;
};

#endif
