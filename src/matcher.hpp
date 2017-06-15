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

#ifndef MATCHER_HPP
#define MATCHER_HPP

#include <chrono>
#include <functional>
#include <memory>

#include "dnsmessage.hpp"
#include "queryresponse.hpp"

/**
 * \class QueryResponseMatcher
 * \brief A processing pipline that matches DNS queries and responses.
 *
 * An instance of this class takes DNS messages as input, and
 * attempts to match queries with responses.
 *
 * The output consists of calls to a sink function. Each call presents
 * a query/response pair. Outputs are in the same order as queries are
 * received.
 */
class QueryResponseMatcher
{
public:
    /**
     * \typedef Sink
     * \brief Prototype of function called with output.
     */
    using Sink = std::function<void (std::shared_ptr<QueryResponse>)>;

    /**
     * \brief Constructor.
     *
     * \param sink          function called with each item of completed output.
     * \param query_timeout timeout period after which a query is regarded as
     *                      having no response.
     * \param skew_timeout  timeout period for out of order packet delivery.
     */
    QueryResponseMatcher(Sink sink,
                         std::chrono::seconds query_timeout = std::chrono::seconds(10),
                         std::chrono::microseconds skew_timeout = std::chrono::microseconds(10));

    /**
     * \brief Destructor.
     *
     * This is specified explicitly because the class uses a PIMPL for
     * internal data. Without an explicity specified destructor built in
     * a source module that defines the PIMPL type, the auto-generated
     * destructor fails to compile.
     */
    ~QueryResponseMatcher();

    /**
     * \brief Add a new DNS message to the matcher.
     *
     * \param m the message to add. Ownership of the message is assumed
     *          by the matcher.
     */
    void add(std::unique_ptr<DNSMessage> m);

    /**
     * \brief Flush all remaining in-progress items.
     *
     * Calls the sink function with each of the items not currently output.
     * Effectively this immediately times out any query without a response.
     */
    void flush();

    /**
     * \brief Set the query timeout value to be used.
     *
     * \param t the new query timeout value.
     */
    void set_query_timeout(std::chrono::seconds t);

    /**
     * \brief Set the skew timeout value to be used.
     *
     * The skew timeout is the maximum time in microseconds to allow
     * for out of temporal order packet delivery. If a response
     * arrives without a query, once a packet arrives with a timestamp
     * this much later, give up hoping for a query to arrive.
     *
     * \param t the new skew timeout value.
     */
    void set_skew_timeout(std::chrono::microseconds t);

protected:
    /**
     * \brief add a new query message to the outstanding queries.
     *
     * \param m the message to add. Pointer ownership will be transferred.
     */
    void add_query(std::unique_ptr<DNSMessage>& m);

    /**
     * \brief add a new response message to the matcher state.
     *
     * \param m the message to add. Pointer ownership will be tranferred
     *          if the response is matched or there is a later query.
     */
    void add_response(std::unique_ptr<DNSMessage>& m);

    /**
     * \brief Check all outstanding queries to see if they are now timed out.
     *
     * If a query is timed out, it is marked as completed.
     *
     * \param now the time point to be used as now with calculating the
     *            timeout boundary.
     * \throws queryresponse_match_error on internal error.
     */
    void timeout_queries(std::chrono::system_clock::time_point now);

    /**
     * \brief Check all outstanding responses without queries to see
     * if they are now timed out.
     *
     * If a response without a query is now older than the skew
     * timeout, it is marked as completed.
     *
     * \param now the time point to be used as now with calculating the
     *            timeout boundary.
     */
    void timeout_responses(std::chrono::system_clock::time_point now);

    /**
     * \brief Write outputs to the sink.
     *
     * Calls the sink function with outputs.
     *
     * A completed item is a query that has either received a response, or
     * has timed out.
     *
     * \param complete_only if `true` only writes completed items to the sink.
     *                      If `false`, writes all items.
     */
    void write(bool complete_only);

private:
    /**
     * \struct QRMData
     * \brief data used internally by the matcher.
     */
    struct QRMData;

    /**
     * \brief the query timeout period.
     */
    std::chrono::seconds query_timeout_;

    /**
     * \brief the skew timeout period.
     */
    std::chrono::microseconds skew_timeout_;

    /**
     * \brief the sink function to receive outputs.
     */
    Sink sink_;

    /**
     * \brief PIMPL for data used internally by the matcher.
     */
    std::unique_ptr<QRMData> data_;
};

#endif
