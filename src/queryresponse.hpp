/*
 * Copyright 2016-2017, 2021, 2022 Internet Corporation for Assigned Names and Numbers.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Developed by Sinodun IT (www.sinodun.com)
 */

#ifndef QUERYRESPONSE_HPP
#define QUERYRESPONSE_HPP

#include <memory>

#include "dnsmessage.hpp"

/**
 * \exception queryresponse_match_error
 * \brief Signals a query/response logic error.
 *
 * This is either an attempt to get the timestamp of a pair without
 * either query or response, or an internal error during matching.
 */
class queryresponse_match_error : public std::logic_error
{
public:
    /**
     * \brief Constructor.
     */
    queryresponse_match_error()
        : std::logic_error("Inconsistent state in query/response matching"){}
};

/**
 * \class QueryResponse
 * \brief A query/response pair.
 *
 * This keeps one or both of a pair of DNS query and response.
 * It may hold a timed out query without response, a response without
 * matching query, or (hopefully) a query with its matching response.
 */
class QueryResponse
{
public:
    /**
     * \brief Constructor.
     *
     * Builds a query/response pair. This may hold a query waiting response
     * or timed out, a response without a query, or a query and its response.
     *
     * \param m DNS message.
     * \param query `true` if this message is a query, `false` if a response.
     */
    explicit QueryResponse(std::unique_ptr<DNSMessage> m, bool query = true)
    {
        if ( query )
            query_ = std::move(m);
        else
            set_response(std::move(m));
    }

    /**
     * \brief Returns `true` if this pair contains a query.
     */
    bool has_query() const
    {
        return query_.get();
    }

    /**
     * \brief Returns `true` if this pair contains a response.
     */
    bool has_response() const
    {
        return response_.get();
    }

    /**
     * \brief Return the query of this pair.
     */
    const DNSMessage &query() const
    {
        return *query_;
    }

    /**
     * \brief Return the response of this pair.
     */
    const DNSMessage &response() const
    {
        return *response_;
    }

    /**
     * \brief Sets the message as the response for this pair.
     */
    void set_response(std::unique_ptr<DNSMessage> m)
    {
        response_ = std::move(m);
    }

    /**
     * \brief Returns the pair timestamp.
     *
     * If there is a query, this is the query timestamp. Otherwise it is
     * the response timestamp.
     *
     * \throws queryresponse_match_error if pair has neither query or response.
     */
    std::chrono::system_clock::time_point timestamp() const
    {
        if ( query_ )
            return query_->timestamp;
        else if ( response_ )
            return response_->timestamp;
        else
            throw queryresponse_match_error();
    }

    /**
     * \brief Write basic information on the pair to the output stream.
     *
     * \param output the output stream.
     * \param qr     the pair.
     * \return the output stream.
     */
    friend std::ostream& operator<<(std::ostream& output, const QueryResponse& qr);

private:
    /**
     * \brief the query.
     */
    std::unique_ptr<DNSMessage> query_;

    /**
     * \brief the response.
     */
    std::unique_ptr<DNSMessage> response_;
};

#endif
