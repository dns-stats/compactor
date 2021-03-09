/*
 * Copyright 2016-2019, 2021 Internet Corporation for Assigned Names and Numbers.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Developed by Sinodun IT (www.sinodun.com)
 */

#include <deque>
#include <list>
#include <unordered_map>
#include <utility>

#include <boost/functional/hash.hpp>

#include "makeunique.hpp"

#include "matcher.hpp"

/**
 * \class QueryResponseInProgress
 * \brief A query/response pair, with added completeness flags.
 *
 * A query/response pair is complete if it is a query with matching response,
 * a query that has timed out, or a response without a query. In other words,
 * a complete pair requires no further processing.
 */
class QueryResponseInProgress
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
    QueryResponseInProgress(std::unique_ptr<DNSMessage> m, bool query = true);

    /**
     * \brief Returns `true` if this query/response pair is complete.
     */
    bool is_complete() const;

    /**
     * \brief Returns `true` if this pair contains a query.
     */
    bool has_query() const;

    /**
     * \brief Return the query of this pair.
     */
    const DNSMessage &query() const;

    /**
     * \brief Return a `QueryResponse` describing the pair.
     */
    std::shared_ptr<QueryResponse> query_response() const;

    /**
     * \brief Sets the message as the response for this pair.
     *
     * In the process this marks the pair as complete.
     *
     * \param m the response message.
     */
    void set_response(std::unique_ptr<DNSMessage> m);

    /**
     * \brief Mark the pair as complete.
     */
    void set_complete();

    /**
     * \brief Returns the pair timestamp.
     *
     * If there is a query, this is the query timestamp. Otherwise it is
     * the response timestamp.
     */
    std::chrono::system_clock::time_point timestamp() const;

private:
    /**
     * \brief flag indicating if the pair is complete.
     */
    bool complete_;

    /**
     * \brief pointer to the query/response pair information.
     */
    std::shared_ptr<QueryResponse> qr_;
};

QueryResponseInProgress::QueryResponseInProgress(std::unique_ptr<DNSMessage> m, bool query)
    : complete_(!query), qr_(std::make_shared<QueryResponse>(std::move(m), query))
{
}

bool QueryResponseInProgress::is_complete() const
{
    return complete_;
}

bool QueryResponseInProgress::has_query() const
{
    return qr_->has_query();
}

const DNSMessage &QueryResponseInProgress::query() const
{
    return qr_->query();
}

std::shared_ptr<QueryResponse> QueryResponseInProgress::query_response() const
{
    return qr_;
}

void QueryResponseInProgress::set_response(std::unique_ptr<DNSMessage> m)
{
    qr_->set_response(std::move(m));
    complete_ = true;
}

void QueryResponseInProgress::set_complete()
{
    complete_ = true;
}

std::chrono::system_clock::time_point QueryResponseInProgress::timestamp() const
{
    return qr_->timestamp();
}

/**
 * \brief Implement equality operator for two DNS questions.
 *
 * \param q1 the first query.
 * \param q2 the second query.
 * \returns `true` if the two are equal.
 */
bool operator==(const CaptureDNS::query &q1, const CaptureDNS::query &q2)
{
    return
        q1.dname() == q2.dname() &&
        q1.query_type() == q2.query_type() &&
        q1.query_class() == q2.query_class();
}

/**
 * \class LiveQueries
 * \brief Lookup for queries currently without responses.
 *
 * This class is used internally in the query/response matcher. It keeps
 * a set of `QueryResponseInProgress` items, and matches response messages
 * with matching queries, if any.
 */
class LiveQueries
{
public:
    /**
     * \brief Add a new `QueryResponseInProgress` pair to the set of
     *        pairs awaiting a match.
     *
     * \param qr the pair to add.
     */
    void add(const std::shared_ptr<QueryResponseInProgress> &qr);

    /**
     * \brief Find a match for a DNS response.
     *
     * If there is no matching query, this generates a new pair with
     * response only.
     *
     * This generates a key from the response, and looks up that
     * key in an unordered map. If not found, there is no matching query.
     * Then if the response has a question, searches the list of matching
     * queries looking for the first with the same question. This is returned
     * and removed from the map. If none is found, there is no matching query.
     *
     * If the response has no question, this returns the first
     * query found. This query is removed from the map.
     *
     * \param m the DNS response to match.
     * \returns matching pair, or a new response-only pair if no query found.
     */
    std::shared_ptr<QueryResponseInProgress> matchResponse(const DNSMessage &m);

private:
    /**
     * \brief Make a key used to look up a query.
     *
     * This key incorporates the client and server IP and port, the DNS
     * transaction ID, and the protocol (UDP or TCP) used.
     *
     * \param m the message to make a key for.
     */
    static std::size_t makeKey(const DNSMessage &m);

    /**
     * \brief A map where each endpoint contains a list of queries with the
     *        same key.
     */
    std::unordered_map<std::size_t, std::deque<std::shared_ptr<QueryResponseInProgress>>> map_;
};

void LiveQueries::add(const std::shared_ptr<QueryResponseInProgress> &qr)
{
    std::size_t key = makeKey(qr->query());
    map_[key].push_back(qr);
}

std::shared_ptr<QueryResponseInProgress>
LiveQueries::matchResponse(const DNSMessage &m)
{
    std::shared_ptr<QueryResponseInProgress> res;
    std::size_t key = makeKey(m);
    auto qrf = map_.find(key);
    if ( qrf == map_.end() )
        return res;

    if ( m.dns.questions_count() == 0 )
    {
        res = qrf->second.front();
        qrf->second.pop_front();
    }
    else
    {
        auto rquery = m.dns.queries().front();
        for ( auto qrli = qrf->second.begin();
              qrli != qrf->second.end();
              ++qrli )
        {
            if ( (**qrli).query().dns.questions_count() > 0 &&
                 (**qrli).query().dns.queries().front() == rquery )
            {
                res = *qrli;
                qrf->second.erase(qrli);
                break;
            }
        }
    }

    if ( res && qrf->second.empty() )
        map_.erase(qrf);

    return res;
}

std::size_t LiveQueries::makeKey(const DNSMessage &m)
{
    std::size_t seed = boost::hash_value(m.transport_type);
    if ( m.clientIP )
        boost::hash_combine(seed, hash_value(*m.clientIP));
    if ( m.serverIP )
        boost::hash_combine(seed, hash_value(*m.serverIP));
    if ( m.clientPort )
         boost::hash_combine(seed, *m.clientPort);
    if ( m.serverPort )
         boost::hash_combine(seed, *m.serverPort);
    boost::hash_combine(seed, m.dns.id());
    return seed;
}

/**
 * \struct QRMData
 * \brief Internal data for the matcher.
 */
struct QueryResponseMatcher::QRMData
{
    /**
     * \brief a map of live queries.
     */
    LiveQueries liveQueries;

    /**
     * \brief the queue of pairs awaiting output.
     *
     * Note that these are output in FIFO order. So an incomplete
     * query at the front will block output of later, completed,
     * queries until it is timed out or the whole queue is flushed.
     */
    std::deque<std::shared_ptr<QueryResponseInProgress>> output;

    /**
     * \brief list of responses waiting for a later query.
     */
    std::list<std::unique_ptr<DNSMessage>> response_queue;
};

QueryResponseMatcher::QueryResponseMatcher(Sink sink,
                                           std::chrono::milliseconds query_timeout,
                                           std::chrono::microseconds skew_timeout)
    : query_timeout_(query_timeout), skew_timeout_(skew_timeout), sink_(sink), data_(make_unique<QRMData>())
{
}

QueryResponseMatcher::~QueryResponseMatcher()
{
}

void QueryResponseMatcher::set_query_timeout(std::chrono::milliseconds timeout)
{
    query_timeout_ = timeout;
}

void QueryResponseMatcher::set_skew_timeout(std::chrono::microseconds timeout)
{
    skew_timeout_ = timeout;
}

void QueryResponseMatcher::flush()
{
    for ( auto& r : data_->response_queue )
    {
        if ( r )
            data_->output.push_back(std::make_shared<QueryResponseInProgress>(std::move(r), false));
    }
    data_->response_queue.clear();

    write(false);
}

void QueryResponseMatcher::add(std::unique_ptr<DNSMessage> m)
{
    timeout_queries(m->timestamp);
    timeout_responses(m->timestamp);

    if ( m->dns.type() == CaptureDNS::QUERY )
        add_query(m);
    else
    {
        add_response(m);
        // If response was not consumed, stash it. Add it to the back of
        // the queue of outstanding responses so that unmatched responses
        // get processed in the order in which they were presented.
        if ( m )
            data_->response_queue.push_back(std::move(m));
    }

    write(true);
}

void QueryResponseMatcher::add_query(std::unique_ptr<DNSMessage>& m)
{
    std::shared_ptr<QueryResponseInProgress> qr = std::make_shared<QueryResponseInProgress>(std::move(m));
    data_->liveQueries.add(qr);
    data_->output.push_back(qr);

    // See if any queued responses can now be consumed.
    for ( auto it = data_->response_queue.begin();
          it != data_->response_queue.end();
          ++it )
    {
        if (*it)
            add_response(*it);
    }
}

void QueryResponseMatcher::add_response(std::unique_ptr<DNSMessage>& m)
{
    std::shared_ptr<QueryResponseInProgress> qr = data_->liveQueries.matchResponse(*m);
    if ( qr )
        qr->set_response(std::move(m));
}

void QueryResponseMatcher::timeout_queries(std::chrono::system_clock::time_point now)
{
    std::chrono::system_clock::time_point timeout_if_before = now - query_timeout_;

    for ( const auto& qr : data_->output )
    {
        if ( !qr->is_complete() )
        {
            if ( !qr->has_query() )
                throw queryresponse_match_error();

            // Output queue is a FIFO, earliest first. So if the
            // timestamp is after the timeout threshold, we're done.
            if ( qr->timestamp() > timeout_if_before )
                break;

            // When marking a query timed out, we need to remove it
            // from the map of live queries. Do this by matching it
            // with itself. If we don't find it, something is wrong.
            if ( !data_->liveQueries.matchResponse(qr->query()) )
                throw queryresponse_match_error();
            else
                qr->set_complete();
        }
    }
}

void QueryResponseMatcher::timeout_responses(std::chrono::system_clock::time_point now)
{
    std::chrono::system_clock::time_point timeout_if_before = now - skew_timeout_;
    bool done;
    do
    {
        done = true;

        for ( auto it = data_->response_queue.begin();
              it != data_->response_queue.end();
              ++it )
        {
            // Does the response exist, and if so has it timed out?
            if ( (*it) && (*it)->timestamp < timeout_if_before )
                data_->output.push_back(std::make_shared<QueryResponseInProgress>(std::move(*it), false));

            // If it's null, the response has been consumed.
            // Remove from the queue and restart iteration.
            if ( !(*it) )
            {
                data_->response_queue.erase(it);
                done = false;
                break;
            }
        }
    } while (!done);
}

void QueryResponseMatcher::write(bool complete_only)
{
    while ( !data_->output.empty() )
    {
        auto front = data_->output.front();

        if ( complete_only && !front->is_complete() )
            break;

        data_->output.pop_front();
        sink_(front->query_response());
    }
}
