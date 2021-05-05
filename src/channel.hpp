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

#ifndef CHANNEL_HPP
#define CHANNEL_HPP

#include <condition_variable>
#include <queue>
#include <mutex>
#include <thread>

// This implementation of something vaguely like a Go channel is
// based on https://st.xorian.net/blog/2012/08/go-style-channel-in-c/.

/**
 * \class Channel
 * \brief A basic Go-like channel.
 *
 * This class implements a basic Go-like channel. This is simply a queue
 * (FIFO) of objects of the specified type. All channel operations are
 * protected by a mutex, so a channel can be used as a means of passing
 * items from one thread to another. A channel can also be marked as closed,
 * allowing a simple receiver loop:
 *
 * \code
 * while ( channel.get(item) ) {
 *     process(item);
 * }
 * \endcode
 *
 * Unlike Go, no select() is currently supported, and the channel capacity
 * can either be fixed or will expand indefinitely as items are added.
 *
 * This class requires C++11 threading, mutexes etc.
 */
template<class item>
class Channel
{
public:
    /**
     * \brief Default constructor.
     */
    explicit Channel(unsigned max_len = 0)
        : closed_(false), max_len_(max_len) {}

    /**
     * \brief Mark the channel as closed.
     */
    void close()
    {
        std::lock_guard<std::mutex> lock(m_);
        closed_ = true;
        cv_.notify_all();
    }

    /**
     * \brief Return `true` if the channel is closed.
     */
    bool is_closed()
    {
        std::lock_guard<std::mutex> lock(m_);
        return closed_;
    }

    /**
     * \brief Add a new item to the channel.
     *
     * Add a new item to the channel. The item is added immediately,
     * expanding the channel capacity if necessary. If any threads
     * are waiting on the channel, one is informed.
     *
     * \param i    the item to add.
     * \param wait if `true` and queue is full, wait for it to have room.
     * \return `false` is queue is full and we're not waiting.
     * \throws std::logic_error if the channel is closed.
     */
    bool put(const item &i, bool wait = true)
    {
        std::unique_lock<std::mutex> lock(m_);
        if ( max_len_ > 0 )
        {
            if ( wait )
                cv_.wait(lock, [this](){ return closed_ || queue_.size() < max_len_; });
            else
                if ( queue_.size() >= max_len_ )
                    return false;
        }
        if ( closed_ )
            throw std::logic_error("put to closed channel");

        queue_.push(i);
        cv_.notify_one();
        return true;
    }

    /**
     * \brief Add a new item to the channel.
     *
     * Add a new item to the channel. The item is added immediately,
     * expanding the channel capacity if necessary. If any threads
     * are waiting on the channel, one is informed.
     *
     * \param i the item to add.
     * \param wait if `true` and queue is full, wait for it to have room.
     * \return `false` is queue is full and we're not waiting.
     * \throws std::logic_error if the channel is closed.
     */
    bool put(item &&i, bool wait = true)
    {
        std::unique_lock<std::mutex> lock(m_);
        if ( max_len_ > 0 )
        {
            if ( wait )
                cv_.wait(lock, [this](){ return closed_ || queue_.size() < max_len_; });
            else
                if ( queue_.size() >= max_len_ )
                    return false;
        }
        if ( closed_ )
            throw std::logic_error("put to closed channel");

        queue_.push(i);
        cv_.notify_one();
        return true;
    }

    /**
     * \brief Retrieve an item from the channel.
     *
     * \param out set to the retrieved item.
     * \param wait if `true`, and channel is empty, block until an item is added.
     * \returns `false` if channel is closed or the channel is empty
     *          and waiting was not specified.
     */
    bool get(item &out, bool wait = true)
    {
        std::unique_lock<std::mutex> lock(m_);
        if ( wait )
            cv_.wait(lock, [this](){ return closed_ || !queue_.empty(); });
        if ( queue_.empty() )
            return false;
        out = std::move(queue_.front());
        queue_.pop();
        cv_.notify_one();
        return true;
    }

    /**
     * \brief Set the maximum number of items in the channel.
     *
     * This will only set the future threshold. It will not remove
     * any excess items currently in the channel.
     *
     * \param max_items the maximum number of items in the channel.
     */
    void set_max_items(unsigned max_items)
    {
        max_len_ = max_items;
    }

private:
    /**
     * \brief the channel item queue.
     */
    std::queue<item> queue_;

    /**
     * \brief mutex guarding access to the channel.
     */
    std::mutex m_;

    /**
     * \brief condition variable for signalling to channel clients.
     */
    std::condition_variable cv_;

    /**
     * \brief mark if the channel is closed.
     */
    bool closed_;

    /**
     * \brief maximum length queue allowed.
     *
     * 0 means 'no maximum'.
     */
    unsigned max_len_;
};

#endif
