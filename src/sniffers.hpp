/*
 * Copyright 2016-2018, 2021 Internet Corporation for Assigned Names and Numbers.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Developed by Sinodun IT (www.sinodun.com)
 */

/**
 * \file sniffers.hpp
 * \brief Read PCAP from a network interface or a file.
 */

#ifndef SNIFFERS_HPP
#define SNIFFERS_HPP

#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <tins/tins.h>

#include <sys/select.h>

#include <pcap/pcap.h>

#include "channel.hpp"
#include "configuration.hpp"

/**
 * \class SniffersConfiguration
 * \brief Configuration information for sniffers.
 */
class SniffersConfiguration
{
public:
    /**
     * \brief Constructor.
     */
    SniffersConfiguration();

    /**
     * \brief Set the snap length.
     *
     * \param len the snap length.
     */
    void set_snap_len(unsigned len)
    {
        snap_len_ = len;
    }

    /**
     * \brief Return the snap length.
     *
     * \returns snap length.
     */
    unsigned snap_len() const
    {
        return snap_len_;
    }

    /**
     * \brief Set promiscous mode.
     *
     * \param enabled `true` if promiscous mode is to be enabled.
     */
    void set_promisc_mode(bool enabled)
    {
        flags_ |= PROMISCUOUS;
        promisc_ = enabled;
    }

    /**
     * \brief Return the promiscuous mode.
     *
     * \returns `true` if promiscuous mode should be enabled.
     */
    bool promisc_mode() const
    {
        return promisc_;
    }

    /**
     * \brief Set the read timeout
     *
     * \param timeout the read timeout in milliseconds.
     */
    void set_timeout(unsigned timeout)
    {
        timeout_ = timeout;
    }

    /**
     * \brief Return the collection timeout.
     *
     * \returns the collection timeout, in milliseconds.
     */
    unsigned timeout() const
    {
        return timeout_;
    }

    /**
     * \brief Set the PCAP filter
     *
     * \param filter the PCAP filter string.
     */
    void set_filter(const std::string& filter)
    {
        flags_ |= PACKET_FILTER;
        filter_ = filter;
    }

    /**
     * \brief Return the collection filter.
     *
     * \returns the collection filter, an empty string if none set.
     */
    std::string filter() const
    {
        return filter_;
    }

    /**
     * \brief Set the channel maximum size
     *
     * \param max_size the channel maximum size.
     */
    void set_chan_max_size(unsigned max_size)
    {
        chan_max_size_ = max_size;
    }

    /**
     * \brief Return the channel maximum size.
     *
     * \returns the channel maximum size.
     */
    unsigned chan_max_size() const
    {
        return chan_max_size_;
    }

protected:
    friend class NetworkSniffers;
    friend class FileSniffer;

    /**
     * \brief Flags indicating items are present.
     */
    enum Flags {
        PACKET_FILTER = 1,
        PROMISCUOUS = 2
    };

    /**
     * \brief Apply configured timeout to PCAP handle.
     *
     * \param handle the PCAP handle.
     */
    void apply_timeout(pcap_t* handle) const;

    /**
     * \brief Apply configured snap length to PCAP handle.
     *
     * \param handle the PCAP handle.
     */
    void apply_snap_len(pcap_t* handle) const;

    /**
     * \brief Apply configured promiscous mode (if set) to PCAP handle.
     *
     * \param handle the PCAP handle.
     */
    void apply_promisc_mode(pcap_t* handle) const;

    /**
     * \brief Apply configured filter (if set) to PCAP handle.
     *
     * \param handle the PCAP handle.
     * \param netmask the IPv4 netmask of the capture network. See
     * `pcap_compile`.
     */
    void apply_filter(pcap_t* handle, bpf_u_int32 netmask) const;

private:
    /**
     * \brief Items present flag.
     */
    unsigned flags_;

    /**
     * \brief The snap length.
     */
    unsigned snap_len_;

    /**
     * \brief Promiscous mode.
     */
    bool promisc_;

    /**
     * \brief Timeout, in milliseconds.
     */
    unsigned timeout_;

    /**
     * \brief PCAP filter string.
     */
    std::string filter_;

    /**
     * \brief Channel maximum size.
     */
    unsigned chan_max_size_;
};

/**
 * \class BaseSniffers
 * \brief Virtual base for sniffers.
 *
 * A virtual base class providing the necessary facilities for collecting
 * packets from multiple sniffers in parallel.
 */
class BaseSniffers
{
public:
    /**
     * \brief The default constructor.
     *
     * \param chan_max_size maximum size of channel delivering packets.
     */
    explicit BaseSniffers(unsigned chan_max_size = 1000);

    /**
     * \brief Destructor.
     */
    virtual ~BaseSniffers();

    /**
     * \brief Get the next packet from the sniffers.
     *
     * \returns the next packet, or if EOF or collection interrupted
     * a packet with a null PDU.
     */
    Tins::Packet next_packet();

    /**
     * \brief Get stats on the sniffers.
     *
     * \param stats a PCAP stats structure.
     * \returns `true` if stats updated.
     */
    bool stats(struct pcap_stat& stats);

    /**
     * \brief Break out of the collection loop.
     *
     * This calls pcap_breakloop() on all underlying sniffers.
     */
    void breakloop();

protected:
    /**
     * \brief Add a new PCAP handle to those being monitored.
     *
     * \param handle handle to add.
     */
    void add_handle(pcap_t* handle);

    /**
     * \brief Update the select timeout.
     *
     * Reduce the timeout if the read timeout is less.
     *
     * \param timeout read timeout.
     */
    void notify_read_timeout(unsigned timeout);

    /**
     * \brief Capture initialisation done.
     *
     * Start the packet reading thread.
     */
    void capture_init_done();

private:
    /**
     * \brief Loop reading packets and adding to the channel.
     */
    void packet_read_thread();

    /**
     * \brief PCAP handles of all input sources.
     */
    std::vector<pcap_t*> handles_;

    /**
     * \brief fdset for selecting on all input sources.
     */
    fd_set fdset_;

    /**
     * \brief maximum fd for all input sources.
     */
    int max_fd_;

    /**
     * \brief timeout for selecting on input sources.
     */
    unsigned select_timeout_;

    /**
     * \brief delivery channel for packets.
     */
    Channel<Tins::Packet> packets_;

    /**
     * \brief mutex guarding PCAP handles.
     */
    std::mutex m_;

    /**
     * \brief background thread collecting packets.
     */
    std::thread t_;
};


/**
 * \class NetworkSniffers
 * \brief A collection of network sniffers.
 *
 * This class allows sniffing on multiple interfaces at once.
 */
class NetworkSniffers : public BaseSniffers
{
public:
    /**
     * \brief Constructor.
     *
     * \param interfaces the interfaces to sniff.
     * \param config     the sniffing configuration.
     */
    NetworkSniffers(const std::vector<std::string>& interfaces,
                    const SniffersConfiguration& config);
};

/**
 * \class FileSniffer
 * \brief A sniffer reading from a capture file.
 */
class FileSniffer : public BaseSniffers
{
public:
    /**
     * \brief Constructor.
     *
     * \param fname  pathname of capture file.
     * \param config the sniffing configuration.
     */
    FileSniffer(const std::string& fname, const SniffersConfiguration& config);
};


#endif
