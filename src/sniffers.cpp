/*
 * Copyright 2016-2018 Internet Corporation for Assigned Names and Numbers.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Developed by Sinodun IT (www.sinodun.com)
 */

#include <errno.h>

#include <tins/loopback.h>
#include <tins/pktap.h>

#include "config.h"
#ifdef HAVE_LIBTINS4
#include <tins/detail/pdu_helpers.h>
#endif

#include "log.hpp"

#include "sniffers.hpp"

SniffersConfiguration::SniffersConfiguration()
    : flags_(0), snap_len_(65535), promisc_(false),
      timeout_(1000), chan_max_size_(1000)
{
}

void SniffersConfiguration::apply_timeout(pcap_t* handle) const
{
    if ( pcap_set_timeout(handle, timeout_) != 0 )
        throw Tins::pcap_error(pcap_geterr(handle));
}

void SniffersConfiguration::apply_snap_len(pcap_t* handle) const
{
    if ( pcap_set_snaplen(handle, snap_len_) != 0 )
        throw Tins::pcap_error(pcap_geterr(handle));
}

void SniffersConfiguration::apply_promisc_mode(pcap_t* handle) const
{
    if ( flags_ & PROMISCUOUS )
        if ( pcap_set_promisc(handle, promisc_) != 0 )
            throw Tins::pcap_error(pcap_geterr(handle));
}

void SniffersConfiguration::apply_filter(pcap_t* handle, bpf_u_int32 netmask) const
{
    if ( flags_ & PACKET_FILTER )
    {
        bpf_program prog;

        if ( pcap_compile(handle, &prog, filter_.c_str(), 0, netmask) != 0 )
            throw Tins::invalid_pcap_filter(pcap_geterr(handle));

        int set_res = pcap_setfilter(handle, &prog);
        pcap_freecode(&prog);
        if ( set_res != 0 )
            throw Tins::invalid_pcap_filter(pcap_geterr(handle));
    }
}

namespace {
    const Tins::Packet::own_pdu DONT_COPY_PDU = {};

    template<typename T>
    Tins::Packet make_generic_packet(const struct pcap_pkthdr* hdr,
                                        const u_char* data)
    {
        return Tins::Packet(new T(reinterpret_cast<const uint8_t*>(data), hdr->caplen), hdr->ts, DONT_COPY_PDU);
    }

    Tins::Packet make_eth_packet(const struct pcap_pkthdr* hdr,
                                 const u_char* data)
    {
        if ( Tins::Internals::is_dot3(reinterpret_cast<const uint8_t*>(data), hdr->caplen) )
            return Tins::Packet(new Tins::Dot3(reinterpret_cast<const uint8_t*>(data), hdr->caplen), hdr->ts, DONT_COPY_PDU);
        else
            return Tins::Packet(new Tins::EthernetII(reinterpret_cast<const uint8_t*>(data), hdr->caplen), hdr->ts, DONT_COPY_PDU);
    }

    Tins::Packet make_packet(pcap_t* handle,
                             const struct pcap_pkthdr* hdr,
                             const u_char* data)
    {
        switch(pcap_datalink(handle))
        {
        case DLT_EN10MB:
            return make_eth_packet(hdr, data);

        case DLT_IEEE802_11_RADIO:
#ifdef TINS_HAVE_DOT11
            return make_generic_packet<Tins::RadioTap>(hdr, data);
#else
            throw Tins::protocol_disabled();
#endif

        case DLT_IEEE802_11:
#ifdef TINS_HAVE_DOT11
            return Tins::Packet(Tins::Dot11::from_bytes(data, hdr->caplen), hdr->ts, DONT_COPY_PDU);
#else
            throw Tins::protocol_disabled();
#endif

#ifdef DLT_PKTAP
        case DLT_PKTAP:
            return make_generic_packet<Tins::PKTAP>(hdr, data);
#endif

        case DLT_NULL:
            return make_generic_packet<Tins::Loopback>(hdr, data);

        case DLT_LINUX_SLL:
            return make_generic_packet<Tins::SLL>(hdr, data);

        case DLT_PPI:
            return make_generic_packet<Tins::PPI>(hdr, data);

        default:
            throw Tins::unknown_link_type();
        }
    }
}

BaseSniffers::BaseSniffers(unsigned chan_max_size)
    : max_fd_(0), select_timeout_(1000), packets_(chan_max_size)
{
    FD_ZERO(&fdset_);
}

BaseSniffers::~BaseSniffers()
{
    breakloop();
    if ( t_.joinable() )
        t_.join();

    for ( auto h : handles_ )
        pcap_close(h);
}

Tins::Packet BaseSniffers::next_packet()
{
    Tins::Packet p;

    if ( packets_.get(p) )
        return p;
    else
        return Tins::Packet();
}

bool BaseSniffers::stats(struct pcap_stat& stats)
{
    bool res = true;
    std::unique_lock<std::mutex> lock(m_);

    stats = { 0, 0, 0 };

    for ( auto h : handles_ )
    {
        struct pcap_stat istat;

        if ( pcap_stats(h, &istat) == 0 )
        {
            stats.ps_recv += istat.ps_recv;
            stats.ps_drop += istat.ps_drop;
            stats.ps_ifdrop += istat.ps_ifdrop;
        }
        else
            res = false;
    }

    return res;
}

void BaseSniffers::breakloop()
{
    std::unique_lock<std::mutex> lock(m_);
    for ( auto h : handles_ )
        pcap_breakloop(h);
}

void BaseSniffers::add_handle(pcap_t* handle)
{
    int fd = pcap_get_selectable_fd(handle);
    if ( fd < 0 )
        throw Tins::unsupported_function();

    handles_.push_back(handle);

    FD_SET(fd, &fdset_);
    if ( fd > max_fd_ )
        max_fd_ = fd;
}

void BaseSniffers::notify_read_timeout(unsigned timeout)
{
    if ( select_timeout_ < timeout )
        select_timeout_ = timeout;
}

void BaseSniffers::packet_read_thread()
{
    bool finished = false;

    while ( !finished )
    {
        bool read_one;

        do
        {
            read_one = false;

            for ( auto h : handles_ )
            {
                std::unique_lock<std::mutex> lock(m_);
                struct pcap_pkthdr* hdr;
                const u_char* data;
                int res = pcap_next_ex(h, &hdr, &data);
                lock.unlock();

                switch (res)
                {
                case 1:
                    read_one = true;
                    try
                    {
                        packets_.put(make_packet(h, hdr, data));
                    }
                    catch (Tins::exception_base&)
                    {
                        // Unlike libtins, which just ignores them, pass malformed
                        // packets - packets where transport level decode fails -
                        // back to the application as RawPDU. There they will be
                        // treated as ignored and logged if appropriate.
                        packets_.put(Tins::Packet(new Tins::RawPDU(reinterpret_cast<const uint8_t*>(data), hdr->caplen), hdr->ts, DONT_COPY_PDU));
                    }
                    break;

                case 0:
                    break;

                case -1:
                    // TODO: Find way to indicate error rather than EOF to
                    // receiving thread.
                    LOG_ERROR << pcap_geterr(h);
                    finished = true;
                    break;

                case -2:
                    finished = true;
                    break;
                }
            }
        }
        while ( read_one && !finished );

        if ( finished )
            continue;

        // Nothing available for immediate read. Wait for something.
        // Note that we may exit select with a timeout or interrupted
        // system call and no data. If interrupted, go round so that
        // pcap may discover a breakloop if that was the cause.
        fd_set fd_selected = fdset_;
        struct timeval tv;
        tv.tv_sec = select_timeout_ / 1000;
        tv.tv_usec = (select_timeout_ % 1000) * 1000;

        switch (select(max_fd_ + 1, &fd_selected, nullptr, nullptr, &tv))
        {
        case -1:
            switch(errno)
            {
            case EAGAIN:
            case EINTR:
                break;

            default:
                // TODO: Find way to indicate error rather than EOF to
                // receiving thread.
                LOG_ERROR << "Selecting next packet failed";
                finished = true;
                break;
            }

        case 0:
            // Timeout expired. Try again.
            break;

        default:
            // Got something. Go round and read it.
            break;
        }
    }

    packets_.close();
}

void BaseSniffers::capture_init_done()
{
    t_ = std::thread([=]{ packet_read_thread(); });
}

NetworkSniffers::NetworkSniffers(const std::vector<std::string>& interfaces,
                                 const SniffersConfiguration& config)
    : BaseSniffers(config.chan_max_size())
{
    notify_read_timeout(config.timeout_);

    for ( const auto& i : interfaces )
    {
        char errbuf[PCAP_ERRBUF_SIZE];
        bpf_u_int32 ip, netmask;
        if ( pcap_lookupnet(i.c_str(), &ip, &netmask, errbuf) == -1 )
            netmask = PCAP_NETMASK_UNKNOWN;

        pcap_t* handle = pcap_create(i.c_str(), errbuf);
        if ( !handle )
            throw Tins::pcap_error(errbuf);

        config.apply_snap_len(handle);
        config.apply_timeout(handle);
        config.apply_promisc_mode(handle);

        if ( pcap_activate(handle) < 0 )
            throw Tins::pcap_error(pcap_geterr(handle));

        if ( pcap_setnonblock(handle, 1, errbuf) < 0 )
            throw Tins::pcap_error(errbuf);

        config.apply_filter(handle, netmask);

        add_handle(handle);
    }

    capture_init_done();
}

FileSniffer::FileSniffer(const std::string& fname,
                         const SniffersConfiguration& config)
    : BaseSniffers(config.chan_max_size())
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(fname.c_str(), errbuf);
    if ( !handle )
        throw Tins::pcap_error(errbuf);

    config.apply_filter(handle, PCAP_NETMASK_UNKNOWN);
    add_handle(handle);

    capture_init_done();
}
