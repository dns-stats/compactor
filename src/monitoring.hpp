/*
 * Copyright 2025 Internet Corporation for Assigned Names and Numbers.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Developed by Sinodun IT (www.sinodun.com)
 */

#ifndef MONITORING_HPP
#define MONITORING_HPP

#include <chrono>

#include "sniffers.hpp"

namespace cno = std::chrono;

/**
 * \class Monitoring
 * \brief Class to manage sampling and dynamic logging
 *
 * A class to track the status of any sampling performed and the stats
 * aquired to report on that in the periodic logging.
 */
class Monitoring
{
public:

    /**
     * \brief The default constructor.
     *
     * \param stats              packet statistics
     * \param config             configuration information.
     * \param sniffer            sniffer used to obtain stats
     */
    explicit Monitoring(PacketStatistics& stats, const Configuration& config, BaseSniffers* sniffer);

    /**
     * \brief Destructor.
     */
    virtual ~Monitoring();

   /**
    * \brief check if periodic sampling check is due
    *
    * \param last_recv_timestamp      timestamp of last recv packet
    */
    bool drop_check_due(cno::system_clock::time_point last_recv_timestamp) const
    {
        return next_dropcheck_timestamp_ <= last_recv_timestamp;
    }

   /**
   * \brief check is periodic logging check is due
   *
   * \param last_recv_timestamp      timestamp of last recv packet
   */
    bool log_stats_due(cno::system_clock::time_point last_recv_timestamp) const
    {
       return next_log_timestamp_ <= last_recv_timestamp;
    }

   /**
    * \brief run the periodic sampling check and also update some stats
    *
    * \param last_recv_timestamp      timestamp of last recv packet
    */
    void drop_check(cno::system_clock::time_point last_recv_timestamp);

   /**
    * \brief perform periodic logging of collection stats
    *
    * \param last_recv_timestamp      timestamp of last recv packet
    * \param matcher_length           Matcher queue length
    * \param cbor_length              CBOR queue length
    */
    void log_stats(cno::system_clock::time_point last_recv_timestamp, unsigned matcher_length, unsigned cbor_length);
 
   /**
    * \brief Return sampling mode
    */
    bool sampling_active() const
    {
        return sampling_;
    }

    enum DropType {
      RAW =     1,
      IGNORED = 2,
      SNIFF =   3,
      MATCH =   4,
      CBOR =    5,
      MAX_SIZE = 6
    };

    const char* ToString(Monitoring::DropType type)
    {
        switch (type)
        {
            case RAW:     return "Raw-PCAP";
            case IGNORED: return "Ignored-PCAP";
            case SNIFF:   return "Sniffer";
            case MATCH:   return "Matcher";
            case CBOR:    return "C-DNS";
            default:      return "Unknown Drop_type";
        }
    }

   /**
    * \brief Log any change in dropping
    */
    void log_drops_change(bool new_drops, Monitoring::DropType type){
      if (new_drops != new_drops_[type])
      {
        if (new_drops)
          LOG_ERROR << "Started dropping on this channel: " << ToString(type);
        else
          LOG_INFO << "Stopped dropping on this channel: " << ToString(type);
        new_drops_[type] = new_drops;
      }
    }

private:

    // Sniffer will be null when called from DNSTAP loop
    BaseSniffers* sniffer_;
    const Configuration& config_; 

    struct pcap_stat    pcap_stats_;
    struct pcap_stat    last_log_pcap_stats_;

    BaseSniffers::Stats sniffer_stats_;
    BaseSniffers::Stats last_log_sniffer_stats_;
    BaseSniffers::Stats last_dropcheck_sniffer_stats_;

    PacketStatistics& stats_; 
    PacketStatistics last_log_stats_;
    PacketStatistics last_dropcheck_stats_;

    bool sampling_;
    bool trigger_last_check_;
    bool new_drops_[Monitoring::DropType::MAX_SIZE]{};

    cno::system_clock::time_point next_dropcheck_timestamp_;  // next time we should inspect the drop stats
    cno::system_clock::time_point next_log_timestamp_;        // time when next log output of stats is due
    cno::system_clock::time_point last_log_timestamp_;        // time when last log output of stats was done
    cno::system_clock::time_point sampling_end_timestamp_;    // next time sampling should be stopped 

    struct LogStats
    {
        /**
         * \brief Total number of packets sniffed.
         */
        unsigned pps;
        uint64_t pcap_recv;
        uint64_t pcap_os_drop;
        uint64_t pcap_if_drop;
        uint64_t snif_recv;
        uint64_t snif_drop;
        unsigned snif_queue;
        uint64_t matc_recv;
        uint64_t matc_drop;
        unsigned matc_queue;
        uint64_t cdns_recv;
        uint64_t cdns_drop;
        unsigned cdns_queue;
        uint64_t cdns_written;
        uint64_t cdns_traffic;
        uint64_t pcap_out_raw_drop;
        uint64_t pcap_out_ign_drop;
        uint64_t samp_count;

    };

    void calculate_stats(cno::system_clock::time_point last_recv_timestamp, 
                          unsigned matcher_length, unsigned cbor_length, LogStats& ls);
    void write_stats(const LogStats& ls);
#ifdef ENABLE_LOGNETWORKSTATSJSON
    void write_stats_json(const LogStats& ls);
#endif

};

#endif
