/*
 * Copyright 2026 Internet Corporation for Assigned Names and Numbers.
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

   /**
    * \brief Types of drops that can occur
    *
    * Different channels were packet dropping can occur.
    */
    enum DropType {
      RAW =     1,
      IGNORED = 2,
      SNIFF =   3,
      MATCH =   4,
      CBOR =    5,
      MAX_SIZE = 6
    };

   /**
    * \brief String literals for logging dropping channels
    */
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

    /**
    * \brief sniffer will be null when called from DNSTAP loop
    */
    BaseSniffers* sniffer_;

    /**
    * \brief the configuration
    */
    const Configuration& config_; 

    /**
    * \struct 
    * \brief pcap stats at timepoint of logging
    */
    struct pcap_stat    pcap_stats_;

    /**
    * \brief pcap stats from previous logging timepoint
    */
    struct pcap_stat    last_log_pcap_stats_;

    /**
    * \brief sniffer stats at timepoint of logging
    */
    BaseSniffers::Stats sniffer_stats_;

    /**
    * \brief sniffer stats from previous logging timepoint
    */
    BaseSniffers::Stats last_log_sniffer_stats_;

    /**
    * \brief sniffer stats from last dropcheck timepoint
    */
    BaseSniffers::Stats last_dropcheck_sniffer_stats_;

    /**
    * \brief packet stats at timepoint of logging
    */
    PacketStatistics& stats_; 

    /**
    * \brief packet stats from previous logging timepoint
    */
    PacketStatistics last_log_stats_;

    /**
    * \brief packet stats from last dropcheck timepoint
    */
    PacketStatistics last_dropcheck_stats_;


    /**
    * \brief flag to indicate if currently in sampling mode
    */
    bool sampling_;

    /**
    * \brief record if sampling threshold was triggered at the last check
    */
    bool trigger_last_check_;

    /**
    * \brief array to track which channels are currenlty dropping
    */
    bool new_drops_[Monitoring::DropType::MAX_SIZE]{};


    /**
    * \brief next time we should inspect the drop stats
    */
    cno::system_clock::time_point next_dropcheck_timestamp_;

    /**
    * \brief time when next log output of stats is due
    */
    cno::system_clock::time_point next_log_timestamp_;

    /**
    * \brief time when last log output of stats was done
    */
    cno::system_clock::time_point last_log_timestamp_;

    /**
    * \brief next time sampling should be stopped 
    */
    cno::system_clock::time_point sampling_end_timestamp_;

    /**
    * \struct 
    * \brief all statistics that can be output by logging
    */
    struct LogStats
    {
        /**
         * \brief total number of packets sniffed.
         */
        unsigned pps;

        /**
        * \brief pcap packets received
        */
        uint64_t pcap_recv;

        /**
        * \brief pcap packets dropped as OS level
        */
        uint64_t pcap_os_drop;

        /**
        * \brief pcap packets dropped at the interface
        */
        uint64_t pcap_if_drop;

        /**
        * \brief sniffer packets received
        */
        uint64_t snif_recv;

        /**
        * \brief sniffer packets dropped
        */
        uint64_t snif_drop;

        /**
        * \brief size of sniffer queue
        */
        unsigned snif_queue;

        /**
        * \brief matcher packets received
        */
        uint64_t matc_recv;

        /**
        * \brief matcher packets dropped
        */
        uint64_t matc_drop;

        /**
        * \brief size of matcher queue
        */
        unsigned matc_queue;

        /**
        * \brief CDNS writer items received
        */
        uint64_t cdns_recv;

        /**
        * \brief CDNS writer items dropped
        */
        uint64_t cdns_drop;

        /**
        * \brief size of CDNS writer queue
        */
        unsigned cdns_queue;

        /**
        * \brief count of CDNS items written
        */
        uint64_t cdns_written;

        /**
        * \brief estimate of % traffic received written to CDNS
        */
        uint64_t cdns_traffic;

        /**
        * \brief count of raw PCAP writer packets dropped
        */
        uint64_t pcap_out_raw_drop;

        /**
        * \brief count of ignored PCAP writer packets dropped
        */
        uint64_t pcap_out_ign_drop;

        /**
        * \brief count of packets dropped by sampling
        */
        uint64_t samp_count;

    };

   /**
    * \brief Calculate the statistics at the given timepoint
    *
    * \param last_recv_timestamp  timepoint of last received packet
    * \param matcher_length       current length of matcher queue
    * \param cbor_length          current lenght of cbor queue
    * \param ls                   struc to write stats into
    */
    void calculate_stats(cno::system_clock::time_point last_recv_timestamp, 
                          unsigned matcher_length, unsigned cbor_length, LogStats& ls);

   /**
    * \brief write the stats to the log in human readable multi line format
    *
    * \param ls struct containing stats
    */
    void write_stats(const LogStats& ls);
    
#ifdef ENABLE_LOGNETWORKSTATSJSON
   /**
    * \brief write the stats to the log in JSON
    *
    * \param ls struct containing stats
    */
    void write_stats_json(const LogStats& ls);
#endif

};

#endif
