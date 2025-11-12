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

#include <iomanip>

#include "log.hpp"
#include "monitoring.hpp"

#ifdef ENABLE_LOGNETWORKSTATSJSON
#include <nlohmann/json.hpp>
#ifdef HAVE_NLOHMANN_ORDERED_MAP_HPP
using json = nlohmann::ordered_json;
#else
using json = nlohmann::json;
#endif
#endif

Monitoring::Monitoring(PacketStatistics& stats, const Configuration& config, BaseSniffers* sniffer_)
                      : sniffer_(sniffer_), config_(config), stats_(stats),
                        sampling_(false), trigger_last_check_(false)
{
    if (sniffer_)
    {
      sniffer_->pcap_stats(pcap_stats_);
      sniffer_->sniffer_stats(sniffer_stats_);
      last_log_pcap_stats_    = pcap_stats_;
      last_log_sniffer_stats_ = last_dropcheck_sniffer_stats_ = sniffer_stats_;
    }
    last_log_stats_         = last_dropcheck_stats_         = stats_;

    last_log_timestamp_ = std::chrono::system_clock::now();
    next_log_timestamp_ = last_log_timestamp_ + std::chrono::seconds(config_.log_network_stats_period);
}

Monitoring::~Monitoring()
{

}

void Monitoring::drop_check(cno::system_clock::time_point last_recv_timestamp)
{
    if (!sniffer_)
      return;

    next_dropcheck_timestamp_ = last_recv_timestamp + std::chrono::seconds(1);

    // Calculate any new drops
    sniffer_->sniffer_stats(sniffer_stats_);
    uint64_t new_sniffs       = sniffer_stats_.pkts_sniffed           - last_dropcheck_sniffer_stats_.pkts_sniffed;
    uint64_t new_sniff_drops  = sniffer_stats_.pkts_dropped           - last_dropcheck_sniffer_stats_.pkts_dropped;
    uint64_t new_raw          = stats_.raw_packet_count               - last_dropcheck_stats_.raw_packet_count;
    uint64_t new_cbor_drops   = stats_.output_cbor_drop_count         - last_dropcheck_stats_.output_cbor_drop_count;
    uint64_t new_match_drops  = stats_.matcher_drop_count             - last_dropcheck_stats_.matcher_drop_count;
    uint64_t new_raw_drops    = stats_.output_raw_pcap_drop_count     - last_dropcheck_stats_.output_raw_pcap_drop_count;
    uint64_t new_ign_drops    = stats_.output_ignored_pcap_drop_count - last_dropcheck_stats_.output_ignored_pcap_drop_count;

    // Update the sniffer drops and pcap stats into the main stats structure
    // here every second (as logging may not be enabled)
    stats_.sniffer_drop_count += new_sniff_drops;
    sniffer_->pcap_stats(pcap_stats_);
    stats_.pcap_recv_count = pcap_stats_.ps_recv;
    stats_.pcap_drop_count = pcap_stats_.ps_drop;
    stats_.pcap_ifdrop_count = pcap_stats_.ps_ifdrop;

    // REPORT ANY DROPS
    log_drops_change(new_raw_drops   > 0 , DropType::RAW);
    log_drops_change(new_ign_drops   > 0 , DropType::IGNORED);
    log_drops_change(new_sniff_drops > 0 , DropType::SNIFF);
    log_drops_change(new_match_drops > 0 , DropType::MATCH);
    log_drops_change(new_cbor_drops  > 0 , DropType::CBOR);

    // SAMPLING ON/OFF CALCULATIONS
    // Now check if we should trigger sampling based on drops and config parameters
    bool sniff_samp_trigger = new_sniff_drops > new_sniffs * (config_.sampling_threshold/100.0);
    bool cbor_samp_trigger  = new_cbor_drops  > new_raw    * (config_.sampling_threshold/100.0);
    bool match_samp_trigger = new_match_drops > new_raw    * (config_.sampling_threshold/100.0);
    if ( sniff_samp_trigger || cbor_samp_trigger || match_samp_trigger) {
        if (config_.sampling_rate > 0) {
            if ( !sampling_ ) {
                if (!trigger_last_check_ ) {
                    // register the trigger and wait for next check
                    trigger_last_check_ = true;
                } else {
                    // switch sampling on
                    sampling_ = true;
                    sampling_end_timestamp_ = last_recv_timestamp + std::chrono::seconds(config_.sampling_time);
                    LOG_WARN << "Sampling mode switched on for " << config_.sampling_time 
                             << "s with rate of 1 in " << config_.sampling_rate << " as dropping above threshold % of "
                             << config_.sampling_threshold;
                }
            }
            // sampling but still dropping, push the end of the timer out
            else if ( sampling_end_timestamp_ <= last_recv_timestamp ) {
                sampling_end_timestamp_ = last_recv_timestamp + std::chrono::seconds(config_.sampling_time);
                LOG_WARN << "Sampling mode extended as drops still occurring";
            } 
        }
    // Not now dropping in sampling mode, turn sampling off it timer has expired
    } else if ( sampling_ && sampling_end_timestamp_ <= last_recv_timestamp ) {
        sampling_ = false;
        trigger_last_check_ = false;
        LOG_WARN << "Sampling mode switched off because time limit expired and not dropping above threshold.";
    }

    last_dropcheck_sniffer_stats_ = sniffer_stats_;
    last_dropcheck_stats_         = stats_;
}

// void Monitoring::log_drops_check(bool new_drops, DropType type){
//
// }

void Monitoring::log_stats(cno::system_clock::time_point last_recv_timestamp, unsigned matcher_length, unsigned cbor_length)
{
    LogStats ls;
    calculate_stats(last_recv_timestamp, matcher_length, cbor_length, ls);
#ifdef ENABLE_LOGNETWORKSTATSJSON
    if (config_.log_network_stats_json)
        write_stats_json(ls);
    else
#endif
        write_stats(ls);
}

void Monitoring::calculate_stats(cno::system_clock::time_point last_recv_timestamp, 
                                  unsigned matcher_length, unsigned cbor_length, LogStats& ls)
{
    cno::seconds period = cno::duration_cast<cno::seconds>(last_recv_timestamp - last_log_timestamp_);
    ls.matc_recv  = stats_.raw_packet_count   - last_log_stats_.raw_packet_count;
    ls.matc_drop  = stats_.matcher_drop_count - last_log_stats_.matcher_drop_count;
    ls.matc_queue = matcher_length;

    if (config_.sampling_rate > 0)
        ls.samp_count = stats_.discarded_sampling_count  - last_log_stats_.discarded_sampling_count;

    ls.cdns_recv    = stats_.processed_message_count - last_log_stats_.processed_message_count;
    ls.cdns_drop    = stats_.output_cbor_drop_count  - last_log_stats_.output_cbor_drop_count;
    ls.cdns_queue   = cbor_length;
    ls.cdns_written = std::max(int(ls.cdns_recv - ls.cdns_drop), 0);

    if (sniffer_)
    {
        sniffer_->pcap_stats(pcap_stats_);
        ls.pps          = (pcap_stats_.ps_recv  - last_log_pcap_stats_.ps_recv) / period.count();
        ls.pcap_recv    = pcap_stats_.ps_recv   - last_log_pcap_stats_.ps_recv;
        ls.pcap_os_drop = pcap_stats_.ps_drop   - last_log_pcap_stats_.ps_drop;
        ls.pcap_if_drop = pcap_stats_.ps_ifdrop - last_log_pcap_stats_.ps_ifdrop;

        sniffer_->sniffer_stats(sniffer_stats_);
        ls.snif_recv  = sniffer_stats_.pkts_sniffed - last_log_sniffer_stats_.pkts_sniffed;
        ls.snif_drop  = sniffer_stats_.pkts_dropped - last_log_sniffer_stats_.pkts_dropped;
        ls.snif_queue = sniffer_stats_.channel_length;

        ls.pcap_out_raw_drop = stats_.output_raw_pcap_drop_count     - last_log_stats_.output_raw_pcap_drop_count;
        ls.pcap_out_ign_drop = stats_.output_ignored_pcap_drop_count - last_log_stats_.output_ignored_pcap_drop_count;

        if (ls.cdns_written != 0 && ls.pcap_recv != 0)
            ls.cdns_traffic = std::min(int(std::lround(ls.cdns_written * 100.0 / ls.pcap_recv )), 100);
        else
          ls.cdns_traffic = 0;
        last_log_pcap_stats_    = pcap_stats_;
        last_log_sniffer_stats_ = sniffer_stats_;
    } 
    else
    {
         ls.pps = (stats_.raw_packet_count - last_log_stats_.raw_packet_count) / period.count();
         if (ls.cdns_written != 0 && ls.cdns_recv != 0)
             ls.cdns_traffic = std::min(int(std::lround(ls.cdns_written * 100.0 / ls.cdns_recv )), 100);
         else
           ls.cdns_traffic = 0;
    }
    last_log_stats_     = stats_;
    last_log_timestamp_ = last_recv_timestamp;
    next_log_timestamp_ = last_log_timestamp_ + cno::seconds(config_.log_network_stats_period);

}

void Monitoring::write_stats(const LogStats& ls)
{
    //output width, big enough for interval numbers up to 5 billion pps
    int w = 10;
    LOG_INFO << "*Stats interval: average rate     " << std::setw(w) 
         << ls.pps << " pps  over  "
         << config_.log_network_stats_period << "s";
    if (sniffer_)
    {
        LOG_INFO << " LIBPCAP : recv/OS drop/IF drop   " << std::setw(w)
                 << ls.pcap_recv    << "/" << std::setw(w)
                 << ls.pcap_os_drop << "/" << std::setw(w)
                 << ls.pcap_if_drop;
        LOG_INFO << " Sniffer : recv/dropped/queue     " << std::setw(w)
                 << ls.snif_recv << "/"  << std::setw(w)
                 << ls.snif_drop << "/"  << std::setw(w)
                 << ls.snif_queue;
    }
    LOG_INFO << " Matcher : recv/dropped/queue     " << std::setw(w)
             << ls.matc_recv << "/" << std::setw(w)
             << ls.matc_drop << "/" << std::setw(w)
             << ls.matc_queue;
    if (config_.sampling_rate > 0) 
    {
        const char* sampling_text = sampling_? "ON":"OFF";
        LOG_INFO << " Sampling: recv/discard/state     " << std::setw(w)
                 << ls.matc_recv  << "/" << std::setw(w)
                 << ls.samp_count << "/" << std::setw(w)
                 << sampling_text;
    }
    LOG_INFO << " CDNS    : recv/dropped/queue     " << std::setw(w)
             << ls.cdns_recv << "/" << std::setw(w)
             << ls.cdns_drop << "/" << std::setw(w)
             << ls.cdns_queue;
    LOG_INFO << " CDNS out: writ/% traffic         " << std::setw(w)
             << ls.cdns_written << "/" << std::setw(w)
             << ls.cdns_traffic << "/" << std::setw(w)
             << "";
    if (sniffer_)
    {
        LOG_INFO << " PCAP out: raw drop/ignored drop  " << std::setw(w)
                 << ls.pcap_out_raw_drop  << "/"  << std::setw(w)
                 << ls.pcap_out_ign_drop  << "/"  << std::setw(w);
        LOG_INFO << "";
    }
}

#ifdef ENABLE_LOGNETWORKSTATSJSON
void Monitoring::write_stats_json(const LogStats& ls)
{
    json data;
    data = { {"ave_rate", ls.pps},
             {"stats_interval", config_.log_network_stats_period} };
    if (sniffer_)
    {
        data["libpcap"] = { {"recv",    ls.pcap_recv}, 
                            {"os_drop", ls.pcap_os_drop},
                            {"if_drop", ls.pcap_if_drop} };
        data["sniffer"] = { {"recv",    ls.snif_recv},
                            {"drop",    ls.snif_drop},
                            {"queue",   ls.snif_queue} };
        }
    data["matcher"] = { {"recv",    ls.matc_recv},
                        {"drop",    ls.matc_drop},
                        {"queue",   ls.matc_queue} };
    if (config_.sampling_rate > 0)
    {
        const char* sampling_text = sampling_? "ON":"OFF";
        data["sampling"] = { {"recv",    ls.matc_recv},
                             {"discard", ls.samp_count},
                             {"state",   sampling_text} };
    }
    data["cdns"] = { {"recv",  ls.cdns_recv}, 
                     {"drop",  ls.cdns_drop},
                     {"queue", ls.cdns_queue}};
    data["cdns_out"] = { {"written",          ls.cdns_written}, 
                         {"percent_traffic",  ls.cdns_traffic}};
    if (sniffer_)
    {
        data["pcap_out"] = { {"raw_drop",     ls.pcap_out_raw_drop}, 
                             {"ignored_drop", ls.pcap_out_ign_drop}};
    }
    json stats( { {"Stats", data} } );
    LOG_INFO << stats.dump();
}
#endif