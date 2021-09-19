/*
 * Copyright 2016-2021 Internet Corporation for Assigned Names and Numbers.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Developed by Sinodun IT (www.sinodun.com)
 */

#include <algorithm>
#include <chrono>
#include <csignal>
#include <exception>
#include <fstream>
#include <memory>
#include <thread>
#include <iomanip>

#include <pthread.h>

#include <boost/asio.hpp>
#include <boost/variant.hpp>

#include <tins/network_interface.h>
#include <tins/tins.h>

#include <pcap/pcap.h>

#include "config.h"

#if ENABLE_DNSTAP
#include <google/protobuf/stubs/common.h>
#endif

#include "addressevent.hpp"
#include "channel.hpp"
#include "blockcborwriter.hpp"
#include "configuration.hpp"
#include "dnstap.hpp"
#include "log.hpp"
#include "makeunique.hpp"
#include "matcher.hpp"
#include "packetstream.hpp"
#include "pcapwriter.hpp"
#include "queryresponse.hpp"
#include "signalhandler.hpp"
#include "sniffers.hpp"
#include "streamwriter.hpp"
#include "util.hpp"

const std::string PROGNAME = "compactor";

namespace al = boost::asio::local;
namespace po = boost::program_options;
namespace cno = std::chrono;

/**
 * \brief A do-nothing signal handler.
 *
 * \param sig   the signal.
 */
static void sighandler_empty(int /* sig */)
{
}

/**
 * \typedef CborItemPayload
 * \brief A varient type for the different items to be written to C-DNS.
 */
using CborItemPayload = boost::variant<std::shared_ptr<QueryResponse>, std::shared_ptr<AddressEvent>>;

/**
 * \struct CborItem
 * \brief Structure holding an item to be written to C-DNS plus the statistics
 * as at the time of that item.
 */
struct CborItem
{
    /**
     * \brief Constructor for query/response.
     */
    CborItem(const std::shared_ptr<QueryResponse>& qr, const PacketStatistics& stats)
        : payload(qr), stats(stats) {}

    /**
     * \brief Constructor for address event.
     */
    CborItem(const std::shared_ptr<AddressEvent>& ae, const PacketStatistics& stats)
        : payload(ae), stats(stats) {}

    /**
     * \brief Empty constructor.
     */
    CborItem() {}

    /**
     * \brief the item data.
     */
    CborItemPayload payload;

    /**
     * \brief the statistics as at the time of the item.
     */
    PacketStatistics stats;
};

/**
 * \struct OutputChannels
 * \brief Shared pointers to output channels for a run.
 *
 * The channels are created in the main thread. Shared pointers are
 * passed to the output threads, and the channel is deleted when the
 * last of the output thread or the main thread exits.
 */
struct OutputChannels
{
    /**
     * \brief Constructor.
     */
    OutputChannels()
        :raw_pcap(std::make_shared<Channel<std::shared_ptr<PcapItem>>>()),
         ignored_pcap(std::make_shared<Channel<std::shared_ptr<PcapItem>>>()),
         cbor(std::make_shared<Channel<CborItem>>())
    {
    }

    /**
     * \brief Channel for sending packets to raw pcap output thread.
     */
    std::shared_ptr<Channel<std::shared_ptr<PcapItem>>> raw_pcap;

    /**
     * \brief Channel for sending packets to ignored pcap output thread.
     */
    std::shared_ptr<Channel<std::shared_ptr<PcapItem>>> ignored_pcap;

    /**
     * \brief Channel for sending items to be written to C-DNS output thread.
     */
    std::shared_ptr<Channel<CborItem>> cbor;
};

/**
 * \brief Main function for threads writing PCAP files.
 *
 * \param name the thread name.
 * \param out  the output destination.
 * \param chan the channel to receive packets from.
 */
static void packet_writer(const char* name,
                          std::unique_ptr<PcapBaseRotatingWriter> out,
                          std::shared_ptr<Channel<std::shared_ptr<PcapItem>>> chan,
                          const Configuration& config)
{
    set_thread_name(name);

    std::shared_ptr<PcapItem> pcap;
    while ( chan->get(pcap) )
    {
        try
        {
            out->write_packet(*(pcap->pdu), pcap->timestamp, config);
        }
        catch (const std::exception& err)
        {
            LOG_ERROR << err.what();
        }
    }
}

/**
 * \class CborItemVisitor
 * \brief Visitor for applying appropriate action to a CBorItem.
 */
class CborItemVisitor : public boost::static_visitor<>
{
public:
    /**
     * \brief Constructor.
     *
     * \param out the output writer.
     */
    explicit CborItemVisitor(std::unique_ptr<BlockCborWriter>& out)
        : out_(std::move(out)), stats_() {}

    /**
     * \brief Process a query/response.
     */
    void operator()(const std::shared_ptr<QueryResponse>& qr)
    {
        out_->writeQR(qr, *stats_);
    }

    /**
     * \brief Process an address event.
     */
    void operator()(const std::shared_ptr<AddressEvent>& ae)
    {
        out_->writeAE(ae, *stats_);
    }

    /**
     * \brief Set the statistics current for the next data.
     */
    void set_stats(const PacketStatistics* stats)
    {
        stats_ = stats;
    }

private:
    /**
     * \brief the output writer.
     */
    std::unique_ptr<BlockCborWriter> out_;

    /**
     * \brief statistics for the next item to write.
     */
    const PacketStatistics* stats_;
};

/**
 * \brief Main function for thread writing C-DNS files.
 *
 * \param out the output destination.
 * \param chan the channel to receive packets from.
 */
static void cbor_writer(std::unique_ptr<BlockCborWriter> out,
                        std::shared_ptr<Channel<CborItem>> chan)
{
    set_thread_name("comp:cdns-write");

    CborItemVisitor cbiv(out);
    CborItem cbi;
    while ( chan->get(cbi) )
    {
        try
        {
            cbiv.set_stats(&cbi.stats);
            boost::apply_visitor(cbiv, cbi.payload);
        }
        catch (const std::exception& err)
        {
            LOG_ERROR << err.what();
        }
    }
}

/**
 * \brief The main network capture loop. Read packets from the sniffer
 * and process them.
 *
 * Outputs are sent down one of the output channels.
 *
 * The loop continues until the sniffer reports EOF.
 *
 * \param sniffer the Tins sniffer to read.
 * \param matcher the query/response matcher to use.
 * \param output  the output channels.
 * \param config  the current configuration.
 * \param stats   collect packet statistics here.
 */
static void sniff_loop(BaseSniffers* sniffer,
                       QueryResponseMatcher& matcher,
                       OutputChannels& output,
                       const Configuration& config,
                       PacketStatistics& stats)
{
    bool seen_raw_overflow = false;
    bool seen_ignored_overflow = false;

    bool do_raw_pcap = !config.raw_pcap_pattern.empty();
    bool do_ignored_pcap = !config.ignored_pcap_pattern.empty();
    bool do_decode = config.debug_qr || config.debug_dns || config.report_info  || !config.output_pattern.empty();
    bool do_match = config.debug_qr || config.report_info || !config.output_pattern.empty();

    cno::system_clock::time_point last_recv_timestamp;       // timestamp of last recieved packet
    cno::system_clock::time_point next_statslog_timestamp;   // time when next log output of stats is due
    cno::system_clock::time_point last_statslog_timestamp;   // time when last log output of stats was done
    cno::system_clock::time_point next_drop_check_timestamp; // next time we should inspect the drop stats
    cno::system_clock::time_point sampling_end_timestamp;    // next time sampling should be stopped 

    PacketStatistics last_stats = stats;
    PacketStatistics last_drop_check_stats = stats;

    struct pcap_stat last_pcap_stats;
    sniffer->pcap_stats(last_pcap_stats);

    BaseSniffers::Stats sniffer_stats;
    BaseSniffers::Stats last_sniffer_stats;
    sniffer->sniffer_stats(last_sniffer_stats);
    BaseSniffers::Stats last_drop_check_sniffer_stats = last_sniffer_stats;

    bool drops_last_check = false;
    bool sampling = false;

    auto dns_sink =
        [&](std::unique_ptr<DNSMessage>& dns)
        {
            ++stats.processed_message_count;

            if ( config.debug_dns )
                std::cout << *dns;

            if ( do_match )
                matcher.add(std::move(dns));
        };

    auto address_event_sink =
        [&](const std::shared_ptr<AddressEvent>& event)
        {
            if ( !config.output_pattern.empty() )
            {
                CborItem cbi(event, stats);
                if ( !output.cbor->put(cbi, false) )
                {
                    ++stats.output_cbor_drop_count;
                }
            }
        };

    auto ignored_sink =
        [&](const std::shared_ptr<PcapItem>& pcap)
        {
            if ( do_ignored_pcap )
            {
                if ( !output.ignored_pcap->put(pcap, false) )
                {
                    ++stats.output_ignored_pcap_drop_count;
                    if ( !seen_ignored_overflow )
                    {
                        LOG_ERROR << "Dropping on these channels: Ignored PCAP";
                        seen_ignored_overflow = true;
                    }
                }
            }
        };

    PacketStream packet_stream(config, dns_sink, address_event_sink);

    for (;;)
    {
        Tins::Packet pkt(sniffer->next_packet());
        if ( !pkt.pdu() )
            break;

        // Get the PDU controlled by a shared_ptr. This will avoid the need
        // to copy it.
        std::shared_ptr<PcapItem> pcap = std::make_shared<PcapItem>(pkt);

        ++stats.raw_packet_count;

        if ( last_recv_timestamp > pcap->timestamp )
            ++stats.out_of_order_packet_count;
        last_recv_timestamp = pcap->timestamp;

        if ( do_raw_pcap )
        {
            if ( !output.raw_pcap->put(pcap, false) )
            {
                ++stats.output_raw_pcap_drop_count;
                if ( !seen_raw_overflow )
                {
                    LOG_ERROR << "Dropping on these channels: Raw PCAP";
                    seen_raw_overflow = true;
                }
            }
        }


        if (matcher.get_length() > (config.max_channel_size * 2)) {
            ++stats.matcher_drop_count;
            matcher.poke(pcap->timestamp);
        }
        // If we're dropping packets, respond by sampling. 
        else if ( sampling && (stats.raw_packet_count % config.sampling_rate) != 0 ) {
            ++stats.discarded_sampling_count;
        } 
        else {
            if ( do_decode )
            {
                bool ignored = false;

                try
                {
                    packet_stream.process_packet(pcap);
                }
                catch (const unhandled_packet& e)
                {
                    ignored = true;
                    ++stats.unhandled_packet_count;
                }
                catch (const malformed_packet& e)
                {
                    ignored = true;
                    ++stats.malformed_message_count;
                }

                if ( ignored )
                    ignored_sink(pcap);
            }
        }

        // SAMPLING - check for drops or timeout on sampling mode very second
        // Also update the stats from sniffer/pcap here from sniffer thread.
        if ( next_drop_check_timestamp <= last_recv_timestamp )
        {
            next_drop_check_timestamp = last_recv_timestamp + std::chrono::seconds(1);
            sniffer->sniffer_stats(sniffer_stats);
            seen_raw_overflow = seen_ignored_overflow = false;

            uint64_t new_sniffs       = sniffer_stats.pkts_sniffed   - last_drop_check_sniffer_stats.pkts_sniffed;
            uint64_t new_raw          = stats.raw_packet_count       - last_drop_check_stats.raw_packet_count;
            uint64_t new_sniff_drops  = sniffer_stats.pkts_dropped   - last_drop_check_sniffer_stats.pkts_dropped;
            uint64_t new_cbor_drops   = stats.output_cbor_drop_count - last_drop_check_stats.output_cbor_drop_count;
            bool sniff_dropping = new_sniff_drops > new_sniffs * (config.sampling_threshold/100.0);
            bool cbor_dropping  = new_cbor_drops  > new_raw    * (config.sampling_threshold/100.0);

            // If seeing drops, only trigger off these two queues for now
            if ( new_sniff_drops > 0 || new_cbor_drops > 0 )
            {             
                LOG_ERROR << "Dropping on these channels: " << (new_sniff_drops!=0?"Sniffer ":"")
                                                            << (new_cbor_drops!=0?"C-DNS":"");
            }
            if ( sniff_dropping || cbor_dropping ) {
                if (config.sampling_rate > 0) {
                    if ( !sampling ) {
                        if (!drops_last_check ) {
                            // register the drops and wait for next check
                            drops_last_check = true;
                        } else {
                            sampling = true;
                            sampling_end_timestamp = last_recv_timestamp + std::chrono::seconds(config.sampling_time);
                            LOG_WARN << "Sampling mode switched on for " << config.sampling_time 
                                     << "s with rate of 1 in " << config.sampling_rate << " as dropping above threshold % of "
                                     << config.sampling_threshold;
                        }
                    }
                    // sampling but still dropping, push the end of the timer out
                    else if ( sampling_end_timestamp <= last_recv_timestamp ) {
                        sampling_end_timestamp = last_recv_timestamp + std::chrono::seconds(config.sampling_time);
                        LOG_WARN << "Sampling mode extended as drops still occurring";
                    } 
                }
            } else if ( sampling && sampling_end_timestamp <= last_recv_timestamp ) {
                sampling = false;
                drops_last_check = false;
                LOG_WARN << "Sampling mode switched off because time limit expired and not dropping above threshold.";
            }

            // Retrieve PCAP stats, if available.
            struct pcap_stat pcap_stat;
            if ( sniffer->pcap_stats(pcap_stat) )
            {
                stats.pcap_recv_count = pcap_stat.ps_recv;
                stats.pcap_drop_count = pcap_stat.ps_drop;
                stats.pcap_ifdrop_count = pcap_stat.ps_ifdrop;
            }
            // Update the number of drops in the sniffer to the stats
            stats.sniffer_drop_count += new_sniff_drops;
            last_drop_check_sniffer_stats = sniffer_stats;
            last_drop_check_stats = last_stats;
        }


        // Output interval stats to log
        if ( config.log_network_stats_period > 0 )
        {
            if ( next_statslog_timestamp.time_since_epoch().count() == 0 )
            {
                next_statslog_timestamp = last_recv_timestamp + std::chrono::seconds(config.log_network_stats_period);
                last_statslog_timestamp = last_recv_timestamp;
            }
            else if ( next_statslog_timestamp <= last_recv_timestamp )
            {
                int w = 10; //output width, big enough for interval numbers up to 5 billion pps
                cno::seconds period = cno::duration_cast<cno::seconds>(last_recv_timestamp - last_statslog_timestamp);

                struct pcap_stat pcap_stats;
                sniffer->pcap_stats(pcap_stats);
                LOG_INFO << "*Stats interval: average rate     " << std::setw(w) 
                     << (pcap_stats.ps_recv   - last_pcap_stats.ps_recv) / period.count() << " pps  over  "
                     << config.log_network_stats_period << "s";

                // Output stats directly from libpcap
                LOG_INFO << " LIBPCAP : recv/OS drop/IF drop   "                  << std::setw(w)
                         << pcap_stats.ps_recv   - last_pcap_stats.ps_recv << "/" << std::setw(w)
                         << pcap_stats.ps_drop   - last_pcap_stats.ps_drop << "/" << std::setw(w)
                         << pcap_stats.ps_ifdrop - last_pcap_stats.ps_ifdrop;
                // Output info from PacketStatists and the sniffer for this interval
                sniffer->sniffer_stats(sniffer_stats);
                LOG_INFO << " Sniffer : recv/dropped/queue     "                                 << std::setw(w)
                         << sniffer_stats.pkts_sniffed - last_sniffer_stats.pkts_sniffed << "/"  << std::setw(w)
                         << sniffer_stats.pkts_dropped - last_sniffer_stats.pkts_dropped << "/"  << std::setw(w)
                         << sniffer_stats.channel_length;
                LOG_INFO << " Matcher : recv/dropped/queue     "                         << std::setw(w)
                         << (stats.raw_packet_count  - last_stats.raw_packet_count)      << "/" << std::setw(w)
                         << stats.matcher_drop_count - last_stats.matcher_drop_count     << "/" << std::setw(w)
                         << matcher.get_length();
                const char* sampling_text = sampling? "ON":"OFF";
                if (config.sampling_rate > 0) {
                    LOG_INFO << " Sampling: recv/discard/state     "                                   << std::setw(w)
                             << (stats.raw_packet_count         - last_stats.raw_packet_count)         << "/" << std::setw(w)
                             << stats.discarded_sampling_count  - last_stats.discarded_sampling_count  << "/" << std::setw(w)
                             << sampling_text;
                }
                LOG_INFO << " CDNS    : recv/dropped/queue     "                                       << std::setw(w)
                         << stats.processed_message_count - last_stats.processed_message_count  << "/" << std::setw(w)
                         << stats.output_cbor_drop_count  - last_stats.output_cbor_drop_count   << "/" << std::setw(w)
                         << output.cbor->get_length();
                uint64_t cdns_written = (stats.processed_message_count - last_stats.processed_message_count) -
                                        (stats.output_cbor_drop_count  - last_stats.output_cbor_drop_count);
                int tp = std::lround(cdns_written * 100.0 / (pcap_stats.ps_recv   - last_pcap_stats.ps_recv));
                LOG_INFO << " CDNS out: writ/% traffic         "                                       << std::setw(w)
                         << cdns_written        << "/" << std::setw(w)
                         << std::min(tp, 100)   << "/" << std::setw(w)
                         << "";
                LOG_INFO << " PCAP out: raw drop/ignored drop  "                                                     << std::setw(w)
                         << stats.output_raw_pcap_drop_count     - last_stats.output_raw_pcap_drop_count     << "/"  << std::setw(w)
                         << stats.output_ignored_pcap_drop_count - last_stats.output_ignored_pcap_drop_count << "/"  << std::setw(w);
                LOG_INFO << "";

                // Update time/state
                next_statslog_timestamp = last_recv_timestamp + cno::seconds(config.log_network_stats_period);
                last_statslog_timestamp = last_recv_timestamp;
                last_stats          = stats;
                last_pcap_stats     = pcap_stats;
                last_sniffer_stats = sniffer_stats;
            }
        }
    }

}

#if ENABLE_DNSTAP
/**
 * \brief The main DNSTAP loop. Read packets from the input stream
 * and process them.
 *
 * Received DNS messages are sent to the matcher.
 *
 * The loop continues until the stream reports EOF.
 *
 * \param dnstap  the DNSTAP processor.
 * \param stream  the input stream to read.
 * \param matcher the query/response matcher to use.
 * \param config  the current configuration.
 * \param stats   collect packet statistics here.
 */
static void tap_loop(DnsTap& dnstap,
                     std::iostream& stream,
                     QueryResponseMatcher& matcher,
                     const Configuration& config,
                     PacketStatistics& stats)
{
    cno::system_clock::time_point last_recv_timestamp;
    cno::system_clock::time_point next_statslog_timestamp;
    cno::system_clock::time_point last_statslog_timestamp;
    PacketStatistics last_stats = stats;

    auto sink = [&](std::unique_ptr<DNSMessage>& dns)
    {
        ++stats.raw_packet_count;
        ++stats.processed_message_count;
        if ( last_recv_timestamp > dns->timestamp )
            ++stats.out_of_order_packet_count;
        stats.malformed_message_count = dnstap.malformed_message_count();
        last_recv_timestamp = dns->timestamp;
        if ( config.debug_dns )
            std::cout << *dns;
        matcher.add(std::move(dns));

        if ( config.log_network_stats_period > 0 )
        {
            if ( next_statslog_timestamp.time_since_epoch().count() == 0 )
            {
                next_statslog_timestamp = last_recv_timestamp + std::chrono::seconds(config.log_network_stats_period);
                last_statslog_timestamp = last_recv_timestamp;
            }
            else if ( next_statslog_timestamp <= last_recv_timestamp )
            {
                cno::seconds period = cno::duration_cast<cno::seconds>(last_recv_timestamp - last_statslog_timestamp);

                LOG_INFO << "*Stats interval: average rate  " << std::setw(10) 
                     << (stats.raw_packet_count        - last_stats.raw_packet_count) / period.count() << " pps  over  "
                     << config.log_network_stats_period << "s";
                LOG_INFO << " C-DNS   : recv/dropped        "                                          << std::setw(10)   
                         << stats.processed_message_count - last_stats.processed_message_count  << "/" << std::setw(10)   
                         << stats.output_cbor_drop_count  - last_stats.output_cbor_drop_count   << "/" << std::setw(10);
                next_statslog_timestamp = last_recv_timestamp + cno::seconds(config.log_network_stats_period);
                last_statslog_timestamp = last_recv_timestamp;
                last_stats = stats;
            }
        }
    };

    dnstap.process_stream(stream, sink);

    // In case last message was malformed, ensure count is correct.
    stats.malformed_message_count = dnstap.malformed_message_count();
}
#endif

/**
 * \brief Create an output PCAP writer with configured compression options.
 *
 * \param fname  filename pattern.
 * \param config configuration.
 * \returns pointer to new writer.
 */
static std::unique_ptr<PcapBaseRotatingWriter> make_pcap_writer(const std::string& pattern, const Configuration& config)
{
    if ( config.xz_pcap )
        return make_unique<PcapRotatingWriter<XzStreamWriter>>(pattern,
                                                               std::chrono::seconds(config.rotation_period),
                                                               config.xz_preset_pcap,
                                                               config.snaplen);
    else if ( config.gzip_pcap )
        return make_unique<PcapRotatingWriter<GzipStreamWriter>>(pattern,
                                                                 std::chrono::seconds(config.rotation_period),
                                                                 config.gzip_level_pcap,
                                                                 config.snaplen);
    else
        return make_unique<PcapRotatingWriter<StreamWriter>>(pattern,
                                                             std::chrono::seconds(config.rotation_period),
                                                             0,
                                                             config.snaplen);
}

/**
 * \brief Do a collection run using the given configuration.
 *
 * \param vm          the configuration variable map.
 * \param config      the configuration values.
 * \param threads     a vector for all program threads.
 * \param writer_pool pool of compression threads.
 * \returns 0 on normal exit, 1 on SIGHUP, 2 on SIGINT, 3 on sniffer error.
 */
static int run_configuration(const po::variables_map& vm,
                             const Configuration& config,
                             std::vector<std::thread>& threads,
                             std::shared_ptr<BaseParallelWriterPool> writer_pool)
{
    // Output channels for this run.
    OutputChannels output;
    bool live_capture = false;

    // Signal handling.
    SignalHandler signal_handler({SIGPIPE, SIGINT, SIGTERM, SIGHUP});
    int signal_received = 0;

    // Set output limits only when we're capturing. If we set them
    // when reading from a capture, we'll just lose items from the
    // capture as we read from the capture at full throttle.
    if ( !vm.count("capture-file") )
    {
        live_capture = true;
        output.raw_pcap->set_max_items(config.max_channel_size);
        output.ignored_pcap->set_max_items(config.max_channel_size);
        output.cbor->set_max_items(config.max_channel_size);
    }


    if ( vm.count("raw-pcap") &&
         !config.raw_pcap_pattern.empty() )
    {
        std::unique_ptr<PcapBaseRotatingWriter> raw_pcap =
            make_pcap_writer(config.raw_pcap_pattern, config);
        threads.emplace_back(packet_writer, "comp:raw-pcap", std::move(raw_pcap), output.raw_pcap, std::ref(config));
    }

    if ( vm.count("ignored-pcap") &&
         !config.ignored_pcap_pattern.empty() )
    {
        std::unique_ptr<PcapBaseRotatingWriter> ignored_pcap =
            make_pcap_writer(config.ignored_pcap_pattern, config);
        threads.emplace_back(packet_writer, "comp:ign-pcap", std::move(ignored_pcap), output.ignored_pcap, std::ref(config));
    }

    if ( vm.count("output") && !config.output_pattern.empty() )
    {
        std::unique_ptr<CborBaseStreamFileEncoder> encoder;
        encoder = make_unique<CborParallelStreamFileEncoder>(writer_pool);

        std::unique_ptr<BlockCborWriter> cbor =
            make_unique<BlockCborWriter>(config, std::move(encoder), live_capture);
        threads.emplace_back(cbor_writer, std::move(cbor), output.cbor);
    }

    SniffersConfiguration sniff_config;
    sniff_config.set_snap_len(config.snaplen);
    sniff_config.set_promisc_mode(config.promisc_mode);
    sniff_config.set_timeout(1);                // Copy DSC Collector.
    if ( vm.count("filter") )
        sniff_config.set_filter(config.filter);
    sniff_config.set_chan_max_size(config.max_channel_size);

    PacketStatistics stats{};

    QueryResponseMatcher matcher(
        [&](std::shared_ptr<QueryResponse> qr)
        {
            if ( qr->has_query() )
            {
                if ( !qr->has_response() )
                    ++stats.query_without_response_count;
                else
                    ++stats.qr_pair_count;
            }
            else
                ++stats.response_without_query_count;

            if ( config.debug_qr )
                std::cout << *qr;
            if ( !config.output_pattern.empty() )
            {
                CborItem cbi(qr, stats);
                if ( !output.cbor->put(cbi, false) )
                {
                    ++stats.output_cbor_drop_count;
                }
            }
        });
    matcher.set_query_timeout(config.query_timeout);
    matcher.set_skew_timeout(config.skew_timeout);

    // We assume that network or DNSTAP capture is typically a daemon
    // process, and log errors. File conversion, on the other hand,
    // is typically a manual process, and so errors go to stderr.
    bool log_errs = ( !vm.count("capture-file") );
    int res = 0;
#if ENABLE_DNSTAP
    DnsTap dnstap;
#endif

    try
    {
        if ( !vm.count("capture-file") )
        {
#if ENABLE_DNSTAP
            if ( vm.count("dnstap-socket") )
            {
                LOG_INFO << "Starting DNSTAP capture";
                std::remove(config.dnstap_socket.c_str());
                boost::asio::io_service service;
                al::stream_protocol::endpoint endpoint(config.dnstap_socket);
                al::stream_protocol::acceptor acceptor(service, endpoint);
                set_file_owner_perms(config.dnstap_socket,
                                     config.dnstap_socket_owner,
                                     config.dnstap_socket_group,
                                     config.dnstap_socket_write);
                al::stream_protocol::iostream stream;

                // To stop any ongoing reads blocked waiting for the network,
                // signal this thread with SIGUSR2, handled with an empty
                // handler.
                pthread_t my_thread = ::pthread_self();
                std::signal(SIGUSR2, sighandler_empty);

                signal_handler.add_handler(
                    [&](int signal)
                    {
                        signal_received = signal;
                        dnstap.breakloop();
                        acceptor.cancel();
                        service.stop();
                        ::pthread_kill(my_thread, SIGUSR2);
                    });

                std::function<void (const boost::system::error_code&)> handle_accept = [&](const boost::system::error_code&)
                {
                    if ( signal_received == 0 )
                        tap_loop(dnstap, stream, matcher, config, stats);
                    acceptor.async_accept(*stream.rdbuf(), handle_accept);
                };
                acceptor.async_accept(*stream.rdbuf(), handle_accept);
                while ( signal_received == 0 )
                    service.run_one();
            }
            else
#endif
            {
                LOG_INFO << "Starting network capture";
                NetworkSniffers sniffer(config.network_interfaces, sniff_config);
                signal_handler.add_handler(
                    [&](int signal)
                    {
                        signal_received = signal;
                        sniffer.breakloop();
                    });
                sniff_loop(&sniffer, matcher, output, config, stats);
            }
        }
        else
        {
            for ( const auto& fname : vm["capture-file"].as<std::vector<std::string>>() )
            {
#if ENABLE_DNSTAP
                if ( vm.count("dnstap") )
                {
                    std::fstream stream(fname, std::ios::binary | std::ios::in);
                    if ( stream.is_open() )
                    {
                        signal_handler.add_handler(
                            [&](int signal)
                            {
                                signal_received = signal;
                                dnstap.breakloop();
                            });
                        tap_loop(dnstap, stream, matcher, config, stats);
                    }
                    else
                        std::cerr << "Failed to open " << fname << std::endl;
                }
                else
#endif
                {
                    FileSniffer sniffer(fname, sniff_config);
                    signal_handler.add_handler(
                        [&](int signal)
                        {
                            signal_received = signal;
                            sniffer.breakloop();
                        });
                    sniff_loop(&sniffer, matcher, output, config, stats);
                }
                if ( signal_received != 0 )
                    break;
            }
        }
    }
    catch (const Tins::pcap_error& err)
    {
        if ( log_errs )
            LOG_ERROR << "PCAP Error: " << err.what();
        else
            std::cerr << "PCAP Error: " << err.what() << std::endl;
        res = 3;
    }
    catch (const Tins::invalid_pcap_filter& err)
    {
        if ( log_errs )
            LOG_ERROR << "Invalid PCAP filter:" << err.what();
        else
            std::cerr << "Invalid PCAP filter: " << err.what() << std::endl;
        res = 3;
    }
#if ENABLE_DNSTAP
    catch (const dnstap_invalid& err)
    {
        if ( log_errs )
            LOG_ERROR << "Invalid DNSTAP:" << err.what();
        else
            std::cerr << "Invalid DNSTAP: " << err.what() << std::endl;
        res = 3;
    }
#endif
    catch (const std::system_error& err)
    {
        if ( log_errs )
            LOG_ERROR << "Error " << err.code() << ": " << err.what();
        else
            std::cerr << "Error " << err.code() << ": " << err.what() << std::endl;
        res = 3;
    }
    catch (const boost::system::system_error& err)
    {
        if ( log_errs )
            LOG_ERROR << "Error " << err.code() << ": " << err.what();
        else
            std::cerr << "Error " << err.code() << ": " << err.what() << std::endl;
        res = 3;
    }

    signal_handler.wait_for_signals();
    switch(signal_received)
    {
    case 0:
        // Normal termination.
        break;

    case SIGHUP:
        // Re-reading configuration and restarting doesn't really make
        // sense if we're reading from file rather than doing network
        // capture. If we're reading from file, treat HUP as a termination.
        if ( !vm.count("capture-file") )
        {
            LOG_INFO << "Re-reading configuration";
            res = 1;
            break;
        }
        // Else fall through.

    default:
        if ( log_errs )
            LOG_INFO << "Collection interrupted";
        else
            std::cerr << "\nInterrupted." << std::endl;
        res = 2;
        break;
    }

    matcher.flush();

    output.raw_pcap->close();
    output.ignored_pcap->close();
    output.cbor->close();

    if ( config.report_info )
    {
        config.dump_config(std::cout);
        stats.dump_stats(std::cout);
    }

    LOG_INFO << "Compactor shutdown complete";
    return res;
}

int main(int ac, char *av[])
{
#if ENABLE_DNSTAP
    GOOGLE_PROTOBUF_VERIFY_VERSION;
#endif

    // I promise not to use C stdio in this code.
    //
    // Valgrind reports this leads to memory leaks on
    // termination. See https://gcc.gnu.org/bugzilla/show_bug.cgi?id=27931.
    std::ios_base::sync_with_stdio(false);

    init_logging();

    Configuration configuration;
    po::variables_map vm;

    try {
        vm = configuration.parse_command_line(ac, av);

        if ( vm.count("help") )
        {
            std::cerr
                << "Usage: " << PROGNAME << " [options] [capture-file ...]\n"
                << configuration.options_usage();
            return 1;
        }

        if ( vm.count("version") )
        {
            std::cout << PROGNAME << " " PACKAGE_VERSION "\n"
                      << "https://tools.ietf.org/html/rfc8618\n";
            return 1;
        }

        if ( vm.count("list-interfaces") )
        {
            std::cout << "Network interfaces:\n";
            for ( const auto& iface : Tins::NetworkInterface::all() )
                std::cout  << "\t" << iface.name() << std::endl;
            return 0;
        }

        if ( !!vm.count("interface") +
#if ENABLE_DNSTAP
             !!vm.count("dnstap-socket") +
#endif
             !!vm.count("capture-file") != 1 )
        {
            std::cerr
                << "Error:\tSpecify EITHER an interface to capture from, "
#if ENABLE_DNSTAP
                << "OR a DNSTAP socket,"
#endif
                << "\n\tOR some capture files to replay. Run '"
                << PROGNAME << " -h' for help.\n";
            return 1;
        }

        if ( configuration.client_address_prefix_ipv4 > 32 ||
             configuration.server_address_prefix_ipv4 > 32 )
        {
            std::cerr
                << "Error:\tIPv4 prefix length must be in range 0 to 32.\n";
            return 1;
        }

        if ( configuration.client_address_prefix_ipv6 > 128 ||
             configuration.server_address_prefix_ipv6 > 128 )
        {
            std::cerr
                << "Error:\tIPv6 prefix length must be in range 0 to 128.\n";
            return 1;
        }
        if ( configuration.sampling_threshold > 100 || configuration.sampling_threshold == 0 )
        {
            std::cerr
                << "Error:\tSampling threshold must be in range 1 to 100.\n";
            return 1;
        }
        if ( configuration.sampling_rate == 1 ) 
        {
            std::cerr
                << "Error:\tSampling rate cannot be set to 1.\n";
            return 1;
        }
        if ( configuration.sampling_time < 10 ) 
        {
            std::cerr
                << "Error:\tSampling time must be greater than 10.\n";
            return 1;
        }

        // Disable collection stats logging and disable logging
        // the hostname if reading from file.
        if ( vm.count("capture-file") )
        {
            configuration.log_network_stats_period = 0;
            configuration.omit_hostid = true;
        }
        LOG_INFO << "Compactor initializing...";

        // To enable a SIGHUP to not lose data, file compression
        // must survive the restart. That means compression
        // management must be outside the individual collection run.
        std::shared_ptr<BaseParallelWriterPool> writer_pool;

        if ( vm.count("output") && !configuration.output_pattern.empty() )
        {
            if ( configuration.xz_output )
            {
                writer_pool = std::make_shared<ParallelWriterPool<XzStreamWriter>>(configuration.max_compression_threads, configuration.xz_preset);
            }
            else if ( configuration.gzip_output )
            {
                writer_pool = std::make_shared<ParallelWriterPool<GzipStreamWriter>>(configuration.max_compression_threads, configuration.gzip_level);
            }
            else
            {
                writer_pool = std::make_shared<ParallelWriterPool<StreamWriter>>(configuration.max_compression_threads, 0);
            }
        }

        std::vector<std::thread> threads;
        int res;
        while ( ( res = run_configuration(vm, configuration, threads, writer_pool) ) == 1 )
            configuration.reread_config_file();

        // On interrupt, abort ongoing compressions.
        if ( res == 2 && writer_pool )
            writer_pool->abort();

        // Wait for in progress output to complete.
        for ( auto& thread : threads )
            if ( thread.joinable() )
                thread.join();

        if ( res != 0 )
            return 1;
    }
    catch (po::error& err)
    {
        LOG_ERROR << err.what();
        std::cerr << "Error: " << err.what() << std::endl;
        return 1;
    }

#if ENABLE_DNSTAP
    google::protobuf::ShutdownProtobufLibrary();
#endif
    LOG_INFO << "Compactor shutdown complete";
    return 0;
}
