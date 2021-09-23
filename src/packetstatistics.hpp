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

#ifndef PACKETSTATISTICS_HPP
#define PACKETSTATISTICS_HPP

#include <cstdint>

/**
 * \typedef PacketStatistics
 * \brief Statistics on packet collection.
 *
 * \struct PacketStatistics_s
 * \brief A structure holding statistics.
 *
 * All of the counts below are from since the program run started.
 */
using PacketStatistics = struct PacketStatistics_s
{
    /**
     * \brief count of packets received (sniffed and dropped by sniffer).
     */
    uint64_t raw_packet_count;

    /**
     * \brief count of DNS packets received out of time order (after any sampling applied).
     */
    uint64_t out_of_order_packet_count;

    /**
     * \brief count of unhandled packets received (after any sampling applied).
     */
    uint64_t unhandled_packet_count;

    /**
     * \brief count of well-formed DNS messages received (after any sampling applied).
     *
     * C-DNS standard quantity.
     */
    uint64_t processed_message_count;

    /**
     * \brief count of total query/response pairs output (after any sampling applied).
     *
     * C-DNS standard quantity.
     */
    uint64_t qr_pair_count;

    /**
     * \brief count of queries with no matching response (after any sampling applied).
     *
     * C-DNS standard quantity.
     */
    uint64_t query_without_response_count;

    /**
     * \brief count of responses with no matching query (after any sampling applied).
     *
     * C-DNS standard quantity.
     */
    uint64_t response_without_query_count;

    /**
     * \brief cout of discarded messages due to OPCODE not in collection list (after any sampling applied).
     *
     * C-DNS standard quantity.
     */
    uint64_t discarded_opcode_count;

    /**
     * \brief count of malformed DNS packets received (after any sampling applied).
     *
     * C-DNS standard quantity.
     */
    uint64_t malformed_message_count;

    /**
     * \brief count from PCAP of packets received.
     */
    uint64_t pcap_recv_count;

    /**
     * \brief count from PCAP of packets dropped by kernel.
     */
    uint64_t pcap_drop_count;

    /**
     * \brief count from PCAP of packets dropped by interface.
     */
    uint64_t pcap_ifdrop_count;

    /**
     * \brief count of raw PCAP packets dropped by output.
     */
    uint64_t output_raw_pcap_drop_count;

    /**
     * \brief count of ignored PCAP packets dropped by output.
     */
    uint64_t output_ignored_pcap_drop_count;

    /**
     * \brief count of CBOR items dropped by output.
     */
    uint64_t output_cbor_drop_count;

    /**
    * \brief count of items dropped in sniffer.
    */
    uint64_t sniffer_drop_count;

   /**
    * \brief count of CBOR items discarded due to sampling.
    */
   uint64_t discarded_sampling_count;

  /**
   * \brief count of items dropped due to matcher max size.
   */

   uint64_t matcher_drop_count;

    /**
     * \brief Dump the stats to the stream provided
     *
     * \param os output stream.
     */
    void dump_stats(std::ostream& os) {
        os << "\nSTATISTICS:\n"
           << "  Total Packets received                   : " << raw_packet_count + sniffer_drop_count << "\n"
           << "  Dropped packets at sniffer    (overload) : " << sniffer_drop_count << "\n"
           << "  Total Packets processed                  : " << raw_packet_count << "\n"
           << "  Dropped Matcher messages      (overload) : " << matcher_drop_count << "\n"
           << "  Discarded C-DNS messages      (sampling) : " << discarded_sampling_count << "\n"
           << "  Processed DNS messages           (C-DNS) : " << processed_message_count << "\n"
           << "  Matched DNS query/response pairs (C-DNS) : " << qr_pair_count << "\n"
           << "  Unmatched DNS queries            (C-DNS) : " << query_without_response_count << "\n"
           << "  Unmatched DNS responses          (C-DNS) : " << response_without_query_count << "\n"
           << "  Discarded OPCODE DNS messages    (C-DNS) : " << discarded_opcode_count << "\n"
           << "  Malformed DNS messages           (C-DNS) : " << malformed_message_count << "\n"
           << "  Non-DNS packets                          : " << unhandled_packet_count  << "\n"
           << "  Out-of-order DNS query/responses         : " << out_of_order_packet_count << "\n"
           << "  Dropped raw PCAP packets      (overload) : " << output_raw_pcap_drop_count << "\n"
           << "  Dropped non-DNS packets       (overload) : " << output_ignored_pcap_drop_count << "\n\n";
        os << "PCAP STATISTICS:\n"
           << "  Packets received               (libpcap) : " << pcap_recv_count << "\n"
           << "  Packets dropped at i/f         (libpcap) : " << pcap_ifdrop_count << "\n"
           << "  Packets dropped in kernel      (libpcap) : " << pcap_drop_count << "\n\n";
    }
};

#endif
