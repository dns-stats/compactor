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

#include <fstream>
#include <functional>
#include <iostream>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <utility>

#include <boost/filesystem.hpp>
#include <boost/optional.hpp>
#include <boost/program_options.hpp>

#include "config.h"

#include "bytestring.hpp"
#include "capturedns.hpp"
#include "cbordecoder.hpp"
#include "blockcborreader.hpp"
#include "log.hpp"
#include "makeunique.hpp"
#include "pcapwriter.hpp"
#include "pseudoanonymise.hpp"

const std::string PROGNAME = "inspector";
const std::string PCAP_EXT = ".pcap";
const std::string INFO_EXT = ".info";

namespace po = boost::program_options;

/**
 * \struct Options
 *
 * Inspector command line option values.
 */
struct Options
{
    /**
     * \brief auto choose name compression.
     */
    bool auto_compression{true};

    /**
     * \brief dump text summary of query/response pairs.
     */
    bool debug_qr{false};

    /**
     * \brief report conversion information on completion.
     */
    bool report_info{false};

    /**
     * \brief don't write conversion only report information.
     */
    bool report_only{false};

    /**
     * \brief don't write PCAP files, only info files.
     */
    bool info_only{false};

    /**
     * \brief write only query messages to output.
     */
    bool query_only{false};

    /**
     * \brief compress output data using gzip.
     */
    bool gzip_output{false};

    /**
     * \brief gzip compression level to use.
     */
    unsigned int gzip_level{6};

    /**
     * \brief compress output data using xz.
     */
    bool xz_output{false};

    /**
     * \brief xz compression preset to use.
     */
    unsigned int xz_preset{6};

    /**
     * \brief pseudo-anonymisation, if to use.
     */
    boost::optional<PseudoAnonymise> pseudo_anon;
};

using PacketSink = std::function<void (std::shared_ptr<QueryResponse>)>;

static void report_regeneration(std::ostream& os, unsigned wire_size)
{
    if ( wire_size > 0 )
        os <<
            "REGENERATION ERRORS:\n"
            "  Incorrect wire size: " << wire_size << " packets\n\n";
}

static void report(std::ostream& os, Configuration& config, BlockCborReader& cbr,
                   unsigned bad_response_wire_size_count)
{
    config.dump_config(os);
    cbr.dump_collector(os);
    cbr.dump_stats(os);
    cbr.dump_address_events(os);
    report_regeneration(os, bad_response_wire_size_count);
}

static void convert_stream(std::istream& is, PacketSink packet_sink, std::ofstream& info, const Options& options, const std::string& out)
{
    Configuration config;
    CborStreamDecoder dec(is);
    BlockCborReader cbr(dec, config, options.pseudo_anon);
    unsigned bad_response_wire_size_count = 0;
    bool auto_compression = options.auto_compression;
    bool using_compression = ( CaptureDNS::name_compression() != CaptureDNS::NONE );
    std::chrono::system_clock::time_point earliest_time, latest_time;
    bool first_time = true;

    for ( std::shared_ptr<QueryResponse> qr = cbr.readQR();
          qr;
          qr = cbr.readQR() )
    {
        // Check size of generated response packet if all sections recorded.
        if ( using_compression &&
             qr->has_response() &&
             config.output_options_responses == Configuration::ALL &&
             qr->response().wire_size != qr->response().dns.size() )
        {
            if ( auto_compression )
            {
                // See if Knot works better. If it does, stick with it.
                CaptureDNS::set_name_compression(CaptureDNS::KNOT_1_6);
                qr->response().dns.clear_cached_size();
                if ( qr->response().wire_size != qr->response().dns.size() )
                {
                    CaptureDNS::set_name_compression(CaptureDNS::DEFAULT);
                    bad_response_wire_size_count++;
                }
                auto_compression = false;
            }
            else
                bad_response_wire_size_count++;
        }

        if ( qr->has_query() )
        {
            std::chrono::system_clock::time_point t = qr->query().timestamp;

            if ( first_time )
            {
                earliest_time = latest_time = t;
                first_time = false;
            }
            else if ( t < earliest_time )
                earliest_time = t;
            else if ( t > latest_time )
                latest_time = t;
        }
        if ( qr->has_response() )
        {
            std::chrono::system_clock::time_point t = qr->response().timestamp;

            if ( first_time )
            {
                earliest_time = latest_time = t;
                first_time = false;
            }
            else if ( t < earliest_time )
                earliest_time = t;
            else if ( t > latest_time )
                latest_time = t;
        }

        packet_sink(qr);
    }

    // Approximate the rotation period with the difference between the first
    // and last timestamps, rounded to the nearest second.
    config.rotation_period = (std::chrono::duration_cast<std::chrono::milliseconds>(latest_time - earliest_time).count() + 500) / 1000;

    if ( !options.report_only )
    {
        if ( info.is_open() )
            report(info, config, cbr, bad_response_wire_size_count);
    }

    if ( options.report_info )
        report(std::cout, config, cbr, bad_response_wire_size_count);
}

static void write_packet(PcapBaseWriter& writer,
                         Tins::PDU* pdu,
                         const IPAddress& src,
                         const IPAddress& dst,
                         uint8_t hoplimit,
                         const std::chrono::system_clock::time_point& timestamp)
{
    Tins::EthernetII ethernet;

    if ( src.is_ipv6() )
    {
        Tins::IPv6 ipv6(dst, src);
        ipv6.hop_limit(hoplimit);
        ipv6.inner_pdu(*pdu);
        ethernet.inner_pdu(ipv6);
    }
    else
    {
        Tins::IP ip(dst, src);
        ip.ttl(hoplimit);
        ip.inner_pdu(*pdu);
        ethernet.inner_pdu(ip);
    }

    writer.write_packet(ethernet, timestamp);
}

static void write_UDP_packet(PcapBaseWriter& writer, const DNSMessage& dns)
{
    IPAddress clientIP = dns.clientIP;
    IPAddress serverIP = dns.serverIP;
    uint16_t clientPort = dns.clientPort;
    uint16_t serverPort = dns.serverPort;

    if ( dns.dns.type() == CaptureDNS::RESPONSE )
    {
        std::swap(clientIP, serverIP);
        std::swap(clientPort, serverPort);
    }

    Tins::UDP udp;
    udp.sport(clientPort);
    udp.dport(serverPort);
    udp.inner_pdu(dns.dns);

    write_packet(writer, &udp, clientIP, serverIP, dns.hoplimit, dns.timestamp);
}

static void writeQRwithUDP(PcapBaseWriter& writer, std::shared_ptr<QueryResponse> qr, const Options& options)
{
    if ( qr->has_query() )
        write_UDP_packet(writer, qr->query());
    if ( qr->has_response() && !options.query_only )
        write_UDP_packet(writer, qr->response());
}

static void writeQRwithTCP(PcapBaseWriter& writer, std::shared_ptr<QueryResponse> qr, const Options& options)
{
    IPAddress client_address, server_address;
    uint16_t client_port, server_port;
    uint8_t client_hoplimit, server_hoplimit;
    std::chrono::system_clock::time_point query_timestamp, response_timestamp;

    if ( qr->has_query() )
    {
        client_address = qr->query().clientIP;
        server_address = qr->query().serverIP;
        client_port = qr->query().clientPort;
        server_port = qr->query().serverPort;
        client_hoplimit = qr->query().hoplimit;
        query_timestamp = qr->query().timestamp;
        if ( qr->has_response() )
        {
            server_hoplimit = qr->response().hoplimit;
            response_timestamp = qr->response().timestamp;
        }
        else
        {
            server_hoplimit = client_hoplimit;
            response_timestamp = query_timestamp;
        }
    }
    else
    {
        client_address = qr->response().clientIP;
        server_address = qr->response().serverIP;
        client_port = qr->response().clientPort;
        server_port = qr->response().serverPort;
        client_hoplimit = qr->response().hoplimit;
        server_hoplimit = client_hoplimit;
        query_timestamp = qr->response().timestamp;
        response_timestamp = query_timestamp;
    }

    // Client SYN -> server.
    Tins::TCP ctcp(server_port, client_port);
    ctcp.set_flag(Tins::TCP::SYN, 1);
    write_packet(writer, &ctcp, client_address, server_address, client_hoplimit, query_timestamp);
    ctcp.set_flag(Tins::TCP::SYN, 0);
    ctcp.seq(ctcp.seq() + 1);

    // Server ACK -> client.
    Tins::TCP stcp(client_port, server_port);
    stcp.set_flag(Tins::TCP::SYN, 1);
    stcp.set_flag(Tins::TCP::ACK, 1);
    stcp.ack_seq(ctcp.seq());
    write_packet(writer, &stcp, server_address, client_address, server_hoplimit, query_timestamp);
    stcp.set_flag(Tins::TCP::SYN, 0);
    stcp.seq(stcp.seq() + 1);

    // Client SYN/ACK -> server.
    ctcp.set_flag(Tins::TCP::ACK, 1);
    ctcp.ack_seq(stcp.seq());
    write_packet(writer, &ctcp, client_address, server_address, client_hoplimit, query_timestamp);

    // Client Query -> server.
    if ( qr->has_query() )
    {
        CaptureDNS dnsmsg = qr->query().dns;
        uint32_t dnssize = dnsmsg.size();
        Tins::PDU::serialization_type dnsbuf = dnsmsg.serialize();
        byte_string buf(dnsbuf.data(), dnssize);
        buf.reserve(dnssize + 2);
        buf.insert(buf.begin(), dnssize & 0xff);
        buf.insert(buf.begin(), (dnssize >> 8) & 0xff);
        Tins::RawPDU raw_pdu(buf.data(), buf.size());
        ctcp.inner_pdu(raw_pdu);
        ctcp.set_flag(Tins::TCP::PSH, 1);
        write_packet(writer, &ctcp, client_address, server_address, client_hoplimit, query_timestamp);
        ctcp.set_flag(Tins::TCP::PSH, 0);
        ctcp.seq(ctcp.seq() + buf.size());
        ctcp.inner_pdu(nullptr);

        stcp.ack_seq(ctcp.seq());
        write_packet(writer, &stcp, server_address, client_address, server_hoplimit, query_timestamp);
    }

    // Server Response -> client.
    if ( qr->has_response() && !options.query_only )
    {
        CaptureDNS dnsmsg = qr->response().dns;
        uint32_t dnssize = dnsmsg.size();
        Tins::PDU::serialization_type dnsbuf = dnsmsg.serialize();
        byte_string buf(dnsbuf.data(), dnssize);
        buf.reserve(dnssize + 2);
        buf.insert(buf.begin(), dnssize & 0xff);
        buf.insert(buf.begin(), (dnssize >> 8) & 0xff);
        Tins::RawPDU raw_pdu(buf.data(), buf.size());
        stcp.inner_pdu(raw_pdu);
        stcp.set_flag(Tins::TCP::PSH, 1);
        write_packet(writer, &stcp, server_address, client_address, server_hoplimit, response_timestamp);
        stcp.set_flag(Tins::TCP::PSH, 0);
        stcp.seq(stcp.seq() + buf.size());
        stcp.inner_pdu(nullptr);

        ctcp.ack_seq(stcp.seq());
        write_packet(writer, &ctcp, client_address, server_address, client_hoplimit, response_timestamp);
    }

    // Client FIN -> server.
    ctcp.set_flag(Tins::TCP::FIN, 1);
    ctcp.ack_seq(stcp.seq());
    write_packet(writer, &ctcp, client_address, server_address, client_hoplimit, response_timestamp);
    ctcp.seq(ctcp.seq() + 1);

    // Server FIN -> client.
    stcp.set_flag(Tins::TCP::FIN, 1);
    stcp.ack_seq(ctcp.seq());
    write_packet(writer, &stcp, server_address, client_address, server_hoplimit, response_timestamp);
    stcp.seq(stcp.seq() + 1);

    // Client ACK -> server.
    ctcp.set_flag(Tins::TCP::FIN, 0);
    ctcp.ack_seq(stcp.seq());
    write_packet(writer, &ctcp, client_address, server_address, client_hoplimit, response_timestamp);
}

static void writeQR(PcapBaseWriter& writer, std::shared_ptr<QueryResponse> qr, const Options& options)
{
    if ( ( qr->has_query() && qr->query().tcp ) ||
         ( qr->has_response() && qr->response().tcp ) )
        writeQRwithTCP(writer, qr, options);
    else
        writeQRwithUDP(writer, qr, options);
}

static std::string new_file(const std::string& name)
{
    int count = 0;

    for(;;)
    {
        std::ostringstream oss;
        oss << name;
        if ( count > 0 )
            oss << "-" << count;
        if ( !boost::filesystem::exists(oss.str()) )
            return oss.str();
        count++;
    }
}

static bool convert_stream_to_packet_writer(std::istream& is,
                                            std::unique_ptr<PcapBaseWriter>& writer,
                                            std::ofstream& info,
                                            const Options& options,
                                            const std::string& out)
{
    try
    {
        convert_stream(
            is,
            [&](std::shared_ptr<QueryResponse> qr)
            {
                if ( options.debug_qr )
                    std::cout << *qr;
                if ( !options.report_only && !options.info_only )
                    writeQR(*writer, qr, options);
            },
            info,
            options,
            out);
    }
    catch (const std::exception& e)
    {
        std::cerr << PROGNAME << ":  Conversion error while processing: "
                  << out << " Error: " << e.what() << std::endl;
        return false;
    }

    return true;
}

static std::string make_output_name(const std::string& name, const Options& options)
{
    if ( options.xz_output )
        return name + XzStreamWriter::suggested_extension();
    else if ( options.gzip_output )
        return name + GzipStreamWriter::suggested_extension();
    else
        return name + StreamWriter::suggested_extension();
}

static std::unique_ptr<PcapBaseWriter> make_writer(const std::string& name, const Options& options)
{
    if ( options.xz_output )
        return make_unique<PcapWriter<XzStreamWriter>>(name, options.xz_preset, 65535);
    else if ( options.gzip_output )
        return make_unique<PcapWriter<GzipStreamWriter>>(name, options.gzip_level, 65535);
    else
        return make_unique<PcapWriter<StreamWriter>>(name, 0, 65535);
}

int main(int ac, char *av[])
{
    // I promise not to use C stdio in this code.
    //
    // Valgrind reports this leads to memory leaks on
    // termination. See https://gcc.gnu.org/bugzilla/show_bug.cgi?id=27931.
    std::ios_base::sync_with_stdio(false);

    init_logging();

    std::string output_file_name;
    std::string pcap_file_name;
    std::string info_file_name;
    std::string compression_type;
    std::string pseudo_anon_passphrase;
    std::string pseudo_anon_key;

    Options options;

    po::options_description visible("Options");
    visible.add_options()
        ("help,h", "show this help message.")
        ("version,v", "show version information.")
        ("output,o",
         po::value<std::string>(&output_file_name),
         "output file name.")
        ("gzip-output,z",
         "compress PCAP data using gzip. Adds .gz extension to output file.")
        ("gzip-level,y",
         po::value<unsigned int>(&options.gzip_level)->default_value(6),
         "gzip compression level.")
        ("xz-output,x",
         "compress PCAP data using xz. Adds .xz extension to output file.")
        ("xz-preset,u",
         po::value<unsigned int>(&options.xz_preset)->default_value(6),
         "xz compression preset level.")
        ("query-only,q",
         "write only query messages to output.")
        ("report-info,r",
         "report info (config and stats summary) on exit.")
        ("info-only,I",
         "don't generate PCAP output files, only info files.")
        ("report-only,R",
         "don't write output files, just report info.")
#if ENABLE_PSEUDOANONYMISATION
        ("pseudo-anonymisation-key,k",
         po::value<std::string>(&pseudo_anon_key),
         "pseudo-anonymisation key.")
        ("pseudo-anonymisation-passphrase,P",
         po::value<std::string>(&pseudo_anon_passphrase),
         "pseudo-anonymisation passphrase.")
        ("pseudo-anonymise,p",
         "pseudo-anonymise output.")
#endif
        ("debug-qr",
         "print Query/Response details.");
    po::options_description debug("Hidden options");
    debug.add_options()
        ("compression",
         po::value<std::string>(&compression_type),
         "name compression type (none, knot, default).")
        ("cdns-file",
         po::value<std::vector<std::string>>(),
         "input C-DNS file.")
        ;
    po::options_description all("Options");
    all.add(visible).add(debug);

    po::positional_options_description positional;
    positional.add("cdns-file", -1);

    po::variables_map vm;

    try {
        po::store(po::command_line_parser(ac, av).options(all).positional(positional).run(), vm);

        if ( vm.count("help") )
        {
            std::cerr
                << "Usage: " << PROGNAME << " [options] [cdns-file [...]]\n"
                << visible;
            return 1;
        }

        if ( vm.count("version") )
        {
            std::cout << PROGNAME << " " PACKAGE_VERSION "\n";
            return 1;
        }

        if ( !vm.count("cdns-file") && !vm.count("output") )
        {
            std::cerr << PROGNAME
                << ":  Error:\tSpecify some C-DNS files to convert, or specify "
                "an output file to convert standard input. "
                << "Run '" << PROGNAME << " -h' for help.\n";
            return 1;
        }

        if ( vm.count("pseudo-anonymisation-key") != 0 &&
             vm.count("pseudo-anonymisation-passphrase") != 0 )
        {
            std::cerr << PROGNAME
                << ":  Error:\tSpecify pseudo-anonymisation key "
                "or passphrase, but not both.\n";
            return 1;
        }

        if ( vm.count("pseudo-anonymisation-key") != 0 &&
             pseudo_anon_key.size() != 16 )
        {
            std::cerr << PROGNAME
                << ":  Error:\tPseudo-anonymisation key "
                "must be exactly 16 bytes long.\n";
            return 1;
        }

        if ( vm.count("pseudo-anonymise") != 0 &&
             vm.count("pseudo-anonymisation-passphrase") == 0 &&
             vm.count("pseudo-anonymisation-passphrase") == 0 )
        {
            std::cerr << PROGNAME
                << ":  Error:\tTo pseudo-anonymise output you must specify "
                " a passphrase or key.\n";
            return 1;
        }

        options.gzip_output = ( vm.count("gzip-output") != 0 );
        options.xz_output = ( vm.count("xz-output") != 0 );
        options.debug_qr = ( vm.count("debug-qr") != 0 );
        options.report_info = ( vm.count("report-info") != 0 );
        options.info_only = ( vm.count("info-only") != 0 );
        options.query_only = ( vm.count("query-only") != 0 );
        options.report_only = ( vm.count("report-only") != 0 );
        if ( options.report_only )
            options.report_info = true;

        po::notify(vm);
    }
    catch (po::error& err)
    {
        std::cerr << PROGNAME << ": Error: " << err.what() << std::endl;
        return 1;
    }

#if ENABLE_PSEUDOANONYMISATION
    if ( vm.count("pseudo-anonymise") != 0 )
    {
        if ( vm.count("pseudo-anonymisation-key") != 0 )
            options.pseudo_anon = boost::optional<PseudoAnonymise>{to_byte_string(pseudo_anon_key)};
        else
            options.pseudo_anon = boost::optional<PseudoAnonymise>{pseudo_anon_passphrase};
    }
#endif

    if ( options.gzip_output && options.xz_output )
    {
        std::cerr << PROGNAME << ": Error: Specify gzip or xz compression, not both." << std::endl;
        return 1;
    }

    std::unique_ptr<PcapBaseWriter> writer;
    std::ofstream info;

    if ( vm.count("compression") )
    {
        options.auto_compression = false;
        if ( compression_type == "knot" )
            CaptureDNS::set_name_compression(CaptureDNS::KNOT_1_6);
        else if ( compression_type == "none" )
            CaptureDNS::set_name_compression(CaptureDNS::NONE);
        else if ( compression_type == "auto" )
            options.auto_compression = true;
        else if ( compression_type != "default" )
        {
            std::cerr << PROGNAME
                      << ":  Error: Compression type must be none, default or knot.\n";
            return 1;
        }
    }

    if ( vm.count("output") )
    {
        if ( output_file_name == StreamWriter::STDOUT_FILE_NAME )
        {
            if ( options.report_only || options.info_only || options.report_info )
            {
                std::cerr << PROGNAME
                          << ":  Writing PCAP to standard output can't be combined with info reporting.\n";
                return 1;
            }
            writer = make_writer(output_file_name, options);
        }
        else
        {
            pcap_file_name = new_file(make_output_name(output_file_name, options));
            info_file_name = output_file_name + INFO_EXT;
            if ( !options.report_only )
            {
                if ( !options.info_only )
                    writer = make_writer(pcap_file_name, options);
                info.open(info_file_name);
                if ( !info.is_open() )
                {
                    std::cerr << PROGNAME << ":  Can't create " << info_file_name << std::endl;
                    return 1;
                }
            }
        }
    }

    if ( !vm.count("cdns-file") )
    {
        if ( !convert_stream_to_packet_writer(std::cin, writer, info, options, output_file_name) )
        {
            std::remove(pcap_file_name.c_str());
            std::remove(info_file_name.c_str());
            return 1;
        }
    }
    else
    {
        int fail = 0;
        for ( auto& fname : vm["cdns-file"].as<std::vector<std::string>>() )
        {
            if ( !vm.count("output") )
            {
                pcap_file_name = new_file(make_output_name(fname + PCAP_EXT, options));
                info_file_name = fname + PCAP_EXT + INFO_EXT;
                if ( !options.report_only )
                {
                    if ( !options.info_only )
                        writer = make_writer(pcap_file_name, options);
                    info.open(info_file_name);
                    if ( !info.is_open() )
                    {
                        std::cerr << PROGNAME << ":  Can't create " << info_file_name << std::endl;
                        return 1;
                    }
                }
            }

            if ( options.report_info )
            {
                std::cout << " INPUT : " << fname;
                if ( !options.report_only )
                    std::cout << "\n OUTPUT: " << pcap_file_name;
                std::cout << "\n\n";
            }

            std::ifstream ifs;
            ifs.open(fname, std::ifstream::binary);
            if ( ifs.is_open() )
            {
                if ( !convert_stream_to_packet_writer(ifs, writer, info, options, fname))
                {
                    if ( !vm.count("output") )
                    {
                        if ( !options.report_only )
                        {
                            if ( !options.info_only )
                                std::remove(pcap_file_name.c_str());
                            std::remove(info_file_name.c_str());
                        }
                    }
                    fail = 1;
                }
            }
            else
            {
                std::cerr << PROGNAME << ":  Can't open input: " << fname << std::endl;
                if ( !vm.count("output") )
                {
                    if ( !options.report_only )
                    {
                        if ( !options.info_only )
                            std::remove(pcap_file_name.c_str());
                        std::remove(info_file_name.c_str());
                    }
                }
                fail = 1;
            }
            if ( !options.report_only )
                info.close();
        }
        return fail;
    }

    return 0;
}
