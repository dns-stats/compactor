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
#include <boost/program_options.hpp>

#include "config.h"

#include "backend.hpp"
#include "bytestring.hpp"
#include "cbordecoder.hpp"
#include "blockcborreader.hpp"
#include "log.hpp"
#include "makeunique.hpp"
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
     * \brief dump text summary of query/response pairs.
     */
    bool debug_qr{false};

    /**
     * \brief should conversion take place?
     */
    bool generate_output{true};

    /**
     * \brief generate info to file?
     */
    bool generate_info{true};

    /**
     * \brief name of the info file.
     */
    std::string info_file_name;

    /**
     * \brief report info?
     */
    bool report_info{false};

    /**
     * \brief pseudo-anonymisation, if to use.
     */
    boost::optional<PseudoAnonymise> pseudo_anon;
};

static void report(std::ostream& os,
                   Configuration& config,
                   BlockCborReader& cbr,
                   std::unique_ptr<OutputBackend>& backend)
{
    config.dump_config(os);
    cbr.dump_collector(os);
    cbr.dump_stats(os);
    cbr.dump_address_events(os);
    backend->report(os);
}

static int convert_stream_to_backend(const std::string& fname, std::istream& is, std::unique_ptr<OutputBackend>& backend, std::ofstream& info, Options& options)
{
    Configuration config;
    CborStreamDecoder dec(is);
    BlockCborReader cbr(dec, config, options.pseudo_anon);
    std::chrono::system_clock::time_point earliest_time, latest_time;
    bool first_time = true;

    try
    {
        for ( std::shared_ptr<QueryResponse> qr = cbr.readQR();
              qr;
              qr = cbr.readQR() )
        {
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

            if ( options.debug_qr )
                std::cout << *qr;

            backend->output(qr, config);
        }

        // Approximate the rotation period with the difference between the first
        // and last timestamps, rounded to the nearest second.
        config.rotation_period = (std::chrono::duration_cast<std::chrono::milliseconds>(latest_time - earliest_time).count() + 500) / 1000;

        if ( options.generate_info )
            report(info, config, cbr, backend);

        if ( options.report_info )
            report(std::cout, config, cbr, backend);
    }
    catch (const std::exception& e)
    {
        std::cerr << PROGNAME << ":  Conversion error while processing: "
                  << fname << " Error: " << e.what() << std::endl;
        if ( !backend->output_file().empty() )
            boost::filesystem::remove(backend->output_file());
        if ( !options.info_file_name.empty() )
            boost::filesystem::remove(options.info_file_name);
        return 1;
    }

    return 0;
}

static bool open_info_file(const std::string& fname, std::ofstream& info, Options& options)
{
    if ( !options.generate_info )
        return true;

    options.info_file_name = fname + INFO_EXT;
    info.open(options.info_file_name);
    if ( !info.is_open() )
    {
        std::cerr << PROGNAME << ":  Can't create " << fname << std::endl;
        return false;
    }
    return true;
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
    std::string compression_type;
#if ENABLE_PSEUDOANONYMISATION
    std::string pseudo_anon_passphrase;
    std::string pseudo_anon_key;
#endif
    Options options;
    PcapBackendOptions pcap_options;

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
         po::value<unsigned int>(&pcap_options.gzip_level)->default_value(6),
         "gzip compression level.")
        ("xz-output,x",
         "compress PCAP data using xz. Adds .xz extension to output file.")
        ("xz-preset,u",
         po::value<unsigned int>(&pcap_options.xz_preset)->default_value(6),
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

        po::notify(vm);

        if ( vm.count("pseudo-anonymisation-key") != 0 &&
             pseudo_anon_key.size() != 16 )
        {
            std::cerr << PROGNAME
                << ":  Error:\tPseudo-anonymisation key "
                "must be exactly 16 bytes long.\n";
            return 1;
        }

        if ( vm.count("pseudo-anonymise") != 0 &&
             vm.count("pseudo-anonymisation-key") == 0 &&
             vm.count("pseudo-anonymisation-passphrase") == 0 )
        {
            std::cerr << PROGNAME
                << ":  Error:\tTo pseudo-anonymise output you must specify "
                " a passphrase or key.\n";
            return 1;
        }

        pcap_options.gzip_output = ( vm.count("gzip-output") != 0 );
        pcap_options.xz_output = ( vm.count("xz-output") != 0 );
        pcap_options.query_only = ( vm.count("query-only") != 0 );
        options.debug_qr = ( vm.count("debug-qr") != 0 );

        options.generate_output = true;
        options.generate_info = true;
        options.report_info = false;

        if ( vm.count("info-only") != 0 )
            options.generate_output = false;

        if ( vm.count("report-info") != 0 )
            options.report_info = true;

        if ( vm.count("report-only") != 0 )
        {
            options.generate_output = false;
            options.generate_info = false;
            options.report_info = true;
        }

        if ( !options.generate_output )
            pcap_options.write_output = false;
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

    if ( pcap_options.gzip_output && pcap_options.xz_output )
    {
        std::cerr << PROGNAME << ": Error: Specify gzip or xz compression, not both." << std::endl;
        return 1;
    }

    if ( vm.count("compression") )
    {
        pcap_options.auto_compression = false;
        if ( compression_type == "knot" )
            CaptureDNS::set_name_compression(CaptureDNS::KNOT_1_6);
        else if ( compression_type == "none" )
            CaptureDNS::set_name_compression(CaptureDNS::NONE);
        else if ( compression_type == "auto" )
            pcap_options.auto_compression = true;
        else if ( compression_type != "default" )
        {
            std::cerr << PROGNAME
                      << ":  Error: Compression type must be none, default or knot.\n";
            return 1;
        }
    }

    std::unique_ptr<OutputBackend> backend;
    std::string pcap_file_name;
    std::string info_file_name;
    std::ofstream info;
    bool output_specified = false;

    if ( vm.count("output") )
    {
        output_specified = true;

        if ( output_file_name == StreamWriter::STDOUT_FILE_NAME )
        {
            if ( options.generate_output )
            {
                if ( options.report_info || options.debug_qr )
                {
                    std::cerr << PROGNAME
                              << ":  Writing PCAP to standard output can't be combined with info reporting or printing Query/Response details.\n";
                    return 1;
                }
                options.generate_info = false;
            } else {
                options.generate_info = false;
                options.report_info = true;
            }
        }
        else
        {
            if ( !open_info_file(output_file_name, info, options) )
                return 1;
        }

        backend = make_unique<PcapBackend>(pcap_options, output_file_name);
    }

    if ( !vm.count("cdns-file") )
    {
        if ( !output_specified )
        {
                    std::cerr << PROGNAME << ":  output file must be specified when reading from standard input." << std::endl;
                    return 1;
        }
        return convert_stream_to_backend(("(stdin)"), std::cin, backend, info, options);
    }

    for ( auto& fname : vm["cdns-file"].as<std::vector<std::string>>() )
    {
        if ( !output_specified )
        {
            std::string pcap_fname = fname + PCAP_EXT;

            if ( !open_info_file(pcap_fname, info, options) )
                return 1;

            backend = make_unique<PcapBackend>(pcap_options, pcap_fname);
        }

        if ( options.report_info )
        {
            std::cout << " INPUT : " << fname;
            if ( options.generate_info || options.generate_output )
                std::cout << "\n OUTPUT: " << backend->output_file();
            std::cout << "\n\n";
        }

        std::ifstream ifs;
        ifs.open(fname, std::ifstream::binary);
        if ( !ifs.is_open() )
        {
            std::cerr << PROGNAME << ":  Can't open input: " << fname << std::endl;
            return 1;
        }

        if ( convert_stream_to_backend(fname, ifs, backend, info, options) != 0 )
            return 1;

        if ( !output_specified )
        {
            if ( options.generate_info )
                info.close();
            backend.reset(nullptr);
        }

        ifs.close();
    }

    return 0;
}
