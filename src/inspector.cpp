/*
 * Copyright 2016-2019 Internet Corporation for Assigned Names and Numbers.
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
#include "template-backend.hpp"

const std::string PROGNAME = "inspector";
const std::string PCAP_EXT = ".pcap";
const std::string TEMPLATE_EXT = ".txt";
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
     * \brief print conversion stats to stderr.
     */
    bool generate_stats{false};

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

    /**
     * \brief output defaults.
     */
    Defaults defaults;
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
    BlockCborReader cbr(dec, config, options.defaults, options.pseudo_anon);
    boost::optional<std::chrono::system_clock::time_point> earliest_time, latest_time;

    backend->check_exclude_hints(config.exclude_hints);

    try
    {
        auto start = std::chrono::system_clock::now();
        unsigned long long nrecs = 0;
        bool eof = false;

        for ( QueryResponseData qr = cbr.readQRData(eof);
              !eof;
              qr = cbr.readQRData(eof) )
        {
            if ( qr.timestamp )
            {
                std::chrono::system_clock::time_point t = *qr.timestamp;
                if ( qr.response_delay )
                    t += *qr.response_delay;
                if ( !earliest_time )
                    earliest_time = latest_time = t;
                else if ( t < earliest_time )
                    earliest_time = t;
                else if ( t > latest_time )
                    latest_time = t;
            }

            if ( options.debug_qr )
                std::cout << qr;

            backend->output(qr, config);
            nrecs++;
        }

        // Approximate the rotation period with the difference between the first
        // and last timestamps, rounded to the nearest second.
        if ( earliest_time )
            config.rotation_period = std::chrono::seconds((std::chrono::duration_cast<std::chrono::milliseconds>(*latest_time - *earliest_time).count() + 500) / 1000);

        if ( options.generate_info )
            report(info, config, cbr, backend);

        if ( options.report_info )
            report(std::cout, config, cbr, backend);

        if ( options.generate_stats )
        {
            auto end = std::chrono::system_clock::now();
            std::chrono::duration<double> elapsed = end - start;
            std::cerr << "Converted " << nrecs << " q/r pairs in " << elapsed.count() << "s (" << nrecs/elapsed.count() << "rec/s)\n";
        }
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

    std::string defaults_file_name;
    std::string output_file_name;
    std::string compression_type;
#if ENABLE_PSEUDOANONYMISATION
    std::string pseudo_anon_passphrase;
    std::string pseudo_anon_key;
#endif
    Options options;
    PcapBackendOptions pcap_options;
    TemplateBackendOptions template_options;
    bool template_backend = false;
    std::string backend;
    std::vector<std::string> vals;

    po::options_description visible("Options");
    visible.add_options()
        ("help,h", "show this help message.")
        ("version,v", "show version information.")
        ("defaultsfile",
         po::value<std::string>(&defaults_file_name)->default_value(DEFAULTSFILE),
         "default values file.")
        ("output,o",
         po::value<std::string>(&output_file_name),
         "output file name.")
        ("output-format,F",
         po::value<std::string>(&backend),
         "output format. 'pcap' (default) or 'template'.")
        ("template,t",
         po::value<std::string>(&template_options.template_name),
         "name of template to use for template output.")
        ("value,V",
         po::value<std::vector<std::string>>(&vals),
         "<key>=<value> to substitute in the template. This argument can be repeated.")
        ("geoip-db-dir,g",
         po::value<std::string>(&template_options.geoip_db_dir_path)->default_value(GEOIPDIR),
         "path of directory with the GeoIP databases.")
        ("gzip-output,z",
         "compress output data using gzip. Adds .gz extension to output file.")
        ("gzip-level,y",
         po::value<unsigned int>(&pcap_options.baseopts.gzip_level)->default_value(6),
         "gzip compression level.")
        ("xz-output,x",
         "compress output data using xz. Adds .xz extension to output file.")
        ("xz-preset,u",
         po::value<unsigned int>(&pcap_options.baseopts.xz_preset)->default_value(6),
         "xz compression preset level.")
        ("query-only,q",
         "write only query messages to output.")
        ("report-info,r",
         "report info (config and stats summary) on exit.")
        ("info-only,I",
         "don't generate output data files, only info files.")
        ("report-only,R",
         "don't write output data files, just report info.")
        ("stats,S",
         "report conversion statistics.")
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

        if ( vm.count("output-format") != 0 )
        {
            if ( backend == "pcap" )
                template_backend = false;
            else if ( backend == "template" )
                template_backend = true;
            else
            {
                std::cerr << PROGNAME
                          << ":  Error:\tOutput format must be 'pcap' or 'template'.\n";
                return 1;
            }
        }

        if ( template_backend  )
        {
            if ( vm.count("template") == 0 )
            {
                std::cerr << PROGNAME
                          << ":  Error:\tTemplate output format requires a template to be specified.\n";
                return 1;
            }
            if ( vm.count("query_only") != 0 )
            {
                std::cerr << PROGNAME
                          << ":  Error:\tquery-only option does not apply when using template output format.\n";
                return 1;
            }
        }
        else
        {
            std::string template_args[] = { "template", "value" };
            for ( const std::string& arg : template_args )
                if ( vm.count(arg) != 0 )
                {
                    std::cerr << PROGNAME
                              << ":  Error:\t" << arg << " option does not apply when using PCAP output format.\n";
                    return 1;
                }
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
             vm.count("pseudo-anonymisation-key") == 0 &&
             vm.count("pseudo-anonymisation-passphrase") == 0 )
        {
            std::cerr << PROGNAME
                << ":  Error:\tTo pseudo-anonymise output you must specify "
                " a passphrase or key.\n";
            return 1;
        }

        pcap_options.baseopts.gzip_output = ( vm.count("gzip-output") != 0 );
        pcap_options.baseopts.xz_output = ( vm.count("xz-output") != 0 );
        pcap_options.query_only = ( vm.count("query-only") != 0 );
        options.debug_qr = ( vm.count("debug-qr") != 0 );
        options.generate_stats = ( vm.count("stats") != 0 );
        options.defaults.read_defaults_file(defaults_file_name);
        pcap_options.defaults = options.defaults;

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
            pcap_options.baseopts.write_output = false;

        template_options.baseopts = pcap_options.baseopts;
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

    if ( pcap_options.baseopts.gzip_output && pcap_options.baseopts.xz_output )
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

    for ( auto&& val : vals )
    {
        auto eq_pos = val.find('=');
        if ( eq_pos == std::string::npos )
        {
            std::cerr << PROGNAME << ": Value '" << val << " not of form <keyname>=<value>." << std::endl;
            return 1;
        }
        std::string key = val.substr(0, eq_pos);
        std::string keyval = val.substr(eq_pos + 1);
        template_options.values.push_back(std::make_pair(key, keyval));
    }

    try
    {
        std::unique_ptr<OutputBackend> backend;
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
                                  << ":  Writing output to standard output can't be combined with info reporting or printing Query/Response details.\n";
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

            if ( template_backend )
                backend = make_unique<TemplateBackend>(template_options, output_file_name);
            else
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
                std::string out_fname;

                if ( template_backend )
                    out_fname = fname + TEMPLATE_EXT;
                else
                    out_fname = fname + PCAP_EXT;

                if ( !open_info_file(out_fname, info, options) )
                    return 1;

                if ( template_backend )
                    backend = make_unique<TemplateBackend>(template_options, out_fname);
                else
                    backend = make_unique<PcapBackend>(pcap_options, out_fname);
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
    }
    catch (const std::runtime_error& err)
    {
        std::cerr << PROGNAME << ": Error: " << err.what() << std::endl;
        return 1;
    }

    return 0;
}
