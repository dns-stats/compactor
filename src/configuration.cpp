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
#include <sstream>
#include <unordered_map>

#include <boost/filesystem.hpp>

#include <tins/network_interface.h>
#include <tins/tins.h>

#include "configuration.hpp"
#include "log.hpp"

namespace po = boost::program_options;

namespace {
    const std::unordered_map<std::string, unsigned> RR_TYPES = {
        { "A", 1 },
        { "NS", 2 },
        { "MD", 3 },
        { "MF", 4 },
        { "CNAME", 5 },
        { "SOA", 6 },
        { "MB", 7 },
        { "MG", 8 },
        { "MR", 9 },
        { "NULL_R", 10 },
        { "WKS", 11 },
        { "PTR", 12 },
        { "HINFO", 13 },
        { "MINFO", 14 },
        { "MX", 15 },
        { "TXT", 16 },
        { "RP", 17 },
        { "AFSDB", 18 },
        { "X25", 19 },
        { "ISDN", 20 },
        { "RT", 21 },
        { "NSAP", 22 },
        { "NSAP_PTR", 23 },
        { "SIG", 24 },
        { "KEY", 25 },
        { "PX", 26 },
        { "GPOS", 27 },
        { "AAAA", 28 },
        { "LOC", 29 },
        { "NXT", 30 },
        { "EID", 31},
        { "NIMLOC", 32 },
        { "SRV", 33 },
        { "ATMA", 34 },
        { "NAPTR", 35 },
        { "KX", 36 },
        { "CERTIFICATE", 37 },
        { "A6", 38 },
        { "DNAM", 39 },
        { "SINK", 40 },
        { "OPT", 41 },
        { "APL", 42 },
        { "DS", 43 },
        { "SSHFP", 44 },
        { "IPSECKEY", 45 },
        { "RRSIG", 46 },
        { "NSEC", 47 },
        { "DNSKEY", 48 },
        { "DHCID", 49 },
        { "NSEC3", 50 },
        { "NSEC3PARAM", 51 },
        { "TLSA", 52 },
        { "HIP", 55 },
        { "NINFO", 56 },
        { "RKEY", 57 },
        { "TALINK", 58 },
        { "CDS", 59 },
        { "SPF", 99 },
        { "UINFO", 100 },
        { "UID", 101 },
        { "GID", 102 },
        { "UNSPEC", 103 },
        { "NID", 104 },
        { "L32", 105 },
        { "L64", 106 },
        { "LP", 107 },
        { "EU148", 108 },
        { "EUI64", 109 },
        { "TKEY", 249  },
        { "TSIG", 250 },
        { "IXFR", 251 },
        { "AXFR", 252 },
        { "MAILB", 253 },
        { "MAILA", 254 },
        { "TYPE_ANY", 255 },
        { "URI", 256 },
        { "CAA", 256 },
        { "TA", 32768  },
        { "DLV", 32769  },

        { "CERT", 37 },
        { "NSEC3PARAMS", 51 }
    };

    void set_rr_type_config(std::vector<unsigned>& config, const std::vector<std::string>& names)
    {
        for ( const auto& s : names )
        {
            auto item = RR_TYPES.find(s);
            if ( item == RR_TYPES.end() )
                throw po::error("unknown RR type " + s );
            else
                config.push_back(item->second);
        }
    }

    /**
     * \brief Check a network interface exists.
     *
     * \param ifname the interface name.
     * \returns network interface access object.
     * \throws boost::program_options::error if interface not found.
     */
    Tins::NetworkInterface check_network_interface(const std::string& ifname)
    {
        try
        {
            return Tins::NetworkInterface(ifname);
        }
        catch (const Tins::invalid_interface&)
        {
            std::ostringstream oss;
            oss << "Interface '" << ifname << "' not found.";
            throw po::error(oss.str());
        }
    }

    /**
     * \brief See if given address is assigned to any machine interface.
     *
     * If the address is not present, log an error, but carry on.
     *
     * \param addr the address.
     */
    void check_server_address(const IPAddress& addr)
    {
        bool found = false;

        for ( const auto& iface : Tins::NetworkInterface::all() )
        {
            const auto& addrs = iface.info();
            if ( addr.is_ipv6() )
            {
                for ( const auto& v6addr : addrs.ipv6_addrs )
                {
                    if ( v6addr.address == addr )
                    {
                        found = true;
                        break;
                    }
                }
            }
            else if ( addrs.ip_addr == addr )
            {
                found = true;
            }

            if ( found )
                break;
        }

        if ( !found )
            LOG_ERROR << addr << " is not configured on any interface.";
    }
}

// cppcheck-suppress unusedFunction
void validate(boost::any& v, const std::vector<std::string>& values,
              Size* val1, int val2)
{
    po::validators::check_first_occurrence(v);
    std::string s = po::validators::get_single_string(values);
    char suffix = s.back();
    std::uintmax_t factor = 1;

    switch(suffix)
    {
    case 'k': factor = 1024ull; break;
    case 'K': factor = 1000ull; break;
    case 'm': factor = 1024ull*1024; break;
    case 'M': factor = 1000ull*1000; break;
    case 'g': factor = 1024ull*1024*1024; break;
    case 'G': factor = 1000ull*1000*1000; break;
    case 't': factor = 1024ull*1024*1024*1024; break;
    case 'T': factor = 1000ull*1000*1000*1000; break;

    default:
        if ( ! ( suffix >= '0' && suffix <= '9' ) )
            throw po::validation_error(po::validation_error::invalid_option_value);
        break;
    }

    if ( factor > 1 )
        s.pop_back();

    v = boost::any(Size(std::stoull(s) * factor));
}

Configuration::Configuration()
    : gzip_output(false), gzip_level(6),
      xz_output(false), xz_preset(6),
      gzip_pcap(false), gzip_level_pcap(6),
      xz_pcap(false), xz_preset_pcap(6),
      max_compression_threads(2),
      rotation_period(300),
      query_timeout(5), skew_timeout(10),
      snaplen(65535),
      promisc_mode(false),
      output_options_queries(0), output_options_responses(0),
      max_block_items(5000),
      max_output_size(0),
      report_info(false), log_network_stats_period(0),
      debug_dns(false), debug_qr(false),
      omit_hostid(false), omit_sysid(false),
      max_channel_size(10000),
      config_file_(CONFFILE),
      cmdline_options_("Command options"),
      cmdline_hidden_options_("Hidden command options"),
      config_file_options_("Configuration"),
      positional_options_()
{
    cmdline_options_.add_options()
        ("help,h", "show this help message.")
        ("version,v", "show version information.")
        ("configfile,c",
         po::value<std::string>(),
         "configuration file.")
        ("report-info,r",
         po::value<bool>(&report_info)->implicit_value(true),
         "report info (config and stats summary) on exit.")
        ("debug-dns",
         po::value<bool>(&debug_dns)->implicit_value(true),
         "print DNS packet details.")
        ("debug-qr",
         po::value<bool>(&debug_qr)->implicit_value(true),
         "print Query/Response match details.")
        ("list-interfaces,l", "list all network interfaces.")
        ;

    cmdline_hidden_options_.add_options()
        ("omit-system-id",
         po::value<bool>(&omit_sysid)->implicit_value(true),
         "omit system identifiers from CBOR outputs.")
        ("max-channel-size",
         po::value<unsigned int>(&max_channel_size)->default_value(300000),
         "maximum number of items in inter-thread queue.")
        ("capture-file",
         po::value<std::vector<std::string>>(),
         "input capture (PCAP) file.")
        ;

    positional_options_.add("capture-file", -1);

    config_file_options_.add_options()
        ("rotation-period,t",
         po::value<unsigned int>(&rotation_period)->default_value(300),
         "rotation period for all outputs, in seconds.")
        ("query-timeout,q",
         po::value<unsigned int>(&query_timeout)->default_value(5),
         "timeout period for unanswered queries, in seconds.")
        ("skew-timeout,k",
         po::value<unsigned int>(&skew_timeout)->default_value(10),
         "timeout period for a query to arrive after its response, in microseconds.")
        ("snaplen,s",
         po::value<unsigned int>(&snaplen)->default_value(65535),
         "capture this many bytes per packet.")
        ("promiscuous-mode,p",
         po::value<bool>(&promisc_mode)->implicit_value(true),
         "put the capture interface into promiscuous mode.")
        ("interface,i",
         po::value<std::vector<std::string>>(&network_interfaces),
         "network interface from which to capture.")
        ("server-address-hint,S",
         po::value<std::vector<std::string>>(),
         "IP addresses belonging to the server.")
        ("vlan-id,a",
         po::value<std::vector<unsigned>>(&vlan_ids),
         "ID of VLAN for capture.")
        ("filter,f",
         po::value<std::string>(&filter),
         "discard packets that don't match the filter.")
        ("include,n",
         po::value<std::vector<std::string>>(),
         "specify optional sections for output, (query|response)-(questions|answers|authorities|all) or all. Default none.")
        ("accept-rr-type,e",
         po::value<std::vector<std::string>>(),
         "RR types to be captured, if not all.")
        ("ignore-rr-type,g",
         po::value<std::vector<std::string>>(),
        "RR types to be ignored.")
        ("max-block-items",
         po::value<unsigned int>(&max_block_items)->default_value(5000),
         "maximum number of items in an output block.")
        ("max-output-size",
         po::value<Size>(&max_output_size),
         "maximum size of output (uncompressed) before rotation.")
        ("output,o",
         po::value<std::string>(&output_pattern),
         "filename pattern for storing C-DNS output.")
        ("raw-pcap,w",
         po::value<std::string>(&raw_pcap_pattern),
         "filename pattern for storing raw PCAP output.")
        ("ignored-pcap,m",
         po::value<std::string>(&ignored_pcap_pattern),
         "filename pattern for storing ignored and malformed packets.")
        ("gzip-output,z",
         po::value<bool>(&gzip_output)->implicit_value(true),
         "compress C-DNS data using gzip. Adds .gz extension to output file.")
        ("gzip-level,y",
         po::value<unsigned int>(&gzip_level)->default_value(6),
         "gzip compression level.")
        ("xz-output,x",
         po::value<bool>(&xz_output)->implicit_value(true),
         "compress C-DNS data using xz. Adds .xz extension to output file.")
        ("xz-preset,u",
         po::value<unsigned int>(&xz_preset)->default_value(6),
         "xz compression preset level.")
        ("gzip-pcap,Z",
         po::value<bool>(&gzip_pcap)->implicit_value(true),
         "compress PCAP data using gzip. Adds .gz extension to output file.")
        ("gzip-level-pcap,Y",
         po::value<unsigned int>(&gzip_level_pcap)->default_value(6),
         "PCAP gzip compression level.")
        ("xz-pcap,X",
         po::value<bool>(&xz_pcap)->implicit_value(true),
         "compress PCAP data using xz. Adds .xz extension to output file.")
        ("xz-preset-pcap,U",
         po::value<unsigned int>(&xz_preset_pcap)->default_value(6),
         "PCAP xz compression preset level.")
        ("max-compression-threads",
         po::value<unsigned int>(&max_compression_threads)->default_value(2),
         "maximum number of compression threads.")
        ("log-network-stats-period,L",
         po::value<unsigned int>(&log_network_stats_period)->default_value(0),
         "log network collection stats period.")
        ;
}

po::variables_map Configuration::parse_command_line(int ac, char *av[])
{
    cmdline_vars_.clear();

    po::options_description all("Options");
    all.add(cmdline_options_).add(cmdline_hidden_options_).add(config_file_options_);

    po::store(po::command_line_parser(ac, av).options(all).positional(positional_options_).run(), cmdline_vars_);

    // If you specify a config file, it must exist.
    if ( cmdline_vars_.count("configfile") )
    {
        config_file_ = cmdline_vars_["configfile"].as<std::string>();
        if ( !boost::filesystem::exists(config_file_) )
            throw po::error("Config file " + config_file_ + " not found.");
    }

    return reread_config_file();
}

po::variables_map Configuration::reread_config_file()
{
    /*
     * Start each time from the command line results only. Config file
     * items must replace any existing values for those items that came
     * from the config file first read.
     */
    po::variables_map res = cmdline_vars_;

    if ( boost::filesystem::exists(config_file_) )
    {
        std::ifstream conf(config_file_);
        if ( conf.fail() )
            throw po::error("Can't open configuration file " + config_file_);
        po::store(po::parse_config_file(conf, config_file_options_), res);
    }

    po::notify(res);
    set_config_items(res);

    return res;
}

std::string Configuration::options_usage() const
{
    po::options_description visible("Options");
    visible.add(cmdline_options_).add(config_file_options_);
    std::ostringstream oss;
    oss << visible;
    return oss.str();
}

void Configuration::dump_config(std::ostream& os) const
{
    bool first = true;

    os << "CONFIGURATION:\n"
       << "  Query timeout        : " << query_timeout << " seconds\n"
       << "  Skew timeout         : " << skew_timeout << " microseconds\n"
       << "  Snap length          : " << snaplen << "\n"
       << "  Max block items      : " << max_block_items << "\n";
    if ( max_output_size.size > 0 )
        os << "  Max output size      : " << max_output_size.size << "\n";
    os << "  File rotation period : " << rotation_period << "\n"
       << "  Promiscuous mode     : " << (promisc_mode ? "On" : "Off") << "\n"
       << "  Capture interfaces   : ";
    for ( const auto& i : network_interfaces )
    {
        if ( first )
            first = false;
        else
            os << ", ";
        os << i;
    }
    os << "\n"
       << "  Server addresses     : ";
    first = true;
    for ( auto a : server_addresses )
    {
        if ( first )
            first = false;
        else
            os << ", ";
        os << a;
    }
    os << "\n"
       << "  VLAN IDs             : ";
    first = true;
    for ( auto v : vlan_ids )
    {
        if ( first )
            first = false;
        else
            os << ", ";
        os << v;
    }
    os << "\n"
       << "  Filter               : " << filter << "\n"
       << "  Query options        : ";
    dump_output_option(os, true);
    os << "  Response options     : ";
    dump_output_option(os, false);
    os << "  Accept RR types      : ";
    dump_RR_types(os, true);
    os << "  Ignore RR types      : ";
    dump_RR_types(os, false);
}

void Configuration::set_config_items(const po::variables_map& vm)
{
    output_options_queries = output_options_responses = 0;
    if ( vm.count("include") )
    {
        for ( const auto& s : vm["include"].as<std::vector<std::string>>() )
        {
            if ( s == "query-questions" )
                output_options_queries |= EXTRA_QUESTIONS;
            else if ( s == "query-answers" )
                output_options_queries |= ANSWERS;
            else if ( s == "query-authorities" )
                output_options_queries |= AUTHORITIES;
            else if ( s == "query-additionals" )
                output_options_queries |= ADDITIONALS;
            else if ( s == "query-all" )
                output_options_queries |= ALL;
            else if ( s == "response-questions" )
                output_options_responses |= EXTRA_QUESTIONS;
            else if ( s == "response-answers" )
                output_options_responses |= ANSWERS;
            else if ( s == "response-authorities" )
                output_options_responses |= AUTHORITIES;
            else if ( s == "response-additionals" )
                output_options_responses |= ADDITIONALS;
            else if ( s == "response-all" )
                output_options_responses = ALL;
            else if ( s == "all" )
                output_options_queries = output_options_responses = ALL;
            else
                throw po::error("invalid include value " + s + ". Valid options are:\n"
                                "  query-questions, query-answers, query-authorities, query-additionals\n"
                                "  response-questions, response-answers, response-authorities, response-additionals\n"
                                "  query-all, response-all, all");
        }
    }

    if ( gzip_level > 9 || gzip_level_pcap > 9 )
        throw po::error("gzip level must be in the range 0-9.");

    if ( xz_preset > 9 || xz_preset_pcap > 9 )
        throw po::error("xz preset level must be in the range 0-9.");

    if ( max_compression_threads < 1 )
        throw po::error("number of compression threads must be at least 1.");

    if ( snaplen == 0 )
        snaplen = 65535;

    if ( gzip_output && xz_output )
        throw po::error("You cannot select more than one C-DNS compression method.");

    if ( gzip_pcap && xz_pcap )
        throw po::error("You cannot select more than one PCAP compression method.");

    if ( vm.count("ignore-rr-type") && vm.count("accept-rr-type") )
        throw po::error("You can specify only accept-rr-type or ignore-rr-type, not both.");

    ignore_rr_types.clear();
    if ( vm.count("ignore-rr-type") )
        set_rr_type_config(ignore_rr_types, vm["ignore-rr-type"].as<std::vector<std::string>>());
    accept_rr_types.clear();
    if ( vm.count("accept-rr-type") )
        set_rr_type_config(accept_rr_types, vm["accept-rr-type"].as<std::vector<std::string>>());

    for ( const auto& ifname : network_interfaces )
        check_network_interface(ifname);

    server_addresses.clear();
    if ( vm.count("server-address-hint") )
    {
        for ( const auto& s : vm["server-address-hint"].as<std::vector<std::string>>() )
        {
            try
            {
                check_server_address(IPAddress(s));
                server_addresses.emplace_back(s);
            }
            catch (Tins::invalid_address&)
            {
                std::ostringstream oss;
                oss << "'" << s << "' is not a valid IPv4 or IPv6 address.";
                throw po::error(oss.str());
            }
        }
    }
}

void Configuration::dump_output_option(std::ostream& os, bool query) const
{
    bool first = true;
    int option = query ? output_options_queries : output_options_responses;
    for ( const auto& o : { "Extra questions", "Answers", "Authorities", "Additionals" } )
    {
        if ( option & 1 )
        {
            if ( first )
                first = false;
            else
                os << ", ";
            os << o;
        }
        option >>= 1;
    }
    os << "\n";
}

void Configuration::dump_RR_types(std::ostream& os, bool accept) const
{
    const std::vector<unsigned>& rr_types = accept ? accept_rr_types : ignore_rr_types;
    if ( !rr_types.empty() )
    {
        bool first = true;
        for ( auto rr_t : rr_types )
        {
            if ( first )
                first = false;
            else
                os << ", ";
            // For now a brute force linear search
            for ( auto rr : RR_TYPES)
            {
                if (rr.second == rr_t)
                {
                    os << rr.first;
                    break;
                }
            }
        }
    }
    os << "\n";
}

bool Configuration::output_rr_type(CaptureDNS::QueryType rr_type) const
{
    if ( !accept_rr_types.empty() )
    {
        for ( auto i : accept_rr_types )
            if ( i == rr_type )
                return true;

        return false;
    }
    else
    {
        for ( auto i : ignore_rr_types )
            if ( i == rr_type )
                return false;

        return true;
    }
}

void Configuration::populate_block_parameters(block_cbor::BlockParameters& bp) const
{
    block_cbor::StorageParameters& sp = bp.storage_parameters;
    block_cbor::StorageHints& sh = sp.storage_hints;
    block_cbor::CollectionParameters& cp = bp.collection_parameters;

    // Set storage parameter values from configuration.
    sp.max_block_items = max_block_items;

    // Query response hints. Compactor always gives time_offset to
    // response size inclusive. It does not currently give response
    // processing data.
    sh.query_response_hints = block_cbor::QueryResponseHintFlags(
        0x3ff |
        output_options_queries << 11 |
        (output_options_responses & 0xe) << 14);
    // Query response signature hints. Compactor always writes everything
    // except qr-type, where it has no data.
    sh.query_response_signature_hints =
        block_cbor::QueryResponseSignatureHintFlags(0x1f7);
    // RR hints. Compactor always writes everything.
    sh.rr_hints = block_cbor::RRHintFlags(0x3);
    // Other data hints. Compactor always writes address event hints,
    // but does not currently write malformed messages.
    sh.other_data_hints = block_cbor::OtherDataHintFlags(0x2);

    // List of opcodes recorded. Currently compactor doesn't
    // filter on opcodes, so set this to all current opcodes.
    for ( const auto op : CaptureDNS::OPCODES )
        sp.opcodes.push_back(op);

    // List of RR types recorded.
    for ( const auto rr : CaptureDNS::QUERYTYPES )
        if ( output_rr_type(rr) )
            sp.rr_types.push_back(rr);

    // Compactor currently doesn't support anonymisation,
    // sampling or name normalisation, so we don't give
    // storage flags or sampling or anonymisation methods.
    // Set collection parameter items from configuration.

    // Compactor currently doesn't support client or server address
    // prefix length setting, so we don't give that parameter.

    // Set collection parameter items from configuration.
    cp.query_timeout = query_timeout;
    cp.skew_timeout = skew_timeout;
    cp.snaplen = snaplen;
    cp.promisc = promisc_mode;

    for ( const auto& s : network_interfaces )
        cp.interfaces.push_back(s);

    for ( const auto& a : server_addresses )
        cp.server_addresses.push_back(a);

    for ( const auto& v : vlan_ids )
        cp.vlan_ids.push_back(v);

    cp.filter = filter;

    // These don't come from configuration, but ensure they are set.
    if ( !omit_sysid )
    {
        cp.generator_id = PACKAGE_STRING;

        if ( !omit_hostid )
        {
            char buf[_POSIX_HOST_NAME_MAX];
            gethostname(buf, sizeof(buf));
            buf[_POSIX_HOST_NAME_MAX - 1] = '\0';
            cp.host_id = buf;
        }
    }
}

void Configuration::set_from_block_parameters(const block_cbor::BlockParameters& bp)
{
    const block_cbor::StorageParameters& sp = bp.storage_parameters;
    const block_cbor::StorageHints& sh = sp.storage_hints;
    const block_cbor::CollectionParameters& cp = bp.collection_parameters;

    // Set configuration from storage parameter values.
    max_block_items = sp.max_block_items;

    output_options_queries = (sh.query_response_hints >> 11) & 0xf;
    output_options_responses = ((sh.query_response_hints >> 14) & 0xe) | ((sh.query_response_hints >> 11) & 1);

    // List of RR types recorded.
    for ( const auto rr : sp.rr_types )
        accept_rr_types.push_back(rr);

    // Set collection parameter items from configuration.
    query_timeout = cp.query_timeout;
    skew_timeout = cp.skew_timeout;
    snaplen = cp.snaplen;
    promisc_mode = cp.promisc;

    for ( const auto& s : cp.interfaces )
        network_interfaces.push_back(s);

    for ( const auto& a : cp.server_addresses )
        server_addresses.push_back(a);

    for ( const auto& v : cp.vlan_ids )
        vlan_ids.push_back(v);

    filter = cp.filter;
}
