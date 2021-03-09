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

#include <cmath>
#include <fstream>
#include <sstream>
#include <unordered_map>

#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>

#include <tins/network_interface.h>
#include <tins/tins.h>

#include "configuration.hpp"
#include "log.hpp"

namespace po = boost::program_options;

namespace {
    const unsigned DEFAULT_IPV4_PREFIX_LENGTH = 32;
    const unsigned DEFAULT_IPV6_PREFIX_LENGTH = 128;

    const std::unordered_map<std::string, unsigned> OPCODES = {
        { "QUERY", 0 },
        { "IQUERY", 1 },
        { "STATUS", 2 },
        { "NOTIFY", 4 },
        { "UPDATE", 5 },
        { "DSO", 6 }
    };

    const std::unordered_map<std::string, unsigned> RCODES = {
        { "NOERROR", 0 },
        { "FORMERR", 1 },
        { "SERVFAIL", 2 },
        { "NXDOMAIN", 3 },
        { "NOTIMP", 4 },
        { "REFUSED", 5 },
        { "YXDOMAIN", 6 },
        { "YXRRSET", 7 },
        { "NXRRSET", 8 },
        { "NOTAUTH", 9 },
        { "NOTZONE", 10 },
        { "DSOTYPENO", 11 },
        { "BADVERS", 16 },
        { "BADSIG", 16 },
        { "BADKEY", 17 },
        { "BADTIME", 18 },
        { "BADMODE", 19 },
        { "BADNAME", 20 },
        { "BADALG", 21 },
        { "BADTRUNC", 22 },
        { "BADCOOKIE", 23 },
    };

    const std::unordered_map<std::string, unsigned> RR_CLASSES = {
        { "INTERNET", 1 },
        { "IN", 1 },
        { "CHAOS", 2 },
        { "CH", 2 },
        { "HESIOD", 4 },
        { "HS", 4 },
        { "NONE", 254 },
        { "ANY", 255 },
    };

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
        { "CAA", 257 },
        { "TA", 32768  },
        { "DLV", 32769  },
    };

    const std::unordered_map<std::string, unsigned> RR_TYPES_ALT = {
        { "CERT", 37 },
        { "NSEC3PARAMS", 51 }
    };

    void set_opcode_config(std::vector<unsigned>& config, const std::vector<std::string>& names)
    {
        for ( const auto& s : names )
        {
            auto item = OPCODES.find(s);
            if ( item == OPCODES.end() )
                throw po::error("unknown OPCODE " + s );
            else
                config.push_back(item->second);
        }
    }

    void set_rr_type_config(std::vector<unsigned>& config, const std::vector<std::string>& names)
    {
        for ( const auto& s : names )
        {
            auto item = RR_TYPES.find(s);
            if ( item == RR_TYPES.end() )
            {
                item = RR_TYPES_ALT.find(s);
                if ( item == RR_TYPES_ALT.end() )
                    throw po::error("unknown RR type " + s );
            }
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

/**
 * \brief Overload <code>validate()</code> for Size.
 *
 * @param v             holder for result.
 * @param values        input values.
 * @param val1          compiler workaround.
 * @param val2          compiler workaround.
 */
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
      dns_port(53),
      query_timeout(5000), skew_timeout(10),
      snaplen(65535),
      promisc_mode(false),
      output_options_queries(0), output_options_responses(0),
      max_block_items(5000),
      max_output_size(0),
      report_info(false), log_network_stats_period(0),
      debug_dns(false), debug_qr(false),
      omit_hostid(false), omit_sysid(false), latest_as_end_time(false),
      max_channel_size(10000),
      client_address_prefix_ipv4(DEFAULT_IPV4_PREFIX_LENGTH),
      client_address_prefix_ipv6(DEFAULT_IPV6_PREFIX_LENGTH),
      server_address_prefix_ipv4(DEFAULT_IPV4_PREFIX_LENGTH),
      server_address_prefix_ipv6(DEFAULT_IPV6_PREFIX_LENGTH),
      config_file_(CONFFILE),
      excludes_file_(EXCLUDESFILE),
      cmdline_options_("Command options"),
      cmdline_hidden_options_("Hidden command options"),
      config_file_options_("Configuration"),
      positional_options_(),
      read_from_block_(false)
{
    cmdline_options_.add_options()
        ("help,h", "show this help message.")
        ("version,v", "show version information.")
        ("configfile,c",
         po::value<std::string>(),
         "configuration file.")
        ("excludesfile",
         po::value<std::string>(),
         "exclude hints file.")
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
        ("latest-as-end-time",
         po::value<bool>(&latest_as_end_time)->implicit_value(true),
         "use latest data time as end time if not present.")
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
         po::value<unsigned int>(),
         "rotation period for all outputs, in seconds.")
        ("query-timeout,q",
         po::value<float>(),
         "timeout period for unanswered queries, in seconds.")
        ("skew-timeout,k",
         po::value<unsigned int>(),
         "timeout period for a query to arrive after its response, in microseconds.")
        ("dns-port",
         po::value<unsigned int>(&dns_port)->default_value(53),
         "traffic to/from this port is DNS traffic.")
        ("snaplen,s",
         po::value<unsigned int>(&snaplen)->default_value(65535),
         "capture this many bytes per packet.")
        ("promiscuous-mode,p",
         po::value<bool>(&promisc_mode)->implicit_value(true),
         "put the capture interface into promiscuous mode.")
        ("interface,i",
         po::value<std::vector<std::string>>(&network_interfaces),
         "network interface from which to capture.")
        ("dnstap,T",
         po::value<bool>(&dnstap)->implicit_value(true),
         "capture from DNSTAP.")
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
        ("accept-opcode,E",
         po::value<std::vector<std::string>>(),
         "OPCODEs to be captured, if not all.")
        ("ignore-opcode,G",
         po::value<std::vector<std::string>>(),
        "OPCODEs to be ignored.")
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
        ("client-address-prefix-ipv4",
         po::value<unsigned int>(&client_address_prefix_ipv4)->default_value(32),
         "prefix length to store for client IPv4 addresses.")
        ("client-address-prefix-ipv6",
         po::value<unsigned int>(&client_address_prefix_ipv6)->default_value(128),
         "prefix length to store for client IPv6 addresses.")
        ("server-address-prefix-ipv4",
         po::value<unsigned int>(&server_address_prefix_ipv4)->default_value(32),
         "prefix length to store for server IPv4 addresses.")
        ("server-address-prefix-ipv6",
         po::value<unsigned int>(&server_address_prefix_ipv6)->default_value(128),
         "prefix length to store for server IPv6 addresses.")
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
    // If you specify an excludes file, it must exist.
    if ( cmdline_vars_.count("excludesfile") )
    {
        excludes_file_ = cmdline_vars_["excludesfile"].as<std::string>();
        if ( !boost::filesystem::exists(excludes_file_) )
            throw po::error("Exclude hints file " + excludes_file_ + " not found.");
    }
    // If you specify a defaults file, it must exist.
    if ( cmdline_vars_.count("defaultsfile") )
    {
        defaults_file_ = cmdline_vars_["defaultsfile"].as<std::string>();
        if ( !boost::filesystem::exists(defaults_file_) )
            throw po::error("Defaults file " + defaults_file_ + " not found.");
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
    if ( exclude_hints.read_excludes_file(excludes_file_) )
    {
        if ( output_options_queries != 0 || output_options_responses != 0 )
            throw po::error("Can't specify 'include' when using excludes file.");
    }
    else
        exclude_hints.set_section_excludes(output_options_queries, output_options_responses);
    exclude_hints.check_config(*this);

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
       << "  Query timeout        : " << query_timeout.count() / 1000.0 << " seconds\n"
       << "  Skew timeout         : " << skew_timeout.count() << " microseconds\n"
       << "  Snap length          : " << snaplen << "\n"
       << "  DNS port             : " << dns_port << "\n"
       << "  Max block items      : " << max_block_items << "\n";
    if ( !read_from_block_ )
    {
        if ( max_output_size.size > 0 )
            os << "  Max output size      : " << max_output_size.size << "\n";
        os << "  File rotation period : " << rotation_period.count() << "\n";
    }
    os << "  Promiscuous mode     : " << (promisc_mode ? "On" : "Off") << "\n"
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
    os << "  Accept OPCODEs       : ";
    dump_OPCODEs(os, true);
    if ( !ignore_opcodes.empty() )
    {
        os << "  Ignore OPCODEs       : ";
        dump_OPCODEs(os, false);
    }
    os << "  Accept RR types      : ";
    dump_RR_types(os, true);
    if ( !ignore_rr_types.empty() )
    {
        os << "  Ignore RR types      : ";
        dump_RR_types(os, false);
    }
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

    if ( vm.count("ignore-opcode") && vm.count("accept-opcode") )
        throw po::error("You can specify only accept-opcode or ignore-opcode, not both.");

    if ( vm.count("ignore-rr-type") && vm.count("accept-rr-type") )
        throw po::error("You can specify only accept-rr-type or ignore-rr-type, not both.");

    ignore_opcodes.clear();
    if ( vm.count("ignore-opcode") )
        set_opcode_config(ignore_opcodes, vm["ignore-opcode"].as<std::vector<std::string>>());
    accept_opcodes.clear();
    if ( vm.count("accept-opcode") )
        set_opcode_config(accept_opcodes, vm["accept-opcode"].as<std::vector<std::string>>());

    ignore_rr_types.clear();
    if ( vm.count("ignore-rr-type") )
        set_rr_type_config(ignore_rr_types, vm["ignore-rr-type"].as<std::vector<std::string>>());
    accept_rr_types.clear();
    if ( vm.count("accept-rr-type") )
        set_rr_type_config(accept_rr_types, vm["accept-rr-type"].as<std::vector<std::string>>());

    if ( vm.count("rotation-period") )
        rotation_period = std::chrono::seconds(vm["rotation-period"].as<unsigned int>());
    if ( vm.count("query-timeout") )
        query_timeout = std::chrono::milliseconds(std::lround(vm["query-timeout"].as<float>() * 1000));
    if ( vm.count("skew-timeout") )
        skew_timeout = std::chrono::microseconds(vm["skew-timeout"].as<unsigned int>());

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

void Configuration::dump_OPCODEs(std::ostream& os, bool accept) const
{
    const std::vector<unsigned>& opcodes = accept ? accept_opcodes : ignore_opcodes;
    if ( !opcodes.empty() )
    {
        bool first = true;
        for ( auto op_t : opcodes )
        {
            if ( first )
                first = false;
            else
                os << ", ";
            // For now a brute force linear search
            bool found = false;
            for ( auto op : OPCODES)
            {
                if (op.second == op_t)
                {
                    os << op.first;
                    found = true;
                    break;
                }
            }
            if ( !found )
                os << op_t;
        }
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
            bool found = false;
            for ( auto rr : RR_TYPES)
            {
                if (rr.second == rr_t)
                {
                    os << rr.first;
                    found = true;
                    break;
                }
            }
            if ( !found )
                os << rr_t;
        }
    }
    os << "\n";
}

bool Configuration::output_opcode(CaptureDNS::Opcode opcode) const
{
    if ( !accept_opcodes.empty() )
    {
        for ( auto i : accept_opcodes )
            if ( i == opcode )
                return true;

        return false;
    }
    else
    {
        for ( auto i : ignore_opcodes )
            if ( i == opcode )
                return false;

        return true;
    }
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

    sp.client_address_prefix_ipv4 = client_address_prefix_ipv4;
    sp.client_address_prefix_ipv6 = client_address_prefix_ipv6;
    sp.server_address_prefix_ipv4 = server_address_prefix_ipv4;
    sp.server_address_prefix_ipv6 = server_address_prefix_ipv6;

    sh.query_response_hints = exclude_hints.get_query_response_hints();
    sh.query_response_signature_hints =
        exclude_hints.get_query_response_signature_hints();
    sh.rr_hints = exclude_hints.get_rr_hints();
    sh.other_data_hints = exclude_hints.get_other_data_hints();

    // List of opcodes recorded.
    for ( const auto op : CaptureDNS::OPCODES )
        if ( output_opcode(op) )
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
    cp.dns_port = dns_port;
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

    // Mark this configuration as read from block parameters, so we know
    // which items won't be present.
    read_from_block_ = true;

    // Set configuration from storage parameter values.
    max_block_items = sp.max_block_items;

    exclude_hints.set_query_response_hints(sh.query_response_hints);
    exclude_hints.get_section_excludes(output_options_queries, output_options_responses);
    exclude_hints.set_query_response_signature_hints(sh.query_response_signature_hints);
    exclude_hints.set_rr_hints(sh.rr_hints);
    exclude_hints.set_other_data_hints(sh.other_data_hints);

    client_address_prefix_ipv4 = sp.client_address_prefix_ipv4;
    client_address_prefix_ipv6 = sp.client_address_prefix_ipv6;
    server_address_prefix_ipv4 = sp.server_address_prefix_ipv4;
    server_address_prefix_ipv6 = sp.server_address_prefix_ipv6;

    // List of OPCODEs recorded.
    for ( const auto op : sp.opcodes )
        accept_opcodes.push_back(op);

    // List of RR types recorded.
    for ( const auto rr : sp.rr_types )
        accept_rr_types.push_back(rr);

    // Set collection parameter items from configuration.
    query_timeout = cp.query_timeout;
    skew_timeout = cp.skew_timeout;
    snaplen = cp.snaplen;
    dns_port = cp.dns_port;
    promisc_mode = cp.promisc;

    for ( const auto& s : cp.interfaces )
        network_interfaces.push_back(s);

    for ( const auto& a : cp.server_addresses )
        server_addresses.push_back(a);

    for ( const auto& v : cp.vlan_ids )
        vlan_ids.push_back(v);

    filter = cp.filter;

    exclude_hints.check_config(*this);
}

/**
 * \brief Overload <code>validate()</code> for IPAddress.
 *
 * @param v             holder for result.
 * @param values        input values.
 * @param val1          compiler workaround.
 * @param val2          compiler workaround.
 */
void validate(boost::any& v, const std::vector<std::string>& values,
              IPAddress* val1, int val2)
{
    po::validators::check_first_occurrence(v);
    std::string s = po::validators::get_single_string(values);

    try
    {
        v = IPAddress(s);
    }
    catch (Tins::invalid_address&)
    {
        throw po::validation_error(po::validation_error::invalid_option_value);
    }
}

/**
 * \brief Overload <code>validate()</code> for CaptureDNS::Opcode.
 *
 * @param v             holder for result.
 * @param values        input values.
 * @param val1          compiler workaround.
 * @param val2          compiler workaround.
 */
void validate(boost::any& v, const std::vector<std::string>& values,
              CaptureDNS::Opcode* val1, int val2)
{
    po::validators::check_first_occurrence(v);
    std::string s = po::validators::get_single_string(values);
    boost::algorithm::to_upper(s);

    auto item = OPCODES.find(s);
    if ( item == OPCODES.end() )
        throw po::validation_error(po::validation_error::invalid_option_value);
    else
        v = CaptureDNS::Opcode(item->second);
}

/**
 * \brief Overload <code>validate()</code> for CaptureDNS:Rcode.
 *
 * @param v             holder for result.
 * @param values        input values.
 * @param val1          compiler workaround.
 * @param val2          compiler workaround.
 */
void validate(boost::any& v, const std::vector<std::string>& values,
              CaptureDNS::Rcode* val1, int val2)
{
    po::validators::check_first_occurrence(v);
    std::string s = po::validators::get_single_string(values);
    boost::algorithm::to_upper(s);

    auto item = RCODES.find(s);
    if ( item == RCODES.end() )
        throw po::validation_error(po::validation_error::invalid_option_value);
    else
        v = CaptureDNS::Rcode(item->second);
}

/**
 * \brief Overload <code>validate()</code> for CaptureDNS::QueryClass.
 *
 * @param v             holder for result.
 * @param values        input values.
 * @param val1          compiler workaround.
 * @param val2          compiler workaround.
 */
void validate(boost::any& v, const std::vector<std::string>& values,
              CaptureDNS::QueryClass* val1, int val2)
{
    po::validators::check_first_occurrence(v);
    std::string s = po::validators::get_single_string(values);
    boost::algorithm::to_upper(s);

    auto item = RR_CLASSES.find(s);
    if ( item == RR_CLASSES.end() )
        throw po::validation_error(po::validation_error::invalid_option_value);
    else
        v = CaptureDNS::QueryClass(item->second);
}

/**
 * \brief Overload <code>validate()</code> for CaptureDNS::QueryType.
 *
 * @param v             holder for result.
 * @param values        input values.
 * @param val1          compiler workaround.
 * @param val2          compiler workaround.
 */
void validate(boost::any& v, const std::vector<std::string>& values,
              CaptureDNS::QueryType* val1, int val2)
{
    po::validators::check_first_occurrence(v);
    std::string s = po::validators::get_single_string(values);
    boost::algorithm::to_upper(s);

    auto item = RR_TYPES.find(s);
    if ( item == RR_TYPES.end() )
    {
        item = RR_TYPES_ALT.find(s);
        if ( item == RR_TYPES_ALT.end() )
            throw po::validation_error(po::validation_error::invalid_option_value);
    }
    v = CaptureDNS::QueryType(item->second);
}

/**
 * \brief Overload <code>validate()</code> for AddressEvent::EventTypes.
 *
 * @param v             holder for result.
 * @param values        input values.
 * @param val1          compiler workaround.
 * @param val2          compiler workaround.
 */
void validate(boost::any& v, const std::vector<std::string>& values,
              AddressEvent::EventType* val1, int val2)
{
    po::validators::check_first_occurrence(v);
    std::string s = po::validators::get_single_string(values);

    boost::algorithm::trim(s);
    boost::algorithm::to_lower(s);
    AddressEvent::EventType aet;

    if ( s == "tcp-reset" )
        aet = AddressEvent::TCP_RESET;
    else if ( s == "icmp-time-exceeded" )
        aet = AddressEvent::ICMP_TIME_EXCEEDED;
    else if ( s == "icmp-dest-unreachable" )
        aet = AddressEvent::ICMP_DEST_UNREACHABLE;
    else if ( s == "icmpv6-time-exceeded" )
        aet = AddressEvent::ICMPv6_TIME_EXCEEDED;
    else if ( s == "icmpv6-dest-unreachable" )
        aet = AddressEvent::ICMPv6_DEST_UNREACHABLE;
    else if ( s == "icmpv6-packet-too-big" )
        aet = AddressEvent::ICMPv6_PACKET_TOO_BIG;
    else
        throw po::validation_error(po::validation_error::invalid_option_value);

    v = aet;
}

// For items declared in their own namespace, validators need to be
// (a) declared in that namespace, and (b) explicitly for
// boost::optional<type>.
namespace block_cbor {

    /**
     * \brief Overload <code>validate()</code> for TransportFlags.
     *
     * @param v             holder for result.
     * @param values        input values.
     * @param val1          compiler workaround.
     * @param val2          compiler workaround.
     */
    void validate(boost::any& v, const std::vector<std::string>& values,
                  TransportFlags* val1, int val2)
    {
        po::validators::check_first_occurrence(v);
        std::string s = po::validators::get_single_string(values);
        std::vector<std::string> tokens;
        boost::algorithm::to_lower(s);
        boost::split(tokens, s, boost::is_any_of("| "), boost::token_compress_on);
        uint8_t tf = 0;
        bool seen_ip = false, seen_proto = false, seen_trailing = false;

        for ( const auto& tok : tokens )
        {
            if ( tok == "ipv4" || tok == "ipv6" )
            {
                if ( seen_ip )
                    throw po::validation_error(po::validation_error::multiple_values_not_allowed);
                seen_ip = true;
                if ( tok == "ipv6" )
                    tf |= IPV6;
            }
            else if ( tok == "trailing-data" )
            {
                if ( seen_trailing )
                    throw po::validation_error(po::validation_error::multiple_values_not_allowed);
                seen_trailing = true;
                tf |= QUERY_TRAILINGDATA;
            }
            else if ( tok == "udp" || tok == "tcp" || tok == "tls" ||
                      tok == "dtls" || tok == "doh" )
            {
                if ( seen_proto )
                    throw po::validation_error(po::validation_error::multiple_values_not_allowed);
                seen_proto = true;
                if ( tok == "tcp" )
                    tf |= TCP;
                else if ( tok == "tls" )
                    tf |= TLS;
                else if ( tok == "dtls" )
                    tf |= DTLS;
                else if ( tok == "doh" )
                    tf |= DOH;
            }
            else
                throw po::validation_error(po::validation_error::invalid_option_value);
        }

        v = TransportFlags(tf);
    }

    /**
     * \brief Overload <code>validate()</code> for QueryResponseFlags.
     *
     * @param v             holder for result.
     * @param values        input values.
     * @param val1          compiler workaround.
     * @param val2          compiler workaround.
     */
    void validate(boost::any& v, const std::vector<std::string>& values,
                  QueryResponseFlags* val1, int val2)
    {
        po::validators::check_first_occurrence(v);
        std::string s = po::validators::get_single_string(values);
        std::vector<std::string> tokens;
        boost::algorithm::to_lower(s);
        boost::split(tokens, s, boost::is_any_of("| "), boost::token_compress_on);
        uint8_t qrf = 0;

        for ( const auto& tok : tokens )
        {
            if ( tok == "has-query" )
                qrf |= HAS_QUERY;
            else if ( tok == "has-response" )
                qrf |= HAS_RESPONSE;
            else if ( tok == "query-has-opt" )
                qrf |= QUERY_HAS_OPT;
            else if ( tok == "response-has-opt" )
                qrf |= RESPONSE_HAS_OPT;
            else if ( tok == "query-has-no-question" )
                qrf |= QUERY_HAS_NO_QUESTION;
            else if ( tok == "response-has-no-question" )
                qrf |= RESPONSE_HAS_NO_QUESTION;
            else if ( !tok.empty() )
                throw po::validation_error(po::validation_error::invalid_option_value);
        }

        v = QueryResponseFlags(qrf);
    }

    /**
     * \brief Overload <code>validate()</code> for QueryResponseType.
     *
     * @param v             holder for result.
     * @param values        input values.
     * @param val1          compiler workaround.
     * @param val2          compiler workaround.
     */
    void validate(boost::any& v, const std::vector<std::string>& values,
                  QueryResponseType* val1, int val2)
    {
        po::validators::check_first_occurrence(v);
        std::string s = po::validators::get_single_string(values);
        boost::algorithm::trim(s);
        boost::algorithm::to_lower(s);
        QueryResponseType qrt;

        if ( s == "query" )
            qrt = QueryResponseType::STUB;
        else if ( s == "client" )
            qrt = QueryResponseType::CLIENT;
        else if ( s == "resolver" )
            qrt = QueryResponseType::RESOLVER;
        else if ( s == "auth" )
            qrt = QueryResponseType::AUTHORITATIVE;
        else if ( s == "forwarder" )
            qrt = QueryResponseType::FORWARDER;
        else if ( s == "tool" )
            qrt = QueryResponseType::TOOL;
        else
            throw po::validation_error(po::validation_error::invalid_option_value);

        v = qrt;
    }

    /**
     * \brief Overload <code>validate()</code> for DNSFlags.
     *
     * @param v             holder for result.
     * @param values        input values.
     * @param val1          compiler workaround.
     * @param val2          compiler workaround.
     */
    void validate(boost::any& v, const std::vector<std::string>& values,
                  DNSFlags* val1, int val2)
    {
        po::validators::check_first_occurrence(v);
        std::string s = po::validators::get_single_string(values);
        std::vector<std::string> tokens;
        boost::algorithm::to_lower(s);
        boost::split(tokens, s, boost::is_any_of("| "), boost::token_compress_on);
        uint16_t dnsf = 0;

        for ( const auto& tok : tokens )
        {
            if ( tok == "query-cd" )
                dnsf |= QUERY_CD;
            else if ( tok == "response-cd" )
                dnsf |= RESPONSE_CD;
            else if ( tok == "query-ad" )
                dnsf |= QUERY_AD;
            else if ( tok == "response-ad" )
                dnsf |= RESPONSE_AD;
            else if ( tok == "query-z" )
                dnsf |= QUERY_Z;
            else if ( tok == "response-z" )
                dnsf |= RESPONSE_Z;
            else if ( tok == "query-ra" )
                dnsf |= QUERY_RA;
            else if ( tok == "response-ra" )
                dnsf |= RESPONSE_RA;
            else if ( tok == "query-rd" )
                dnsf |= QUERY_RD;
            else if ( tok == "response-rd" )
                dnsf |= RESPONSE_RD;
            else if ( tok == "query-tc" )
                dnsf |= QUERY_TC;
            else if ( tok == "response-tc" )
                dnsf |= RESPONSE_TC;
            else if ( tok == "query-aa" )
                dnsf |= QUERY_AA;
            else if ( tok == "response-aa" )
                dnsf |= RESPONSE_AA;
            else if ( tok == "query-do" )
                dnsf |= QUERY_DO;
            else if ( !tok.empty() )
                throw po::validation_error(po::validation_error::invalid_option_value);
        }

        v = DNSFlags(dnsf);
    }
}

// For items declared in their own namespace, validators need to be
// (a) declared in that namespace, and (b) explicitly for
// boost::optional<type>.
namespace std {
    namespace chrono {

        /**
         * \brief Overload <code>validate()</code> for std::chrono::microseconds.
         *
         * @param v             holder for result.
         * @param values        input values.
         * @param val1          compiler workaround.
         * @param val2          compiler workaround.
         */
        void validate(boost::any& v, const std::vector<std::string>& values,
                      nanoseconds* val1, int val2)
        {
            po::validators::check_first_occurrence(v);
            std::string s = po::validators::get_single_string(values);
            boost::algorithm::trim(s);
            std::stringstream ss(s);
            uint64_t val;
            std::string suffix;

            ss >> val;
            if ( !ss )
                throw po::validation_error(po::validation_error::invalid_option_value);
            ss >> suffix;
            if ( !ss )
                throw po::validation_error(po::validation_error::invalid_option_value);

            if ( suffix == "ns" )
                v = nanoseconds(val);
            else if ( suffix == "us" )
            {
                microseconds ns(val);
                v = duration_cast<nanoseconds>(ns);
            }
            else if ( suffix == "ms" )
            {
                milliseconds ms(val);
                v = duration_cast<nanoseconds>(ms);
            }
            else if ( suffix == "s" )
            {
                seconds s(val);
                v = duration_cast<nanoseconds>(s);
            }
            else
                throw po::validation_error(po::validation_error::invalid_option_value);
        }

    }
}

Defaults::Defaults()
    : defaults_file_read(false)
{
}

void Defaults::read_defaults_file(const std::string& defaultsfile)
{
    po::variables_map res;
    boost::program_options::options_description opt;

    // Although theoretically one should be able to use the program options
    // magic with boost::optional, in practice I've found that I can't
    // get it working. So instead I'm going the simple way, setting local
    // values and copying into the default optionals if the corresponding
    // argument was actually set.
    std::chrono::nanoseconds time_offset;
    std::chrono::nanoseconds response_delay;
    IPAddress client_address;
    uint16_t client_port = 0;
    unsigned client_hoplimit = 0;
    IPAddress server_address;
    uint16_t server_port = 0;
    block_cbor::TransportFlags transport;
    uint16_t transaction_id = 0;
    CaptureDNS::Opcode query_opcode;
    CaptureDNS::Rcode query_rcode;
    block_cbor::DNSFlags dns_flags;
    CaptureDNS::Rcode response_rcode;
    uint16_t query_qdcount = 0;
    uint16_t query_ancount = 0;
    uint16_t query_arcount = 0;
    uint16_t query_nscount = 0;
    byte_string query_name;
    CaptureDNS::QueryClass query_class;
    CaptureDNS::QueryType query_type;
    uint32_t rr_ttl = 0;
    byte_string rr_rdata;
    uint16_t query_udp_size = 0;
    byte_string query_opt_rdata;
    unsigned query_edns_version = 0;
    block_cbor::QueryResponseType qr_type = block_cbor::QueryResponseType::CLIENT;
    std::string response_processing_bailiwick;
    bool response_processing_from_cache = false;
    uint16_t query_size = 0;
    uint16_t response_size = 0;
    AddressEvent::EventType ae_type = AddressEvent::TCP_RESET;
    unsigned ae_code = 0;
    IPAddress ae_address;

    opt.add_options()
        ("ip-header.time-offset",
         po::value(&time_offset),
         "time offset default.")
        ("ip-header.response-delay",
         po::value(&response_delay),
         "response delay default.")
        ("ip-header.client-address",
         po::value(&client_address),
         "client address default.")
        ("ip-header.client-port",
         po::value(&client_port),
         "client port default.")
        ("ip-header.client-hoplimit",
         po::value(&client_hoplimit),
         "client hoplimit default.")
        ("ip-header.server-address",
         po::value(&server_address),
         "server address default.")
        ("ip-header.server-port",
         po::value(&server_port),
         "server port default.")
        ("ip-header.qr-transport-flags",
         po::value(&transport),
         "transport flags default.")

        ("dns-header.transaction-id",
         po::value(&transaction_id),
         "transaction id default.")
        ("dns-header.query-opcode",
         po::value(&query_opcode),
         "query opcode default.")
        ("dns-header.query-rcode",
         po::value(&query_rcode),
         "query rcode default.")
        ("dns-header.dns-flags",
         po::value(&dns_flags),
         "DNS flags default.")
        ("dns-header.response-rcode",
         po::value(&response_rcode),
         "response rcode default.")

        ("dns-payload.query-name",
         po::value<std::string>(),
         "query name default.")
        ("dns-payload.query-class",
         po::value(&query_class),
         "query class default.")
        ("dns-payload.query-type",
         po::value(&query_type),
         "query type default.")
        ("dns-payload.rr-ttl",
         po::value(&rr_ttl),
         "RR TTL default.")
        ("dns-payload.query-udp-size",
         po::value(&query_udp_size),
         "query UDP size default.")
        ("dns-payload.query-edns-version",
         po::value(&query_edns_version),
         "query EDNS version default.")
        ;

    if ( boost::filesystem::exists(defaultsfile) )
    {
        std::ifstream defaults(defaultsfile);
        if ( defaults.fail() )
            throw po::error("Can't open defaults file " + defaultsfile);
        po::store(po::parse_config_file(defaults, opt), res);
        defaults_file_read = true;
    }

    po::notify(res);

    if ( res.count("ip-header.time-offset") )
        this->time_offset = time_offset;
    if ( res.count("ip-header.response-delay") )
        this->response_delay = response_delay;
    if ( res.count("ip-header.client-address") )
        this->client_address = client_address;
    if ( res.count("ip-header.client-port") )
        this->client_port = client_port;
    if ( res.count("ip-header.client-hoplimit") )
        this->client_hoplimit = client_hoplimit;
    if ( res.count("ip-header.server-address") )
        this->server_address = server_address;
    if ( res.count("ip-header.server-port") )
        this->server_port = server_port;
    if ( res.count("ip-header.qr-transport-flags") )
        this->transport = transport;

    if ( res.count("dns-header.transaction-id") )
        this->transaction_id = transaction_id;
    if ( res.count("dns-header.query-opcode") )
        this->query_opcode = query_opcode;
    if ( res.count("dns-header.query-rcode") )
        this->query_rcode = query_rcode;
    if ( res.count("dns-header.dns-flags") )
        this->dns_flags = dns_flags;
    if ( res.count("dns-header.response-rcode") )
        this->response_rcode = response_rcode;
    if ( res.count("dns-header.query-qdcount") )
        this->query_qdcount = query_qdcount;
    if ( res.count("dns-header.query-ancount") )
        this->query_ancount = query_ancount;
    if ( res.count("dns-header.query-arcount") )
        this->query_arcount = query_arcount;
    if ( res.count("dns-header.query-nscount") )
        this->query_nscount = query_nscount;

    if ( res.count("dns-payload.query-name") )
        this->query_name = CaptureDNS::encode_domain_name(res["dns-payload.query-name"].as<std::string>());
    if ( res.count("dns-payload.query-class") )
        this->query_class = query_class;
    if ( res.count("dns-payload.query-type") )
        this->query_type = query_type;
    if ( res.count("dns-payload.rr-ttl") )
        this->rr_ttl = rr_ttl;
    this->rr_rdata = byte_string();
    if ( res.count("dns-payload.query-udp-size") )
        this->query_udp_size = query_udp_size;
    this->query_opt_rdata = byte_string();
    if ( res.count("dns-payload.query-edns-version") )
        this->query_edns_version = query_edns_version;

    if ( res.count("dns-meta-data.qr-type") )
        this->qr_type = qr_type;
    if ( res.count("dns-meta-data.response-processing-bailiwick") )
        this->response_processing_bailiwick = response_processing_bailiwick;
    if ( res.count("dns-meta-data.response-processing-from-cache") )
        this->response_processing_from_cache = response_processing_from_cache;
    if ( res.count("dns-meta-data.query-size") )
        this->query_size = query_size;
    if ( res.count("dns-meta-data.response-size") )
        this->response_size = response_size;

    if ( res.count("address-event.ae-address" ) )
        this->ae_address = ae_address;
    if ( res.count("address-event.ae-type" ) )
        this->ae_type = ae_type;
    if ( res.count("address-event.ae-code" ) )
        this->ae_code = ae_code;
}

HintsExcluded::HintsExcluded()
    : timestamp(false),
      client_address(false), client_port(false), client_hoplimit(false),
      server_address(false), server_port(false),
      transport(false),
      transaction_type(false),
      qr_flags(false),
      transaction_id(false),
      qr_signature(false),
      query_opcode(false),
      dns_flags(false),
      query_rcode(false),
      query_name(false),
      query_class_type(false),
      query_qdcount(false), query_ancount(false), query_nscount(false), query_arcount(false),
      query_size(false),
      query_udp_size(false), query_edns_version(false), query_opt_rdata(false),
      query_question_section(false), query_answer_section(false),
      query_authority_section(false), query_additional_section(false),
      response_delay(false),
      response_rcode(false),
      response_size(false),
      response_answer_section(false),
      response_authority_section(false), response_additional_section(false),
      rr_ttl(false), rr_rdata(false),
      address_events(false),
      query_type(true),
      response_processing(true),
      malformed_messages(true)

{
    excludes_file_options_.add_options()
        ("ip-header.time-offset",
         po::value<bool>(&timestamp)->implicit_value(true)->default_value(false),
         "exclude timestamp data.")
        ("ip-header.response-delay",
         po::value<bool>(&response_delay)->implicit_value(true)->default_value(false),
         "exclude response delay data.")
        ("ip-header.client-address",
         po::value<bool>(&client_address)->implicit_value(true)->default_value(false),
         "exclude client address data.")
        ("ip-header.client-port",
         po::value<bool>(&client_port)->implicit_value(true)->default_value(false),
         "exclude client port data.")
        ("ip-header.client-hoplimit",
         po::value<bool>(&client_hoplimit)->implicit_value(true)->default_value(false),
         "exclude client hoplimit data.")
        ("ip-header.server-address",
         po::value<bool>(&server_address)->implicit_value(true)->default_value(false),
         "exclude server address data.")
        ("ip-header.server-port",
         po::value<bool>(&server_port)->implicit_value(true)->default_value(false),
         "exclude server port data.")
        ("ip-header.qr-transport-flags",
         po::value<bool>(&transport)->implicit_value(true)->default_value(false),
         "exclude transport data.")

        ("dns-header.transaction-id",
         po::value<bool>(&transaction_id)->implicit_value(true)->default_value(false),
         "exclude transaction IDs.")
        ("dns-header.query-opcode",
         po::value<bool>(&query_opcode)->implicit_value(true)->default_value(false),
         "exclude query OPCODEs.")
        ("dns-header.query-rcode",
         po::value<bool>(&query_rcode)->implicit_value(true)->default_value(false),
         "exclude query RCODEs.")
        ("dns-header.dns-flags",
         po::value<bool>(&dns_flags)->implicit_value(true)->default_value(false),
         "exclude DNS flags.")
        ("dns-header.response-rcode",
         po::value<bool>(&response_rcode)->implicit_value(true)->default_value(false),
         "exclude response RCODEs.")
        ("dns-header.query-qdcount",
         po::value<bool>(&query_qdcount)->implicit_value(true)->default_value(false),
         "exclude query QDCOUNTs.")
        ("dns-header.query-ancount",
         po::value<bool>(&query_ancount)->implicit_value(true)->default_value(false),
         "exclude query ARCOUNTs.")
        ("dns-header.query-arcount",
         po::value<bool>(&query_arcount)->implicit_value(true)->default_value(false),
         "exclude query ARCOUNTs.")
        ("dns-header.query-nscount",
         po::value<bool>(&query_nscount)->implicit_value(true)->default_value(false),
         "exclude query NSCOUNTs.")

        ("dns-payload.query-name",
         po::value<bool>(&query_name)->implicit_value(true)->default_value(false),
         "exclude query NAMEs.")
        ("dns-payload.query-class-type",
         po::value<bool>(&query_class_type)->implicit_value(true)->default_value(false),
         "exclude query CLASS and TYPEs.")
        ("dns-payload.rr-ttl",
         po::value<bool>(&rr_ttl)->implicit_value(true)->default_value(false),
         "exclude RR TTLs.")
        ("dns-payload.rr-rdata",
         po::value<bool>(&rr_rdata)->implicit_value(true)->default_value(false),
         "exclude RR RDATA.")
        ("dns-payload.query-udp-size",
         po::value<bool>(&query_udp_size)->implicit_value(true)->default_value(false),
         "exclude query UDP size.")
        ("dns-payload.query-edns-version",
         po::value<bool>(&query_edns_version)->implicit_value(true)->default_value(false),
         "exclude query EDNS version.")
        ("dns-payload.query-opt-rdata",
         po::value<bool>(&query_opt_rdata)->implicit_value(true)->default_value(false),
         "exclude query OPT RDATA.")
        ("dns-payload.query-question-sections",
         po::value<bool>(&query_question_section)->implicit_value(true)->default_value(false),
         "exclude query second or subsequent question sections.")
        ("dns-payload.query-answer-sections",
         po::value<bool>(&query_answer_section)->implicit_value(true)->default_value(false),
         "exclude query answer sections.")
        ("dns-payload.query-authority-sections",
         po::value<bool>(&query_authority_section)->implicit_value(true)->default_value(false),
         "exclude query authority sections.")
        ("dns-payload.query-additional-sections",
         po::value<bool>(&query_additional_section)->implicit_value(true)->default_value(false),
         "exclude query additional sections.")
        ("dns-payload.response-answer-sections",
         po::value<bool>(&response_answer_section)->implicit_value(true)->default_value(false),
         "exclude response answer sections.")
        ("dns-payload.response-authority-sections",
         po::value<bool>(&response_authority_section)->implicit_value(true)->default_value(false),
         "exclude response authority sections.")
        ("dns-payload.response-additional-sections",
         po::value<bool>(&response_additional_section)->implicit_value(true)->default_value(false),
         "exclude response additional sections.")

        ("dns-meta-data.qr-type",
         po::value<bool>(&transaction_type)->implicit_value(true)->default_value(false),
         "exclude transaction type data.")
        ("dns-meta-data.qr-sig-flags",
         po::value<bool>(&qr_flags)->implicit_value(true)->default_value(false),
         "exclude query response flags.")
        ("dns-meta-data.query-size",
         po::value<bool>(&query_size)->implicit_value(true)->default_value(false),
         "exclude query size.")
        ("dns-meta-data.response-size",
         po::value<bool>(&response_size)->implicit_value(true)->default_value(false),
         "exclude response size.")

        ("storage-meta-data.address-events",
         po::value<bool>(&address_events)->implicit_value(true)->default_value(false),
         "exclude address events.")
        ;
}

void HintsExcluded::set_section_excludes(int output_options_queries, int output_options_responses)
{
    query_question_section = !(output_options_queries & Configuration::EXTRA_QUESTIONS);
    query_answer_section = !(output_options_queries & Configuration::ANSWERS);
    query_additional_section = !(output_options_queries & Configuration::ADDITIONALS);
    query_authority_section = !(output_options_queries & Configuration::AUTHORITIES);

    response_answer_section = !(output_options_responses & Configuration::ANSWERS);
    response_additional_section = !(output_options_responses & Configuration::ADDITIONALS);
    response_authority_section = !(output_options_responses & Configuration::AUTHORITIES);
}

void HintsExcluded::get_section_excludes(int& output_options_queries, int& output_options_responses) const
{
    output_options_queries = output_options_responses = 0;

    if ( !query_question_section )
    {
        output_options_queries |= Configuration::EXTRA_QUESTIONS;
        // Backwards compatible setting.
        output_options_responses |= Configuration::EXTRA_QUESTIONS;
    }
    if ( !query_answer_section )
        output_options_queries |= Configuration::ANSWERS;
    if ( !query_authority_section )
        output_options_queries |= Configuration::AUTHORITIES;
    if ( !query_additional_section )
        output_options_queries |= Configuration::ADDITIONALS;

    if ( !response_answer_section )
        output_options_responses |= Configuration::ANSWERS;
    if ( !response_authority_section )
        output_options_responses |= Configuration::AUTHORITIES;
    if ( !response_additional_section )
        output_options_responses |= Configuration::ADDITIONALS;
}

bool HintsExcluded::read_excludes_file(const std::string& excludesfile)
{
    po::variables_map res;
    bool exists = false;

    if ( boost::filesystem::exists(excludesfile) )
    {
        std::ifstream excludes(excludesfile);
        if ( excludes.fail() )
            throw po::error("Can't open excludes file " + excludesfile);

        // Program Options requires a non-section line has a '='.
        // So pre-process input and add one if required.
        std::string config;
        for ( std::string line; getline(excludes, line); )
        {
            std::string::size_type n;

            if ( ( n = line.find('#')) != std::string::npos )
                line = line.substr(0, n);
            boost::algorithm::trim(line);
            if ( !line.empty() &&
                 *line.begin() != '[' &&
                 line.find('=') == std::string::npos )
                line.append(1, '=');
            config.append(line);
            config.append(1, '\n');
        }

        std::istringstream is(config);
        po::store(po::parse_config_file(is, excludes_file_options_), res);
        exists = true;
    }

    po::notify(res);
    qr_signature = ( server_address && server_port && transport && transaction_type &&
                     qr_flags && query_opcode && dns_flags &&
                     query_rcode && query_class_type &&
                     query_qdcount && query_ancount && query_nscount &&
                     query_arcount && query_edns_version &&
                     query_udp_size && query_opt_rdata && response_rcode );
    return exists;
}

block_cbor::QueryResponseHintFlags HintsExcluded::get_query_response_hints() const
{
    unsigned res = 0;

    if ( !timestamp )
        res |= block_cbor::TIME_OFFSET;
    if ( !client_address )
        res |= block_cbor::CLIENT_ADDRESS_INDEX;
    if ( !client_port )
        res |= block_cbor::CLIENT_PORT;
    if ( !transaction_id )
        res |= block_cbor::TRANSACTION_ID;
    res |= block_cbor::QR_SIGNATURE_INDEX;
    if ( !client_hoplimit )
        res |= block_cbor::CLIENT_HOPLIMIT;
    if ( !response_delay )
        res |= block_cbor::RESPONSE_DELAY;
    if ( !query_name )
        res |= block_cbor::QUERY_NAME_INDEX;
    if ( !query_size )
        res |= block_cbor::QUERY_SIZE;
    if ( !response_size )
        res |= block_cbor::RESPONSE_SIZE;
    if ( !query_question_section )
        res |= block_cbor::QUERY_QUESTION_SECTIONS;
    if ( !query_answer_section )
        res |= block_cbor::QUERY_ANSWER_SECTIONS;
    if ( !query_authority_section )
        res |= block_cbor::QUERY_AUTHORITY_SECTIONS;
    if ( !query_additional_section )
        res |= block_cbor::QUERY_ADDITIONAL_SECTIONS;
    if ( !response_answer_section )
        res |= block_cbor::RESPONSE_ANSWER_SECTIONS;
    if ( !response_authority_section )
        res |= block_cbor::RESPONSE_AUTHORITY_SECTIONS;
    if ( !response_additional_section )
        res |= block_cbor::RESPONSE_ADDITIONAL_SECTIONS;

    return block_cbor::QueryResponseHintFlags(res);
}

void HintsExcluded::set_query_response_hints(block_cbor::QueryResponseHintFlags hints)
{
    timestamp = !( hints & block_cbor::TIME_OFFSET );
    client_address = !( hints & block_cbor::CLIENT_ADDRESS_INDEX );
    client_port = !( hints & block_cbor::CLIENT_PORT );
    transaction_id = !( hints & block_cbor::TRANSACTION_ID );
    client_hoplimit = !( hints & block_cbor::CLIENT_HOPLIMIT );
    response_delay = !( hints & block_cbor::RESPONSE_DELAY );
    query_name = !( hints & block_cbor::QUERY_NAME_INDEX );
    query_size = !( hints & block_cbor::QUERY_SIZE );
    response_size = !( hints & block_cbor::RESPONSE_SIZE );
    response_processing = !( hints & block_cbor::RESPONSE_PROCESSING_DATA );
    query_question_section = !( hints & block_cbor::QUERY_QUESTION_SECTIONS );
    query_answer_section = !( hints & block_cbor::QUERY_ANSWER_SECTIONS );
    query_authority_section = !( hints & block_cbor::QUERY_AUTHORITY_SECTIONS );
    query_additional_section = !( hints & block_cbor::QUERY_ADDITIONAL_SECTIONS );
    response_answer_section = !( hints & block_cbor::RESPONSE_ANSWER_SECTIONS );
    response_authority_section = !( hints & block_cbor::RESPONSE_AUTHORITY_SECTIONS );
    response_additional_section = !( hints & block_cbor::RESPONSE_ADDITIONAL_SECTIONS );
}

block_cbor::QueryResponseSignatureHintFlags HintsExcluded::get_query_response_signature_hints() const
{
    unsigned res = 0;

    if ( !server_address )
        res |= block_cbor::SERVER_ADDRESS;
    if ( !server_port )
        res |= block_cbor::SERVER_PORT;
    if ( !transport )
        res |= block_cbor::QR_TRANSPORT_FLAGS;
    if ( !transaction_type )
        res |= block_cbor::QR_TYPE;
    if ( !qr_flags )
        res |= block_cbor::QR_SIG_FLAGS;
    if ( !query_opcode )
        res |= block_cbor::QUERY_OPCODE;
    if ( !dns_flags )
        res |= block_cbor::DNS_FLAGS;
    if ( !query_rcode )
        res |= block_cbor::QUERY_RCODE;
    if ( !query_class_type )
        res |= block_cbor::QUERY_CLASS_TYPE;
    if ( !query_qdcount )
        res |= block_cbor::QUERY_QDCOUNT;
    if ( !query_ancount )
        res |= block_cbor::QUERY_ANCOUNT;
    if ( !query_arcount )
        res |= block_cbor::QUERY_ARCOUNT;
    if ( !query_nscount )
        res |= block_cbor::QUERY_NSCOUNT;
    if ( !query_edns_version )
        res |= block_cbor::QUERY_EDNS_VERSION;
    if ( !query_udp_size )
        res |= block_cbor::QUERY_UDP_SIZE;
    if ( !query_opt_rdata )
        res |= block_cbor::QUERY_OPT_RDATA;
    if ( !response_rcode )
        res |= block_cbor::RESPONSE_RCODE;

    return block_cbor::QueryResponseSignatureHintFlags(res);
}

void HintsExcluded::set_query_response_signature_hints(block_cbor::QueryResponseSignatureHintFlags hints)
{
    server_address = !( hints & block_cbor::SERVER_ADDRESS );
    server_port = !( hints & block_cbor::SERVER_PORT );
    transport = !( hints & block_cbor::QR_TRANSPORT_FLAGS );
    transaction_type = !( hints & block_cbor::QR_TYPE );
    qr_flags = !(hints & block_cbor::QR_SIG_FLAGS );
    query_type = !( hints & block_cbor::QR_TYPE );
    query_opcode = !( hints & block_cbor::QUERY_OPCODE );
    dns_flags = !( hints & block_cbor::DNS_FLAGS );
    query_rcode = !( hints & block_cbor::QUERY_RCODE );
    query_class_type = !( hints & block_cbor::QUERY_CLASS_TYPE );
    query_qdcount = !( hints & block_cbor::QUERY_QDCOUNT );
    query_ancount = !( hints & block_cbor::QUERY_ANCOUNT );
    query_arcount = !( hints & block_cbor::QUERY_ARCOUNT );
    query_nscount = !( hints & block_cbor::QUERY_NSCOUNT );
    query_edns_version = !( hints & block_cbor::QUERY_EDNS_VERSION );
    query_udp_size = !( hints & block_cbor::QUERY_UDP_SIZE );
    query_opt_rdata = !( hints & block_cbor::QUERY_OPT_RDATA );
    response_rcode = !( hints & block_cbor::RESPONSE_RCODE );
}

block_cbor::RRHintFlags HintsExcluded::get_rr_hints() const
{
    unsigned res = 0;

    if ( !rr_ttl )
        res |= block_cbor::TTL;
    if ( !rr_rdata )
        res |= block_cbor::RDATA_INDEX;

    return block_cbor::RRHintFlags(res);
}

void HintsExcluded::set_rr_hints(block_cbor::RRHintFlags hints)
{
    rr_ttl = !( hints & block_cbor::TTL );
    rr_rdata = !( hints & block_cbor::RDATA_INDEX );
}

block_cbor::OtherDataHintFlags HintsExcluded::get_other_data_hints() const
{
    unsigned res = 0;

    // Malformed messages not currently supported.
    if ( !address_events )
        res |= block_cbor::ADDRESS_EVENT_COUNTS;

    return block_cbor::OtherDataHintFlags(res);
}

void HintsExcluded::set_other_data_hints(block_cbor::OtherDataHintFlags hints)
{
    address_events = !( hints & block_cbor::ADDRESS_EVENT_COUNTS );
}

void HintsExcluded::check_config(const Configuration& config)
{
    // Check that transport flags are not excluded if less than complete
    // addresses are stored.
    if ( transport &&
         ( config.client_address_prefix_ipv4 != DEFAULT_IPV4_PREFIX_LENGTH ||
           config.server_address_prefix_ipv4 != DEFAULT_IPV4_PREFIX_LENGTH ||
           config.client_address_prefix_ipv6 != DEFAULT_IPV6_PREFIX_LENGTH ||
           config.server_address_prefix_ipv6 != DEFAULT_IPV6_PREFIX_LENGTH ) )
        throw po::error("Can't omit transport flags if not storing full addresses.");
}

void HintsExcluded::dump_config(std::ostream& os) const
{
    os << "[ip-header]\n";
    if ( timestamp )
        os << "time-offset\n";
    if ( response_delay )
        os << "response-delay\n";
    if ( client_address )
        os << "client-address\n";
    if ( client_port )
        os << "client-port\n";
    if ( client_hoplimit )
        os << "client-hoplimit\n";
    if ( server_address )
        os << "server-address\n";
    if ( server_port )
        os << "server-port\n";
    if ( transport )
        os << "qr-transport-flags\n";

    os << "\n[dns-header]\n";
    if ( transaction_id )
        os << "transaction-id\n";
    if ( query_opcode )
        os << "query-opcode\n";
    if ( query_rcode )
        os << "query-rcode\n";
    if ( dns_flags )
        os << "dns-flags\n";
    if ( response_rcode )
        os << "response-rcode\n";
    if ( query_qdcount )
        os << "query-qdcount\n";
    if ( query_ancount )
        os << "query-ancount\n";
    if ( query_nscount )
        os << "query-nscount\n";
    if ( query_arcount )
        os << "query-arcount\n";

    os << "\n[dns-payload]\n";
    if ( query_name )
        os << "query-name\n";
    if ( query_class_type )
        os << "query-class-type\n";
    if ( rr_ttl )
        os << "rr-ttl\n";
    if ( rr_rdata )
        os << "rr-rdata\n";
    if ( query_udp_size )
        os << "query-udp-size\n";
    if ( query_opt_rdata )
        os << "query-opt-rdata\n";
    if ( query_edns_version )
        os << "query-edns-version\n";
    if ( query_question_section )
        os << "query-question-sections\n";
    if ( query_answer_section )
        os << "query-answer-sections\n";
    if ( query_authority_section )
        os << "query-authority-sections\n";
    if ( query_additional_section )
        os << "query-additional-sections\n";
    if ( response_answer_section )
        os << "response-answer-sections\n";
    if ( response_authority_section )
        os << "response-authority-sections\n";
    if ( response_additional_section )
        os << "response-additional-sections\n";

    os << "\n[dns-meta-data]\n";
    if ( qr_flags )
        os << "qr-sig-flags\n";
    if ( transaction_type )
        os << "qr-type\n";
    if ( query_size )
        os << "query-size\n";
    if ( response_size )
        os << "response-size\n";

    os << "\n[storage-meta-data]\n";
    if ( address_events )
        os << "address-events\n";
}
