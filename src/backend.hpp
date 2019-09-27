/*
 * Copyright 2018-2019 Sinodun IT.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef BACKEND_HPP
#define BACKEND_HPP

#include <memory>
#include <ostream>
#include <string>

#include "blockcborreader.hpp"
#include "configuration.hpp"
#include "dnsmessage.hpp"
#include "pcapwriter.hpp"

/**
 ** Inspector output backend interface.
 **/

/**
 * \exception backend_error
 * \brief Signals an error with a backend.
 */
class backend_error : public std::runtime_error
{
public:
    /**
     * \brief Constructor.
     *
     * \param what message detailing the problem.
     */
    explicit backend_error(const std::string& what)
        : std::runtime_error(what) {}

    /**
     * \brief Constructor.
     *
     * \param what message detailing the problem.
     */
    explicit backend_error(const char*  what)
        : std::runtime_error(what) {}
};

/**
 * \struct OutputBackendOptions
 * \brief Common options for the inspector backends.
 */
struct OutputBackendOptions
{
    /**
     * \brief write output data? Possibly we just analyse.
     */
    bool write_output{true};

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
     * \brief pseudo-anonymise?
     */
    bool pseudo_anon{false};
};

/**
 * \class OutputBackend
 * \brief Output backend for inspector.
 */
class OutputBackend
{
public:
    /**
     * \brief Constructor.
     *
     * \param opts      output options information.
     */
    explicit OutputBackend(const OutputBackendOptions& opts) : baseopts_(opts) {}

    /**
     *  \brief Destructor.
     */
    virtual ~OutputBackend() {}

    /**
     * \brief Give the backend a look at the exclude hints from the input.
     *
     * Give it a chance to throw an error if it doesn't think that
     * it has enough material to work with.
     *
     * \param exclude_hints the exclude hints.
     * \throws backend_error on problems.
     */
    virtual void check_exclude_hints(const HintsExcluded& exclude_hints) {}

    /**
     * \brief Output a QueryResponse.
     *
     * \param qr        the QueryResponse.
     * \param config    the configuration applying when recording the QR.
     */
    virtual void output(const QueryResponseData& qr, const Configuration& config) = 0;

    /**
     * \brief Write backend-specific report.
     *
     * \param os        stream to which to write report.
     */
    virtual void report(std::ostream& os) {}

    /**
     * \brief the output file path.
     *
     * \return the output file path. "" if unnamed stream, e.g. stdout.
     */
    virtual std::string output_file() = 0;

protected:
    /**
     * \brief construct output filename with compression-appropriate extension.
     *
     * \param name      the base filename.
     * \return the decorated filename.
     */
    virtual std::string output_name(const std::string& name);

private:
    /**
     * \brief common options.
     */
    const OutputBackendOptions& baseopts_;
};

/**
 * \exception pcap_defaults_backend_error
 * \brief Signals a missing required default in the PCAP backend.
 */
class pcap_defaults_backend_error : public backend_error
{
public:
    /**
     * \brief Constructor.
     *
     * \param what the missing default.
     */
    explicit pcap_defaults_backend_error(const std::string& what)
        : backend_error("Require default values for: " + what) {}
};

/**
 * \struct PcapBackendOptions
 * \brief Options for the PCAP backend.
 */
struct PcapBackendOptions
{
    /**
     * \brief base options.
     */
    OutputBackendOptions baseopts;

    /**
     * \brief write only query messages to output.
     */
    bool query_only{false};

    /**
     * \brief auto choose name compression.
     */
    bool auto_compression{true};

    /**
     * \brief available defaults.
     */
    Defaults defaults;
};

/**
 * \class PcapBackend
 * \brief Output PCAP backend for inspector.
 */
class PcapBackend : public OutputBackend
{
public:
    /**
     * \brief Constructor.
     *
     * \param opts              options information.
     * \param fname             output file path.
     */
    PcapBackend(const PcapBackendOptions& opts, const std::string& fname);

    /**
     * \brief Destructor.
     */
    virtual ~PcapBackend();

    /**
     * \brief Give the backend a look at the exclude hints from the input.
     *
     * Give it a chance to throw an error if it doesn't think that
     * it has enough material to work with. In this case, we need defaults
     * to cover everything that might be missing.
     *
     * \param exclude_hints the exclude hints.
     * \throws pcap_defaults_backend_error on problems.
     */
    virtual void check_exclude_hints(const HintsExcluded& exclude_hints);

    /**
     * \brief Output a QueryResponse.
     *
     * \param qrd       the QueryResponse.
     * \param config    the configuration applying when recording the QR.
     */
    virtual void output(const QueryResponseData& qrd, const Configuration& config);

    /**
     * \brief Write backend-specific report.
     *
     * \param os        stream to which to write report.
     */
    virtual void report(std::ostream& os);

    /**
     * \brief the output file path.
     *
     * \return the output file path. "" if unnamed stream, e.g. stdout.
     */
    virtual std::string output_file();

private:
    /**
     * \brief Convert QueryResponseData to wire format.
     *
     * \param qr        the Query/Response.
     * \returns a QueryResponse.
     */
    std::unique_ptr<QueryResponse> convert_to_wire(const QueryResponseData& qrd);

    /**
     * \brief Add extra sections to DNS message.
     *
     * \param dns         the DNS message.
     * \param questions   second and subsequent Question sections.
     * \param answers     Answer sections.
     * \param authorities Authorities sections.
     * \param additionals Additional sections.
     */
    void add_extra_sections(DNSMessage& dns,
                            const boost::optional<std::vector<QueryResponseData::Question>>& questions,
                            const boost::optional<std::vector<QueryResponseData::RR>>& answers,
                            const boost::optional<std::vector<QueryResponseData::RR>>& authorities,
                            const boost::optional<std::vector<QueryResponseData::RR>>& additionals);

    /**
     * \brief Write a TCP QR.
     *
     * \param qr        the Query/Response.
     */
    void write_qr_tcp(const std::unique_ptr<QueryResponse>& qr);

    /**
     * \brief Write a UDP QR.
     *
     * \param qr        the Query/Response.
     */
    void write_qr_udp(const std::unique_ptr<QueryResponse>& qr);

    /**
     * \brief Write a single UDP DNS packet.
     *
     * \param dns       the DNS message.
     */
    void write_udp_packet(const DNSMessage& dns);

    /**
     * \brief Write a single packet.
     *
     * \param pdu       the PDU to write.
     * \param src       the source address.
     * \param dst       the destination address.
     * \param hoplimit  packet hoplimit.
     * \param timestamp the packet timestamp.
     */
    void write_packet(Tins::PDU* pdu,
                      const IPAddress& src,
                      const IPAddress& dst,
                      uint8_t hoplimit,
                      const std::chrono::system_clock::time_point& timestamp);

    /**
     * \brief the options.
     */
    const PcapBackendOptions& opts_;

    /**
     * \brief the output file path.
     */
    std::string output_path_;

    /**
     * \brief the output writer.
     */
    std::unique_ptr<PcapBaseWriter> writer_;

    /**
     * \brief are we using name compression?
     */
    bool using_compression_;

    /**
     * \brief current auto-compression status.
     */
    bool auto_compression_;

    /**
     * \brief number of response with different wire sizes to expected.
     */
    unsigned bad_response_wire_size_count_;
};

#endif
