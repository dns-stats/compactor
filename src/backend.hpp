/*
 * Copyright 2018 Sinodun IT.
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

#include "configuration.hpp"
#include "dnsmessage.hpp"
#include "pcapwriter.hpp"
#include "queryresponse.hpp"

/**
 ** Inspector output backend interface.
 **/

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
    OutputBackend(const OutputBackendOptions& opts) : baseopts_(opts) {}

    /**
     *  \brief Destructor.
     */
    virtual ~OutputBackend() {}

    /**
     * \brief Output a QueryResponse.
     *
     * \param qr        the QueryResponse.
     * \param config    the configuration applying when recording the QR.
     */
    virtual void output(std::shared_ptr<QueryResponse>& qr, const Configuration& config) = 0;

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
     * \brief Output a QueryResponse.
     *
     * \param qr        the QueryResponse.
     * \param config    the configuration applying when recording the QR.
     */
    virtual void output(std::shared_ptr<QueryResponse>& qr, const Configuration& config);

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
     * \brief Write a TCP QR.
     *
     * \param qr        the Query/Response.
     */
    void write_qr_tcp(std::shared_ptr<QueryResponse> qr);

    /**
     * \brief Write a UDP QR.
     *
     * \param qr        the Query/Response.
     */
    void write_qr_udp(std::shared_ptr<QueryResponse> qr);

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
