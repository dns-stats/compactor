/*
 * Copyright 2021 Internet Corporation for Assigned Names and Numbers.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Developed by Sinodun IT (www.sinodun.com)
 */

#ifndef DNSTAP_HPP
#define DNSTAP_HPP

#include <cstdint>
#include <exception>
#include <fstream>
#include <string>

#include "dnsmessage.hpp"

/**
 * \exception invalid_dnstap
 * \brief Signals incompliant DNSTAP input.
 *
 * Signals that the input is not conformant DNSTAP.
 */
class invalid_dnstap : public std::runtime_error
{
public:
    /**
     * \brief Default construtor.
     */
    invalid_dnstap()
        : std::runtime_error("Invalid DNSTAP"){};
};

/**
 * \class DnsTap
 * \brief Machinery for receiving DNSTAP input.
 */
class DnsTap
{
public:
    /**
     * \typedef DNSSink
     * \brief Sink function for DNS messages.
     */
    using DNSSink = std::function<void (std::unique_ptr<DNSMessage>&)>;

    /**
     * \brief Constructor.
     *
     * \param stream            DNSTAP data source.
     * \param dns_sink          sink for DNS messages.
     */
    DnsTap(std::fstream& stream, DNSSink dns_sink);

    /**
     * \brief Process input.
     *
     * Receive and process DNSTAP until end of file.
     */
    void process_stream();

protected:
    /**
     * \brief receive 4 byte bigendian value.
     */
    uint32_t get_value();

    /**
     * \brief receive buffer of given size.
     */
    std::string get_buffer(uint32_t len);

    /**
     * \brief read and process control frame.
     *
     * \returns `false` if FINISH read.
     */
    bool process_control_frame();

    /**
     * \brief read and process data frame.
     *
     * \param len       data frame length.
     */
    void process_data_frame(uint32_t len);

private:
    /**
     * \brief stream for DNSTAP data.
     */
    std::fstream& stream_;

    /**
     * \brief sink function for read DNS messages.
     */
    DNSSink dns_sink_;

    /**
     * \brief have we seen a START frame?
     */
    bool started_;
};

#endif
