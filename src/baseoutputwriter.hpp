/*
 * Copyright 2016-2017 Internet Corporation for Assigned Names and Numbers.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Developed by Sinodun IT (www.sinodun.com)
 */

#ifndef BASEOUTPUTWRITER_HPP
#define BASEOUTPUTWRITER_HPP

#include <cstdint>

#include "addressevent.hpp"
#include "configuration.hpp"
#include "dnsmessage.hpp"
#include "packetstatistics.hpp"
#include "queryresponse.hpp"
#include "rotatingfilename.hpp"

/**
 * \class BaseOutputWriter
 * \brief Virtual base for writing output following section include options.
 *
 * This class provides base functionality for writing output files while
 * including or omitting optional output sections depending on the
 * configuration options supplied. Subclasses implement the virtual
 * methods to do the output, and this class ensures the items required
 * are output.
 */
class BaseOutputWriter
{
public:
    /**
     * \brief DNS flags enum.
     *
     * Note that we always store response OPT RRs directly in the file,
     * so there is no need for a response D0 in the following.
     */
    enum DNSFlags
    {
        QUERY_CD = (1 << 0),
        QUERY_AD = (1 << 1),
        QUERY_Z = (1 << 2),
        QUERY_RA = (1 << 3),
        QUERY_RD = (1 << 4),
        QUERY_TC = (1 << 5),
        QUERY_AA = (1 << 6),
        QUERY_D0 = (1 << 7),
        RESPONSE_CD = (1 << 8),
        RESPONSE_AD = (1 << 9),
        RESPONSE_Z = (1 << 10),
        RESPONSE_RA = (1 << 11),
        RESPONSE_RD = (1 << 12),
        RESPONSE_TC = (1 << 13),
        RESPONSE_AA = (1 << 14),
    };

    /**
     * \brief Transport flags enum.
     */
    enum TransportFlags
    {
        TCP = (1 << 0),
        IPV6 = (1 << 1),

        QUERY_TRAILINGDATA = (1 << 2),
    };

    /**
     * \brief Construct the base class.
     *
     * \param config output configuration.
     */
    explicit BaseOutputWriter(const Configuration& config);

    /**
     * \brief Write out a single Query/Response pair.
     *
     * \param qr        Query/Response record to write.
     * \param stats     statistics at time of record.
     */
    void writeQR(const std::shared_ptr<QueryResponse>& qr,
                 const PacketStatistics& stats);

    /**
     * \brief Write out a single address event.
     *
     * \param ae        address event record to write.
     * \param stats     statistics at time of event.
     */
    virtual void writeAE(const std::shared_ptr<AddressEvent>& ae,
                         const PacketStatistics& stats) = 0;

    /**
     * \brief See if the output file needs rotating.
     *
     * \param timestamp the time point to check for rotation.
     */
    virtual void checkForRotation(const std::chrono::system_clock::time_point& timestamp) = 0;

    /**
     * \brief A new Query/Response pair is to be output.
     *
     * \param qr the new Query/Response pair.
     */
    virtual void startRecord(const std::shared_ptr<QueryResponse>& qr) = 0;

    /**
     * \brief Indicate the end of output for a Query/Response pair.
     *
     * \param qr the current Query/Response pair.
     */
    virtual void endRecord(const std::shared_ptr<QueryResponse>& qr) = 0;

    /**
     * \brief Write the basic output for a Query/Response pair.
     *
     * Basic output is information always output for a Query/Response pair,
     * regardless of the optional sections requested.
     *
     * \param qr        the Query/Response record.
     * \param stats     statistics at time of record.
     */
    virtual void writeBasic(const std::shared_ptr<QueryResponse>& qr,
                            const PacketStatistics& stats) = 0;

    /**
     * \brief Start output of optional Query sections.
     */
    virtual void startExtendedQueryGroup() = 0;

    /**
     * \brief Start output of optional Response sections.
     */
    virtual void startExtendedResponseGroup() = 0;

    /**
     * \brief End output of optional Query or Response sections.
     */
    virtual void endExtendedGroup() = 0;

    /**
     * \brief Start output of an optional Question section.
     */
    virtual void startQuestionsSection() = 0;

    /**
     * \brief Output a Question section.
     *
     * \param question the question.
     */
    virtual void writeQuestionRecord(const CaptureDNS::query& question) = 0;

    /**
     * \brief End output of optional Question or Resource sections in the current pair.
     */
    virtual void endSection() = 0;

    /**
     * \brief Start output of an Answers section.
     */
    virtual void startAnswersSection() = 0;

    /**
     * \brief Output a Resource section.
     *
     * \param resource the resource.
     */
    virtual void writeResourceRecord(const CaptureDNS::resource& resource) = 0;

    /**
     * \brief Start output of an Authority section.
     */
    virtual void startAuthoritySection() = 0;

    /**
     * \brief Start output of an Additional section.
     */
    virtual void startAdditionalSection() = 0;

    // Utilities.

    /**
     * \brief Calculate the DNS flags for a Query/Response.
     *
     * The DNS flag value composed from the DNSFlag enum.
     *
     * \param qr    the Query/Response.
     * \return DNS flags value.
     */
    uint16_t dnsFlags(const std::shared_ptr<QueryResponse>& qr);

    /**
     * \brief Calculate the Transport flags for a Query/Response.
     *
     * The Transport flag value is composed from the TransportFlags enum.
     *
     * \param qr    the Query/Response.
     * \return DNS flags value.
     */
    uint8_t transportFlags(const std::shared_ptr<QueryResponse>& qr);

    /**
     * \brief Set the basic DNS flags in a query or response message.
     *
     * Note this does not set the query D0 flag.
     *
     * \param msg   the message.
     * \param flags DNS flags value.
     * \param query `true` if the message is a query.
     */
    static void setDnsFlags(DNSMessage& msg, uint16_t flags, bool query);

protected:
    /**
     * \brief Write the indicated optional sections in a query or response.
     *
     * The details of the first Question are in the basic information,
     * so this function only records a second and subsequent questions.
     *
     * OPT information in Questions is also in the basic information, so
     * the first OPT section in a Question is skipped.
     *
     * \param dm       the query or response message.
     * \param options  which sections to write. Values are combined from Configuration::OptionalOutputSections.
     */
    void writeSections(const DNSMessage& dm, int options);

    /**
     * \brief Determine if this RR type should be output.
     *
     * Check the RR type against the list of configured accept and ignore
     * RR types.
     *
     * \param rr_type the RR type.
     * \returns `true` if it should be output.
     */
    bool outputRRType(CaptureDNS::QueryType rr_type);

    /**
     * \brief configuration options.
     */
    const Configuration config_;
};

#endif
