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
     * \brief configuration options.
     */
    const Configuration config_;
};

#endif
