/*
 * Copyright 2016-2020 Internet Corporation for Assigned Names and Numbers.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Developed by Sinodun IT (www.sinodun.com)
 */

#ifndef BLOCKEDCBORWRITER_HPP
#define BLOCKEDCBORWRITER_HPP

#include <chrono>
#include <cstdint>
#include <memory>

#include "baseoutputwriter.hpp"
#include "cborencoder.hpp"
#include "blockcbordata.hpp"
#include "packetstatistics.hpp"

/**
 * \class BlockCborWriter
 * \brief Write CBOR output in a space-efficient block format.
 *
 * The block [CBOR] format consists of blocks, or groups, of query/response
 * pairs. Each block has a header, comprising tables of information likely
 * to the repeated in individual query/response pairs.
 *
 * A formal description of the file format is given in a CDDL
 * specification in the documentation.
 *
 * [cbor]: http://cbor.io "CBOR website"
 */
class BlockCborWriter : public BaseOutputWriter
{
public:
    /**
     * \brief Constructor.
     *
     * \param config output configuration.
     * \param enc    file encoder to use for writing output.
     */
    BlockCborWriter(const Configuration& config,
                      std::unique_ptr<CborBaseStreamFileEncoder> enc);

    /**
     * \brief Destructor.
     *
     * This ensures the file is closed.
     */
    virtual ~BlockCborWriter();

    /**
     * \brief Close the file.
     */
    void close();

    /**
     * \brief Write out a single address event.
     *
     * \param ae        address event record to write.
     * \param stats     statistics at time of event.
     */
    virtual void writeAE(const std::shared_ptr<AddressEvent>& ae,
                         const PacketStatistics& stats);

    /**
     * \brief See if the output file needs rotating.
     *
     * \param timestamp the time point to check for rotation.
     */
    virtual void checkForRotation(const std::chrono::system_clock::time_point& timestamp);

    /**
     * \brief A new Query/Response pair is to be output.
     *
     * \param qr the new Query/Response pair.
     */
    virtual void startRecord(const std::shared_ptr<QueryResponse>& qr);

    /**
     * \brief Indicate the end of output for a Query/Response pair.
     *
     * \param qr the current Query/Response pair.
     */
    virtual void endRecord(const std::shared_ptr<QueryResponse>& qr);

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
                            const PacketStatistics& stats);

    /**
     * \brief Start output of optional Query sections.
     */
    virtual void startExtendedQueryGroup();

    /**
     * \brief Start output of optional Response sections.
     */
    virtual void startExtendedResponseGroup();

    /**
     * \brief End output of optional Query or Response sections.
     */
    virtual void endExtendedGroup();

    /**
     * \brief Start output of an optional Question section.
     */
    virtual void startQuestionsSection();

    /**
     * \brief Output a Question section.
     *
     * \param question the question.
     */
    virtual void writeQuestionRecord(const CaptureDNS::query& question);

    /**
     * \brief End output of optional Question or Resource sections in the current pair.
     */
    virtual void endSection();

    /**
     * \brief Start output of an Answers section.
     */
    virtual void startAnswersSection();

    /**
     * \brief Output a Resource section.
     *
     * \param resource the resource.
     */
    virtual void writeResourceRecord(const CaptureDNS::resource& resource);

    /**
     * \brief Start output of an Additional section.
     */
    virtual void startAuthoritySection();

    /**
     * \brief Start output of an Additional section.
     */
    virtual void startAdditionalSection();

protected:
    /**
     * \brief Write file header, to start of first block.
     */
    void writeFileHeader();

    /**
     * \brief Write file footer, after end of last block.
     */
    void writeFileFooter();

    /**
     * \brief Write block out to file.
     */
    void writeBlock();

    /**
     * \brief Write block parameters out to file.
     */
    void writeBlockParameters();

private:
    /**
     * \brief Update block stats.
     *
     * \param stats     latest statistics.
     */
    void updateBlockStats(const PacketStatistics& stats);

    /**
     * \brief output file details.
     */
    RotatingFileName output_pattern_;

    /**
     * \brief the name of the temporary file to which output is written.
     */
    std::string temp_filename_;

    /**
     * \brief the final current filename.
     */
    std::string filename_;

    /**
     * \brief block parameters vector for writing.
     */
    std::vector<block_cbor::BlockParameters> block_parameters_;

    /**
     * \brief the output CBOR encoder.
     */
    std::unique_ptr<CborBaseStreamFileEncoder> enc_;

    /**
     * \brief the internal block data instance.
     */
    std::unique_ptr<block_cbor::BlockData> data_;

    /**
     * \brief the current in-progress query/response item.
     */
    block_cbor::QueryResponseItem query_response_;

    /**
     * \brief Questions part of current in-progress query or response.
     */
    std::vector<block_cbor::index_t> extra_questions_;

    /**
     * \brief Answers part of current in-progress query or response.
     */
    std::vector<block_cbor::index_t> extra_answers_;

    /**
     * \brief Authority part of current in-progress query or response.
     */
    std::vector<block_cbor::index_t> extra_authority_;

    /**
     * \brief Additional part of current in-progress query or response.
     */
    std::vector<block_cbor::index_t> extra_additional_;

    /**
     * \brief Pointer to current in-progress RR section.
     */
    std::vector<block_cbor::index_t>* ext_rr_;

    /**
     * \brief Pointer to current in-progress extras info, Query or Response.
     */
    block_cbor::QueryResponseExtraInfo* ext_group_;

    /**
     * \brief Statistics before the first record in the current block.
     */
    PacketStatistics last_end_block_statistics_;

    /**
     * \brief Do we need to note the start block statistics?
     */
    bool need_start_block_stats_;

    /**
     * \brief Clear in-progress extras info.
     */
    void clear_in_progress_extra_info()
    {
        extra_questions_.clear();
        extra_answers_.clear();
        extra_authority_.clear();
        extra_additional_.clear();
    }
};

#endif
