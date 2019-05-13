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

#ifndef BLOCKEDCBORREADER_HPP
#define BLOCKEDCBORREADER_HPP

#include <memory>
#include <unordered_map>
#include <vector>

#include <boost/optional.hpp>
#include <boost/functional/hash.hpp>

#include "addressevent.hpp"
#include "cbordecoder.hpp"
#include "blockcbor.hpp"
#include "blockcbordata.hpp"
#include "configuration.hpp"
#include "pseudoanonymise.hpp"
#include "queryresponse.hpp"

/**
 * \class BlockCborReader
 * \brief Read input in the block CBOR format.
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
class BlockCborReader
{
public:
    /**
     * \brief Constructor.
     *
     * \param dec               the decoder to use.
     * \param config            the configuration.
     * \param pseudo_anon       pseudo-anonymisation, if to use.
     */
    BlockCborReader(CborBaseDecoder& dec, Configuration& config,
                    boost::optional<PseudoAnonymise> pseudo_anon ={});

    /**
     * \brief Return the next Query/Response pair.
     *
     * Retrieving the Query/Response pairs should probably be done
     * via an iterator. This fills in for now.
     *
     * \return Next unread Query/Response pair. The pointer value will be
     * `nullptr`.
     */
    std::shared_ptr<QueryResponse> readQR();

    /**
     * \brief Dump the statistics for the block to the stream provided
     *
     * \param os output stream.
     */
    void dump_stats(std::ostream& os) {
        block_->last_packet_statistics.dump_stats(os);
    }

    /**
     * \brief Dump information on the collector to the stream provided.
     *
     * \param os output stream.
     */
    void dump_collector(std::ostream& os);

    /**
     * \brief Dump address event info to the stream provided.
     *
     * \param os output stream.
     */
    void dump_address_events(std::ostream& os);

protected:
    /**
     * \brief Read the file header.
     *
     * Read the file header and extract the configuration information
     * from the preamble.
     *
     * \param config extracted configuration information.
     * \throws cbor_decode_error if the CBOR is invalid.
     * \throws cbor_file_format_error on unexpected CBOR content.
     */
    void readFileHeader(Configuration& config);

    /**
     * \brief Read the file preamble.
     *
     * Read the file preamble and extract the configuration information
     * therein.
     *
     * \param config extracted configuration information.
     * \param ver    the file format version.
     * \throws cbor_decode_error if the CBOR is invalid.
     * \throws std::logic_error on unexpected CBOR content.
     * \throws cbor_file_format_error on unexpected CBOR content.
     */
    void readFilePreamble(Configuration& config, block_cbor::FileFormatVersion ver);

    /**
     * \brief Read the configuration in pre-format 1.0 files.
     *
     * Read the configuration information.
     *
     * \param config extracted configuration information.
     * \throws cbor_decode_error if the CBOR is invalid.
     * \throws std::logic_error on unexpected CBOR content.
     * \throws cbor_file_format_error on unexpected CBOR content.
     */
    void readConfiguration(Configuration& config);

    /**
     * \brief Read the block parameters in format 1.0 files.
     *
     * Read the block parameter information vector. Set configuration
     * information from parameters.
     *
     * \param config extracted configuration information.
     * \throws cbor_decode_error if the CBOR is invalid.
     * \throws std::logic_error on unexpected CBOR content.
     * \throws cbor_file_format_error on unexpected CBOR content.
     */
    void readBlockParameters(Configuration& config);

    /**
     * \brief Verify the block parameters in format 1.0 files
     * contain sufficient fields for our purposes.
     *
     * Look through the supplied hints and make sure that the data
     * we require should be present.
     *
     * \returns `false` if hints show data we can't do without is missing.
     */
    bool verifyBlockParameters(const block_cbor::BlockParameters& bp);

    /**
     * \brief Add the message extra info into the message.
     *
     * \param dns   message to receive extra info.
     * \param extra the extra info to add.
     */
    void readExtraInfo(DNSMessage& dns, const block_cbor::QueryResponseExtraInfo& extra) const;

    /**
     * \brief Create a new message query section.
     *
     * \param qname_id      the ID for the QNAME.
     * \param class_type_id the ID for the QCLASS, QTYPE.
     * \return the new query section.
     */
    CaptureDNS::query makeQuery(block_cbor::index_t qname_id, block_cbor::index_t class_type_id) const;

    /**
     * \brief Create a new message resource section.
     *
     * \param rr the resource info.
     * \return the new resource section.
     */
    CaptureDNS::resource makeResource(const block_cbor::ResourceRecord& rr) const;

private:
    /**
     * \brief Read the info for the next block.
     *
     * \return `false` if no more blocks in file.
     */
    bool readBlock();

    /**
     * \brief the decoder to read from.
     */
    CborBaseDecoder& dec_;

    /**
     * \brief index of the next item to read from the current block.
     */
    unsigned next_item_;

    /**
     * \brief `true` if we need to read a new block.
     */
    bool need_block_;

    /**
     * \brief is the block size indefinite?
     */
    bool blocks_indef_;

    /**
     * \brief the number of blocks in the file, if definite.
     */
    uint64_t nblocks_;

    /**
     * \brief the current block.
     */
    std::unique_ptr<block_cbor::BlockData> block_;

    /**
     * \brief the number of the current block
     */
    uint64_t current_block_num_;

    /**
     * \brief ID of the capturing program.
     */
    std::string generator_id_;

    /**
     * \brief ID of the capturing host.
     */
    std::string host_id_;

    /**
     * \brief Pointer to the field translation object.
     */
    std::unique_ptr<block_cbor::FileVersionFields> fields_;

    /**
     * \brief pseudo-anonymisation, if to use.
     */
    boost::optional<PseudoAnonymise> pseudo_anon_;

    /**
     * \brief accumulated address events from the file.
     */
    std::unordered_map<AddressEvent, unsigned, boost::hash<AddressEvent>> address_events_read_;

    /**
     * \brief vector of block parameters.
     */
    std::vector<block_cbor::BlockParameters> block_parameters_;
};

#endif
