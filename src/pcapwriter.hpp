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

#ifndef PCAPWRITER_HPP
#define PCAPWRITER_HPP

#include <chrono>
#include <memory>
#include <string>

#include <pcap/pcap.h>
#include <tins/tins.h>

#include "configuration.hpp"
#include "makeunique.hpp"
#include "nocopypacket.hpp"
#include "rotatingfilename.hpp"

/**
 * \class PcapBaseWriter
 * \brief Base class for writing to PCAP file.
 */
class PcapBaseWriter
{
public:
    /**
     * \brief Constructor.
     */
    PcapBaseWriter() {}

    /**
     * \brief Destructor.
     */
    virtual ~PcapBaseWriter() {}

    /**
     * \brief Close the current output.
     *
     * \throws std::runtime_error if temporary to final filename rename fails.
     */
    virtual void close() = 0;

    /**
     * \brief Write a packet to the output file.
     *
     * \param pdu       the packet data to write.
     * \param timestamp the packet timestamp.
     */
    virtual void write_packet(Tins::PDU& pdu,
                              const std::chrono::system_clock::time_point& timestamp) = 0;
};

/**
 * \class PcapBaseRotatingWriter
 * \brief Base class for writing to PCAP file with a rotating filename.
 */
class PcapBaseRotatingWriter
{
public:
    /**
     * \brief Constructor.
     */
    PcapBaseRotatingWriter() {}

    /**
     * \brief Destructor.
     */
    virtual ~PcapBaseRotatingWriter() {}

    /**
     * \brief Close the current output.
     *
     * \throws std::runtime_error if temporary to final filename rename fails.
     */
    virtual void close() = 0;

    /**
     * \brief Write a packet to the output file.
     *
     * \param pdu       the packet data to write.
     * \param timestamp the packet timestamp.
     * \param config    the current configuration.
     */
    virtual void write_packet(Tins::PDU& pdu,
                              const std::chrono::system_clock::time_point& timestamp,
                              const Configuration& config) = 0;
};

/**
 * \class PcapWriter
 * \brief Write packets to an output PCAP file.
 */
template<typename Writer>
class PcapWriter : public PcapBaseWriter
{
    const unsigned NO_LINK_TYPE = 0xffffffffu;

public:
    /**
     * \brief Constructor.
     *
     * \param filename filename for the output file.
     * \param level    compression level, if required.
     * \param snaplen  snap length.
     */
    PcapWriter(const std::string& filename, unsigned level, unsigned snaplen)
        : filename_(filename), level_(level),
          linktype_(NO_LINK_TYPE), snaplen_(snaplen)
    {
    }

    /**
     * \brief Close the current output.
     */
    virtual void close()
    {
        if ( writer_ )
            writer_.reset(nullptr);
    }

    /**
     * \brief Write a packet to the output file.
     *
     * \param pdu       the packet data to write.
     * \param timestamp the packet timestamp.
     */
    virtual void write_packet(Tins::PDU& pdu,
                              const std::chrono::system_clock::time_point& timestamp)
    {
        if ( !writer_ )
        {
            writer_ = make_unique<Writer>(filename_, level_);
            if ( linktype_ == NO_LINK_TYPE )
                set_link_type(pdu);
            write_file_header();
        }

        Tins::PDU::serialization_type buffer = pdu.serialize();
        auto us = std::chrono::duration_cast<std::chrono::microseconds>(timestamp.time_since_epoch());

        TINS_BEGIN_PACK
        struct pcap_packet_header {
            uint32_t ts_sec;
            uint32_t ts_usec;
            uint32_t incl_len;
            uint32_t orig_len;
        } TINS_END_PACK;

        pcap_packet_header packet_header = {
            static_cast<uint32_t>(us.count() / 1000000),
            static_cast<uint32_t>(us.count() % 1000000),
            static_cast<uint32_t>(buffer.size()),
            static_cast<uint32_t>(buffer.size())
        };

        writer_->writeBytes(reinterpret_cast<uint8_t*>(&packet_header), sizeof(packet_header));
        writer_->writeBytes(&buffer[0], buffer.size());
    }

    /**
     * \brief Get the output filename.
     *
     * \returns the current filename.
     */
    const std::string& filename()
    {
        return filename_;
    }

    /**
     * \brief Set a new output filename.
     *
     * \param filename the new filename.
     */
    void set_filename(const std::string& filename)
    {
        close();
        filename_ = filename;
    }

private:
    /**
     * \brief Set the output link type from the capture data.
     *
     * \param pdu capture data.
     */
    void set_link_type(const Tins::PDU& pdu)
    {
        // Get a link type for the file from the current packet.
        switch(pdu.pdu_type())
        {
#ifdef DLT_PKTAP
        case Tins::PDU::PKTAP:
            linktype_ = DLT_PKTAP;
            break;
#endif

        case Tins::PDU::RADIOTAP:
            linktype_ = DLT_IEEE802_11_RADIO;
            break;

        case Tins::PDU::SLL:
            linktype_ = DLT_LINUX_SLL;
            break;

#ifdef TINS_HAVE_DOT11
        case Tins::PDU::DOT11:
            linktype_ = DLT_IEEE802_11;
            break;
#endif

        case Tins::PDU::LOOPBACK:
            linktype_ = DLT_NULL;
            break;

        case Tins::PDU::PPI:
            linktype_ = DLT_PPI;
            break;

        default:
            // For anything else, go for Ethernet.
            linktype_ = DLT_EN10MB;
            break;
        }
    }

    /**
     * \brief Write a file header to the output file.
     */
    void write_file_header()
    {
        // Write file header.
        TINS_BEGIN_PACK
            struct pcap_file_header {
            uint32_t magic;
            uint16_t major;
            uint16_t minor;
            int32_t thiszone;
            uint32_t sigfigs;
            uint32_t snaplen;
            uint32_t network;
        } TINS_END_PACK;

        pcap_file_header file_header = {
            0xa1b2c3d4,
            PCAP_VERSION_MAJOR,
            PCAP_VERSION_MINOR,
            0,
            0,
            snaplen_,
            linktype_
        };

        writer_->writeBytes(reinterpret_cast<uint8_t*>(&file_header), sizeof(file_header));
    }

    /**
     * \brief the output writer.
     */
    std::unique_ptr<Writer> writer_;

    /**
     * \brief the current output filename.
     */
    std::string filename_;

    /**
     * \brief compression level, if applicable.
     */
    unsigned level_;

    /**
     * \brief file link type.
     */
    unsigned linktype_;

    /**
     * \brief snap length.
     */
    unsigned snaplen_;
};

/**
 * \class PcapRotatingWriter
 * \brief Write packets to an output PCAP file with rotating filename.
 */
template<typename Writer>
class PcapRotatingWriter : public PcapBaseRotatingWriter
{
public:
    /**
     * \brief Constructor.
     *
     * Prepare a rotating output file for writing. The file is named
     * following the pattern (expanded by `strftime`), and will be
     * rotated periodically.
     *
     * \param pattern filename pattern for the output file.
     * \param period  rotation period for output file.
     * \param level   compression level, if required.
     * \param snaplen snap length.
     */
    PcapRotatingWriter(const std::string& pattern,
                       const std::chrono::seconds& period,
                       unsigned level, unsigned snaplen)
        : fname_(make_unique<RotatingFileName>(pattern + Writer::suggested_extension(), period)),
          writer_("", level, snaplen)
    {
    }

    /**
     * \brief Close the current output.
     */
    virtual void close()
    {
        writer_.close();
    }

    /**
     * \brief Write a packet to the output file.
     *
     * Use the timestamp to see if the output file needs rotating, and then
     * write the packet out to the file.
     *
     * \param pdu       the packet data to write.
     * \param timestamp the packet timestamp.
     * \param config    the current configuration.
     */
    virtual void write_packet(Tins::PDU& pdu,
                              const std::chrono::system_clock::time_point& timestamp,
                              const Configuration& config)
    {
        if ( fname_->need_rotate(timestamp, config) )
            writer_.set_filename(fname_->filename(timestamp, config));

        writer_.write_packet(pdu, timestamp);
    }

private:
    /**
     * \brief the output file details.
     */
    std::unique_ptr<RotatingFileName> fname_;

    /**
     * \brief output writer.
     */
    PcapWriter<Writer> writer_;
};

#endif
