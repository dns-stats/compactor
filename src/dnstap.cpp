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

#include "dnstap.hpp"

/*
 * I am indebted to NLnet Labs and the Unbound source code
 * for a cogent description of the workings of Frame Streams.
 * I reporoduce it here:
 *
 * Quick writeup for DNSTAP usage, from reading fstrm/control.h eloquent
 * comments and fstrm/control.c for some bytesize details (the content type
 * length).
 *
 * The Frame Streams can be unidirectional or bi-directional.
 * bi-directional streams use control frame types READY, ACCEPT and FINISH.
 * uni-directional streams use control frame types START and STOP.
 * unknown control frame types should be ignored by the receiver, they
 * do not change the data frame encoding.
 *
 * bi-directional control frames implement a simple handshake protocol
 * between sender and receiver.
 *
 * The uni-directional control frames have one start and one stop frame,
 * before and after the data.  The start frame can have a content type.
 * The start and stop frames are not optional.
 *
 * data frames are preceded by 4byte length, bigendian.
 * zero length data frames are not possible, they are an escape that
 * signals the presence of a control frame.
 *
 * a control frame consists of 0 value in 4byte bigendian, this is really
 * the data frame length, with 0 the escape sequence that indicates one
 * control frame follows.
 * Then, 4byte bigendian, length of the control frame message.
 * Then, the control frame payload (of that length). with in it:
 *   4byte bigendian, control type (eg. START, STOP, READY, ACCEPT, FINISH).
 *   perhaps nothing more (STOP, FINISH), but for other types maybe
 *   control fields
 *      4byte bigendian, the control-field-type, currently only content-type.
 *      4byte bigendian, length of the string for this option.
 *      .. bytes of that string.
 *
 * The START type can have only one field.  Field max len 256.
 * control frame max frame length 512 (excludes the 0-escape and control
 * frame length bytes).
 *
 * the bidirectional type of transmission is like this:
 * client sends READY (with content type included),
 * client waits for ACCEPT (with content type included),
 * client sends START (with matched content type from ACCEPT)
 * .. data frames
 * client sends STOP.
 * client waits for FINISH frame.
 */

namespace {
    enum FstrmControlFrame
    {
        ACCEPT = 1,
        START  = 2,
        STOP   = 3,
        READY  = 4,
        FINISH = 5,
    };

    enum FstrmControlField
    {
        CONTENT_TYPE = 1,
    };

    const unsigned FSTRM_CONTROL_LENGTH_MAX= 512;
    const unsigned FSTRM_CONTENT_TYPE_LENGTH_MAX= 256;
    const std::string CONTENT_TYPE_DNSTAP("protobuf:dnstap.Dnstap");
}

DnsTap::DnsTap(std::fstream& stream, DNSSink dns_sink)
    : stream_(stream), dns_sink_(dns_sink), started_(false)
{
}

void DnsTap::process_stream()
{
    for(;;)
    {
        uint32_t len = get_value();

        if ( len == 0 )
        {
            if ( !process_control_frame() )
                break;  // Received FINISH.
        }
        else
            process_data_frame(len);
    }
}

uint32_t DnsTap::get_value()
{
    char buf[4];

    if ( !stream_.read(buf, sizeof(buf)) )
         throw invalid_dnstap();

    return
        static_cast<uint8_t>(buf[0]) << 24 |
        static_cast<uint8_t>(buf[1]) << 16 |
        static_cast<uint8_t>(buf[2]) << 8 |
        static_cast<uint8_t>(buf[3]);
}

std::string DnsTap::get_buffer(uint32_t len)
{
    std::string res(len, '\0');
    if ( !stream_.read(&res[0], len) )
        throw invalid_dnstap();
    return res;
}

bool DnsTap::process_control_frame()
{
    uint32_t control_len = get_value();

    if ( control_len < 4 || control_len > FSTRM_CONTROL_LENGTH_MAX )
        throw invalid_dnstap();

    uint32_t control_type = get_value();
    control_len -= 4;

    if ( control_type == READY || control_type == START )
    {
        if ( started_ || control_len < 4 )
            throw invalid_dnstap();

        uint32_t field_type = get_value();
        uint32_t field_len = get_value();
        control_len -= 8;

        if ( field_type != CONTENT_TYPE ||
             field_len > FSTRM_CONTENT_TYPE_LENGTH_MAX ||
             control_len != field_len )
            throw invalid_dnstap();

        std::string content_type = get_buffer(field_len);
        if ( content_type != CONTENT_TYPE_DNSTAP )
            throw invalid_dnstap();

        if ( control_type == START )
            started_ = true;
    }
    else if ( control_type == STOP )
    {
        if ( !started_ )
            throw invalid_dnstap();
        return false;
    }
    else
        throw invalid_dnstap();

    return true;
}

void DnsTap::process_data_frame(uint32_t len)
{
    if ( !started_ )
        throw invalid_dnstap();

    std::string data = get_buffer(len);

    // TODO: Implement decoding.
}
