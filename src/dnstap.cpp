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

#include <chrono>

#include <tins/tins.h>

#include "ipaddress.hpp"

#include "dnstap/dnstap.pb.h"

#include "dnstap.hpp"

/*
 * I am indebted to NLnet Labs and the Unbound source code
 * for a cogent description of the workings of Frame Streams.
 * I reprooduce it here:
 *
 * ==========
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
 *
 * ==========
 *
 * In fact, it appears that when Unbound sends STOP, it does not hang
 * around waiting for FINISH but closes the socket immediately.
 *
 * Unidirectional transmission is START, data, STOP.
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

    enum FstrmStates
    {
        WAIT,
        WAIT_START,
        STARTED,
    };

    const unsigned FSTRM_CONTROL_LENGTH_MAX= 512;
    const unsigned FSTRM_CONTENT_TYPE_LENGTH_MAX= 256;
    const std::string CONTENT_TYPE_DNSTAP("protobuf:dnstap.Dnstap");

    TransactionType convert_message_type(::dnstap::Message_Type t)
    {
        switch(t)
        {
        case dnstap::Message_Type::Message_Type_AUTH_QUERY:
            return TransactionType::AUTH_QUERY;

        case dnstap::Message_Type::Message_Type_AUTH_RESPONSE:
            return TransactionType::AUTH_RESPONSE;

        case dnstap::Message_Type::Message_Type_RESOLVER_QUERY:
            return TransactionType::RESOLVER_QUERY;

        case dnstap::Message_Type::Message_Type_RESOLVER_RESPONSE:
            return TransactionType::RESOLVER_RESPONSE;

        case dnstap::Message_Type::Message_Type_CLIENT_QUERY:
            return TransactionType::CLIENT_QUERY;

        case dnstap::Message_Type::Message_Type_CLIENT_RESPONSE:
            return TransactionType::CLIENT_RESPONSE;

        case dnstap::Message_Type::Message_Type_FORWARDER_QUERY:
            return TransactionType::FORWARDER_QUERY;

        case dnstap::Message_Type::Message_Type_FORWARDER_RESPONSE:
            return TransactionType::FORWARDER_RESPONSE;

        case dnstap::Message_Type::Message_Type_STUB_QUERY:
            return TransactionType::STUB_QUERY;

        case dnstap::Message_Type::Message_Type_STUB_RESPONSE:
            return TransactionType::STUB_RESPONSE;

        case dnstap::Message_Type::Message_Type_TOOL_QUERY:
            return TransactionType::TOOL_QUERY;

        case dnstap::Message_Type::Message_Type_TOOL_RESPONSE:
            return TransactionType::TOOL_RESPONSE;

        case dnstap::Message_Type::Message_Type_UPDATE_QUERY:
            return TransactionType::UPDATE_QUERY;

        case dnstap::Message_Type::Message_Type_UPDATE_RESPONSE:
            return TransactionType::UPDATE_RESPONSE;
        }

        throw dnstap_invalid("Unknown message type");
    }

    TransportType convert_transport_type(::dnstap::SocketProtocol p)
    {
        switch(p)
        {
        case dnstap::SocketProtocol::UDP:
            return TransportType::UDP;

        case dnstap::SocketProtocol::TCP:
            return TransportType::TCP;

        case dnstap::SocketProtocol::DOT:
            return TransportType::DOT;

        case dnstap::SocketProtocol::DOH:
            return TransportType::DOH;
        }

        throw dnstap_invalid("Unknown transport type");
    }
}

DnsTap::DnsTap(std::iostream& stream, DNSSink dns_sink)
    : stream_(stream), dns_sink_(dns_sink),
      bidirectional_(false), state_(WAIT)
{
    stream_.exceptions(std::ios::failbit | std::ios::badbit);
}

void DnsTap::process_stream()
{
    for(;;)
    {
        uint32_t len = get_value();

        if ( len == 0 )
        {
            if ( !process_control_frame(read_control_frame()) )
                break;  // Received STOP.
        }
        else
            process_data_frame(read_data_frame(len));
    }
}

bool DnsTap::process_control_frame(uint32_t f)
{
    bool res = true;

    switch(state_)
    {
    case WAIT:
        if ( f != READY && f != START )
            throw dnstap_invalid("READY or START expected");
        if ( f == READY )
        {
            bidirectional_ = true;
            send_control(make_accept());
            state_ = WAIT_START;
        }
        else
            state_ = STARTED;
        break;

    case WAIT_START:
        if ( f != START )
            throw dnstap_invalid("START expected");
        state_ = STARTED;
        break;

    case STARTED:
        if ( f != STOP )
            throw dnstap_invalid("STOP expected");
        if ( bidirectional_ )
            send_control(make_finish(), true);
        res = false;
        break;
    }
    return res;
}

void DnsTap::process_data_frame(std::unique_ptr<DNSMessage> msg)
{
    if ( state_ != STARTED )
        throw dnstap_invalid("Data when not started");

    if ( msg )
        dns_sink_(msg);
}

uint32_t DnsTap::read_control_frame()
{
    uint32_t control_len = get_value();

    if ( control_len < 4 || control_len > FSTRM_CONTROL_LENGTH_MAX )
        throw dnstap_invalid("bad control length");

    uint32_t control_type = get_value();
    control_len -= 4;

    // Read and check content type.
    if ( control_type == READY || control_type == START )
    {
        if ( control_len < 4 )
            throw dnstap_invalid("Invalid control length");

        uint32_t field_type = get_value();
        uint32_t field_len = get_value();
        control_len -= 8;

        if ( field_type != CONTENT_TYPE ||
             field_len > FSTRM_CONTENT_TYPE_LENGTH_MAX ||
             control_len != field_len )
            throw dnstap_invalid("Bad field type or length");

        std::string content_type = get_buffer(field_len);

        if ( content_type != CONTENT_TYPE_DNSTAP )
            throw dnstap_invalid("unknown field");
    }

    return control_type;
}

std::unique_ptr<DNSMessage> DnsTap::read_data_frame(uint32_t len)
{
    std::string data = get_buffer(len);

    dnstap::Dnstap dnstap;
    if ( !dnstap.ParseFromString(data) )
        throw dnstap_invalid("Data parse failed");

    if ( !dnstap.has_type() )
        throw dnstap_invalid("Data has no type");

    std::unique_ptr<DNSMessage> dns;

    if ( dnstap.type() == dnstap::Dnstap_Type::Dnstap_Type_MESSAGE )
    {
        const dnstap::Message& message = dnstap.message();

        if ( !message.has_type() )
            throw dnstap_invalid("Message has no type");
        TransactionType transaction_type = convert_message_type(message.type());

        if ( !message.has_socket_protocol() )
            throw dnstap_invalid("Message has no protocol");
        TransportType transport_type = convert_transport_type(message.socket_protocol());

        if ( message.has_query_message() )
        {
            if ( message.has_query_time_sec() &&
                 message.has_query_time_nsec() )
            {
                std::chrono::seconds s(message.query_time_sec());
                std::chrono::nanoseconds ns(message.query_time_nsec());
                std::chrono::system_clock::time_point t(std::chrono::duration_cast<std::chrono::system_clock::duration>(s + ns));

                dns = std::make_unique<DNSMessage>(
                    Tins::RawPDU(message.query_message()),
                    t, transport_type, transaction_type);
            }
        }
        else if ( message.has_response_message() )
        {
            if ( message.has_response_time_sec() &&
                 message.has_response_time_nsec() )
            {
                std::chrono::seconds s(message.response_time_sec());
                std::chrono::nanoseconds ns(message.response_time_nsec());
                std::chrono::system_clock::time_point t(std::chrono::duration_cast<std::chrono::system_clock::duration>(s + ns));

                dns = std::make_unique<DNSMessage>(
                    Tins::RawPDU(message.response_message()),
                    t, transport_type, transaction_type);
            }
        }

        if ( dns )
        {
            if ( message.has_query_address() )
                dns->clientIP = IPAddress(to_byte_string(message.query_address()));
            if ( message.has_query_port() )
                dns->clientPort = message.query_port();

            if ( message.has_response_address() )
                dns->serverIP = IPAddress(to_byte_string(message.response_address()));
            if ( message.has_response_port() )
                dns->serverPort = message.response_port();

            if ( message.has_socket_family() )
                dns->ipv6 = ( message.socket_family() == dnstap::SocketFamily::INET6 );
        }
    }

    return dns;
}

void DnsTap::send_control(const std::string& msg, bool ignore_err)
{
    try
    {
        stream_.write(msg.c_str(), msg.size());
    }
    catch (std::iostream::failure&)
    {
        if ( !ignore_err )
            throw;
    }
}

uint32_t DnsTap::get_value()
{
    char buf[4];

    stream_.read(buf, sizeof(buf));

    return
        static_cast<uint8_t>(buf[0]) << 24 |
        static_cast<uint8_t>(buf[1]) << 16 |
        static_cast<uint8_t>(buf[2]) << 8 |
        static_cast<uint8_t>(buf[3]);
}

std::string DnsTap::get_buffer(uint32_t len)
{
    std::string res(len, '\0');
    stream_.read(&res[0], len);
    return res;
}

std::string DnsTap::make_accept()
{
    std::string msg(4 +    // Initial zero
                    4 +    // Control frame length
                    4 +    // Control type
                    4 +    // Content field type
                    4,     // Content field length
                    '\0'); // Initialised to 0.
    msg[7] = msg.size() + CONTENT_TYPE_DNSTAP.size() - 8;
    msg[11] = ACCEPT;
    msg[15] = CONTENT_TYPE;
    msg[19] = CONTENT_TYPE_DNSTAP.size();
    msg += CONTENT_TYPE_DNSTAP;
    return msg;
}


std::string DnsTap::make_finish()
{
    std::string msg(4 +    // Initial zero
                    4 +    // Control frame length
                    4,     // Control type
                    '\0'); // Initialised to 0.
    msg[7] = msg.size() - 8;
    msg[11] = FINISH;
    return msg;
}
