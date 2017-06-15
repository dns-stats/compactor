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

#include "cbordecoder.hpp"

namespace {
    const uint8_t BREAK_MAJOR = 7;
    const uint8_t BREAK_MINOR = 31;
    const uint8_t BREAK = ((7 << 5) | 31);
};

CborBaseDecoder::type_t CborBaseDecoder::type()
{
    needRead();
    if ( *p_ == BREAK )
        return TYPE_BREAK;

    unsigned major, minor;
    major_minor(major, minor);

    if ( major == TYPE_SIMPLE && minor >= 25 && minor <= 27 )
        return TYPE_FLOAT;

    return static_cast<type_t>(major);
}

uint64_t CborBaseDecoder::read_unsigned()
{
    unsigned major, minor;
    uint64_t uint_val;

    needRead();
    read_type_unsigned(major, minor, uint_val);
    if ( major != TYPE_UNSIGNED )
        throw std::logic_error("read_unsigned() called on wrong type");
    if ( minor > 27 )
            throw cbor_decode_error("minor > 27 in unsigned");
    return uint_val;
}

int64_t CborBaseDecoder::read_signed()
{
    unsigned major, minor;
    uint64_t uint_val;

    needRead();
    read_type_unsigned(major, minor, uint_val);
    if ( major != TYPE_SIGNED && major != TYPE_UNSIGNED )
        throw std::logic_error("read_signed() called on wrong type");
    if ( minor > 27 )
            throw cbor_decode_error("minor > 27 in signed");
    if ( major == TYPE_UNSIGNED )
        return uint_val;
    else
        return -1 - uint_val;
}

byte_string CborBaseDecoder::read_binary()
{
    byte_string res;
    unsigned major, minor;
    uint64_t uint_val;

    needRead();
    read_type_unsigned(major, minor, uint_val);
    if ( major != TYPE_BINARY )
        throw std::logic_error("read_binary() called on wrong type");
    if ( minor > 27 && minor < 31 )
        throw cbor_decode_error("minor > 27 in binary");
    if ( minor == 31 )
        throw std::logic_error("indeterminate length binary not supported");
    res.reserve(uint_val);
    while ( uint_val-- > 0 )
    {
        needRead();
        res.push_back(*p_++);
    }

    return res;
}

std::string CborBaseDecoder::read_string()
{
    std::string res;
    unsigned major, minor;
    uint64_t uint_val;

    needRead();
    read_type_unsigned(major, minor, uint_val);
    if ( major != TYPE_STRING && major != TYPE_BINARY )
        throw std::logic_error("read_string() called on wrong type");
    if ( minor > 27 && minor < 31 )
        throw cbor_decode_error("minor > 27 in string");
    if ( minor == 31 )
        throw std::logic_error("indeterminate length string not supported");
    res.reserve(uint_val);
    while ( uint_val-- > 0 )
    {
        needRead();
        res.push_back(*p_++);
    }

    return res;
}

uint64_t CborBaseDecoder::readArrayHeader(bool& indefinite_length)
{
    unsigned major, minor;
    uint64_t uint_val;

    needRead();
    read_type_unsigned(major, minor, uint_val);
    if ( major != TYPE_ARRAY )
        throw std::logic_error("read_array_header() called on wrong type");
    if ( minor > 27 && minor < 31 )
        throw cbor_decode_error("minor > 27 in read_array_header()");
    indefinite_length = ( minor == 31 );
    return uint_val;
}

uint64_t CborBaseDecoder::readMapHeader(bool& indefinite_length)
{
    unsigned major, minor;
    uint64_t uint_val;

    needRead();
    read_type_unsigned(major, minor, uint_val);
    if ( major != TYPE_MAP )
        throw std::logic_error("read_map_header() called on wrong type");
    if ( minor > 27 && minor < 31 )
        throw cbor_decode_error("minor > 27 in read_map_header()");
    indefinite_length = ( minor == 31 );
    return uint_val;
}

// Present for completeness. Not currently used.
// cppcheck-suppress unusedFunction
uint64_t CborBaseDecoder::read_tag()
{
    unsigned major, minor;
    uint64_t uint_val;

    needRead();
    read_type_unsigned(major, minor, uint_val);
    if ( major != TYPE_TAG )
        throw std::logic_error("read_tag() called on wrong type");
    if ( minor > 27 )
        throw cbor_decode_error("minor > 27 in read_tag()");
    return uint_val;
}

// Present for completeness. Not currently used.
// cppcheck-suppress unusedFunction
uint8_t CborBaseDecoder::readSimple()
{
    unsigned major, minor;
    uint64_t uint_val;

    needRead();
    read_type_unsigned(major, minor, uint_val);
    if ( major != TYPE_SIMPLE )
        throw std::logic_error("readSimple() called on wrong type");
    if ( minor >= 25 )
        throw cbor_decode_error("minor >= 25 in readSimple()");
    return static_cast<uint8_t>(uint_val & 0xff);
}

// Present for completeness. Not currently used.
// cppcheck-suppress unusedFunction
double CborBaseDecoder::read_float()
{
    needRead();
    if ( type() != TYPE_FLOAT )
        throw std::logic_error("read_float() called on wrong type");
    throw cbor_decode_error("floating point not implemented");
}

void CborBaseDecoder::readBreak()
{
    needRead();
    if ( type() != TYPE_BREAK )
        throw std::logic_error("read_break() called on wrong type");
    ++p_;
}

std::chrono::system_clock::time_point CborBaseDecoder::read_time()
{
    bool indefLen;
    uint64_t nelems = readArrayHeader(indefLen);

    if ( indefLen || nelems != 2 )
        throw std::logic_error("read_time() called on wrong type");

    std::chrono::seconds s(read_unsigned());
    std::chrono::microseconds us(read_unsigned());
    return std::chrono::system_clock::time_point(s + us);
}

void CborBaseDecoder::skip()
{
    unsigned major, minor;
    uint64_t uint_val;

    needRead();
    read_type_unsigned(major, minor, uint_val);

    switch(major)
    {
    case TYPE_UNSIGNED:
    case TYPE_SIGNED:
    case TYPE_TAG:
        if ( minor > 27 )
            throw cbor_decode_error("minor > 27 in unsigned or signed");
        break;

    case TYPE_BINARY:
    case TYPE_STRING:
        if ( minor > 27 && minor < 31 )
            throw cbor_decode_error("minor > 27 in binary or string");
        if ( minor == 31 )
        {
            unsigned this_major = major;
            for(;;)
            {
                read_type_unsigned(major, minor, uint_val);
                if ( major == this_major )
                {
                    while ( uint_val-- > 0 )
                    {
                        needRead();
                        ++p_;
                    }
                }
                else if ( major == BREAK_MAJOR && minor == BREAK_MINOR )
                    break;
                else
                    throw cbor_decode_error("bad major type in indefinite string");
            }
        }
        else
            while ( uint_val-- > 0 )
            {
                needRead();
                ++p_;
            }
        break;

    case TYPE_ARRAY:
        if ( minor > 27 && minor < 31 )
            throw cbor_decode_error("minor > 27 in array");
        if ( minor == 31 )
            for (;;)
            {
                needRead();
                if ( *p_ == BREAK )
                {
                    ++p_;
                    break;
                }
                else
                    skip();
            }
        else
            while ( uint_val-- > 0 )
                skip();
        break;

    case TYPE_MAP:
        if ( minor > 27 && minor < 31 )
            throw cbor_decode_error("minor > 27 in map");
        if ( minor == 31 )
            for (;;)
            {
                needRead();
                if ( *p_ == BREAK )
                {
                    ++p_;
                    break;
                }
                else
                {
                    skip();
                    skip();
                }
            }
        else
            while ( uint_val-- > 0 )
            {
                skip();
                skip();
            }
        break;

    case TYPE_SIMPLE:
    case TYPE_BREAK:
    case TYPE_FLOAT:
        if ( minor > 27 && minor < 31 )
            throw cbor_decode_error("minor > 27 in simple");
        break;

    default:
        std::logic_error("Missing CBOR type");
        break;
    }
}

void CborBaseDecoder::read_type_unsigned(unsigned& major, unsigned& minor, uint64_t& value)
{
    major_minor(major, minor);
    ++p_;

    if ( minor >= 24 && minor <= 27 )
    {
        value = 0;
        for ( unsigned extra = 1 << (minor - 24); extra > 0; --extra )
        {
            value = value << 8;
            needRead();
            value |= *p_++;
        }
    }
    else if ( minor < 24 )
        value = minor;
    else
        value = 0;    // No value, so keep compiler quiet.
}
