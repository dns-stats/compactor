/*
 * Copyright 2016-2017, 2019 Internet Corporation for Assigned Names and Numbers.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Developed by Sinodun IT (www.sinodun.com)
 */

#include <cstdio>
#include <iostream>
#include <limits>

#include "cborencoder.hpp"
#include "log.cpp"

void CborBaseEncoder::writeTypeValue(unsigned cbor_type, unsigned long value)
{
    if ( value < 24 )
        writeByte((cbor_type << 5) | value);
    else if ( value <= std::numeric_limits<uint8_t>::max() )
    {
        writeByte((cbor_type << 5) | 24);
        writeByte(value);
    }
    else if ( value <= std::numeric_limits<uint16_t>::max() )
    {
        writeByte((cbor_type << 5) | 25);
        writeByte(value >> 8);
        writeByte(value);
    }
    else
    {
        writeByte((cbor_type << 5) | 26);
        writeByte(value >> 24);
        writeByte(value >> 16);
        writeByte(value >> 8);
        writeByte(value);
    }
}

void CborBaseEncoder::writeTypeValue64(unsigned cbor_type, unsigned long long value)
{
    if ( value < 24 )
        writeByte((cbor_type << 5) | value);
    else if ( value <= std::numeric_limits<uint8_t>::max() )
    {
        writeByte((cbor_type << 5) | 24);
        writeByte(value);
    }
    else if ( value <= std::numeric_limits<uint16_t>::max() )
    {
        writeByte((cbor_type << 5) | 25);
        writeByte(value >> 8);
        writeByte(value);
    }
    else if ( value <= std::numeric_limits<uint32_t>::max() )
    {
        writeByte((cbor_type << 5) | 26);
        writeByte(value >> 24);
        writeByte(value >> 16);
        writeByte(value >> 8);
        writeByte(value);
    }
    else
    {
        writeByte((cbor_type << 5) | 27);
        writeByte(value >> 56);
        writeByte(value >> 48);
        writeByte(value >> 40);
        writeByte(value >> 32);
        writeByte(value >> 24);
        writeByte(value >> 16);
        writeByte(value >> 8);
        writeByte(value);
    }
}

void CborBaseEncoder::write(bool value)
{
    writeByte((7 << 5) | (value ? 21 : 20));
}

void CborBaseEncoder::write(unsigned char value)
{
    writeTypeValue(0, value);
}

void CborBaseEncoder::write(unsigned short value)
{
    writeTypeValue(0, value);
}

void CborBaseEncoder::write(unsigned int value)
{
    writeTypeValue(0, value);
}

void CborBaseEncoder::write(unsigned long value)
{
    writeTypeValue(0, value);
}

void CborBaseEncoder::write(unsigned long long value)
{
    writeTypeValue64(0, value);
}

void CborBaseEncoder::write(signed char value)
{
    if ( value < 0 )
        writeTypeValue(1, static_cast<unsigned long>(-1 - value));
    else
        writeTypeValue(0, static_cast<unsigned long>(value));
}

void CborBaseEncoder::write(short value)
{
    if ( value < 0 )
        writeTypeValue(1, static_cast<unsigned long>(-1 - value));
    else
        writeTypeValue(0, static_cast<unsigned long>(value));
}

void CborBaseEncoder::write(int value)
{
    if ( value < 0 )
        writeTypeValue(1, static_cast<unsigned long>(-1 - value));
    else
        writeTypeValue(0, static_cast<unsigned long>(value));
}

void CborBaseEncoder::write(long value)
{
    if ( value < 0 )
        writeTypeValue(1, static_cast<unsigned long>(-1 - value));
    else
        writeTypeValue(0, static_cast<unsigned long>(value));
}

void CborBaseEncoder::write(long long value)
{
    if ( value < 0 )
        writeTypeValue64(1, static_cast<unsigned long long>(-1 - value));
    else
        writeTypeValue64(0, static_cast<unsigned long long>(value));
}

void CborBaseEncoder::write(const char* str, bool is_text)
{
    std::string s(str);
    write(s, is_text);
}

void CborBaseEncoder::write(const std::string& str, bool is_text)
{
    writeTypeValue(is_text ? 3 : 2, str.size());
    for ( auto c : str )
        writeByte(c);
}

void CborBaseEncoder::write(const byte_string& str)
{
    writeTypeValue(2, str.size());
    for ( auto c : str )
        writeByte(c);
}

void CborBaseEncoder::writeArrayHeader(unsigned int array_size)
{
    writeTypeValue(4, array_size);
}

void CborBaseEncoder::writeArrayHeader()
{
    writeByte((4 << 5) | 31);
}

void CborBaseEncoder::writeMapHeader(unsigned int map_size)
{
    writeTypeValue(5, map_size);
}

void CborBaseEncoder::writeMapHeader()
{
    writeByte((5 << 5) | 31);
}

void CborBaseEncoder::writeBreak()
{
    writeByte((7 << 5) | 31);
}

template<>
void ParallelWriterPool<StreamWriter>::compressFile(const std::string& input, const std::string& output)
{

    if (logging_)
        LOG_INFO << "File handling: Renaming file:                 " << input.c_str() << " to " << output.c_str();
    if ( std::rename(input.c_str(), output.c_str()) != 0 )
        throw std::runtime_error("Can't rename " + input + " to " + output);
}
