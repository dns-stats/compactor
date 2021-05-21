/*
 * Copyright 2016-2019, 2021 Internet Corporation for Assigned Names and Numbers.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Developed by Sinodun IT (www.sinodun.com)
 */

/**
 * \file cbordecoder.hpp
 * \brief Decode basic data types from CBOR.
 */

#ifndef CBORDECODER_HPP
#define CBORDECODER_HPP

#include <cstdint>
#include <fstream>
#include <stdexcept>
#include <string>
#include <type_traits>

#include <boost/optional.hpp>

#include "bytestring.hpp"

/**
 * \exception cbor_decode_error
 * \brief Signals a malformed CBOR item.
 */
class cbor_decode_error : public std::runtime_error
{
public:
    /**
     * \brief Constructor.
     *
     * \param what message detailing the problem.
     */
    explicit cbor_decode_error(const std::string& what)
        : std::runtime_error(what) {}

    /**
     * \brief Constructor.
     *
     * \param what message detailing the problem.
     */
    explicit cbor_decode_error(const char*  what)
        : std::runtime_error(what) {}
};

/**
 * \exception cbor_end_of_input
 * \brief Signals attempt to read past end of CBOR input.
 */
class cbor_end_of_input : public std::runtime_error
{
public:
    /**
     * \brief Constructor.
     */
    cbor_end_of_input()
        : std::runtime_error("End of input on CBOR stream") {}
};

/**
 * \class CborBaseDecoder
 * \brief Virtual base for decoding CBOR to basic values.
 *
 * This class provides basic [CBOR] decoding facilities, providing
 * methods that read CBOR encoding and return basic values. The CBOR
 * is read from an internal buffer, replenished using `readBytes()`.
 *
 * [cbor]: http://cbor.io "CBOR website"
 */
class CborBaseDecoder
{
public:
    /**
     * \brief Types of basic CBOR record.
     */
    enum type_t
    {
        TYPE_UNSIGNED = 0,
        TYPE_SIGNED = 1,
        TYPE_BINARY = 2,
        TYPE_STRING = 3,
        TYPE_ARRAY = 4,
        TYPE_MAP = 5,
        TYPE_TAG = 6,
        TYPE_SIMPLE = 7,
        TYPE_FLOAT,
        TYPE_BREAK,
    };

    /**
     * \brief Constructor.
     */
    CborBaseDecoder()
        : buf_(), bufend_(&buf_[0]), p_(bufend_) {}

    /**
     * \brief Returns the type of the current basic CBOR record.
     *
     * This does not change the current position.
     */
    type_t type();

    /**
     * \brief templated read.
     *
     * Read an item of given type. Pass to private implementation which
     * can be overloaded and specialised.
     *
     * \param item The item to read.
     */
    template<typename T>
    void read(T& item)
    {
        read_item(item);
    }

    /**
     * \brief templated read of optional item.
     *
     * Read an item of given type. Pass to private implementation which
     * can be overloaded and specialised.
     *
     * \param item The item to read.
     */
    template<typename T>
    void read(boost::optional<T>& item)
    {
        T val;
        read_item(val);
        item = val;
    }

    /**
     * \brief Read the value of the current CBOR unsigned item.
     *
     * Reading moves on the next CBOR item.
     *
     * \return the value of the CBOR item.
     * \throws cbor_decode_error if the CBOR is invalid.
     * \throws std::logic_error if the current CBOR item isn't of unsigned type.
     */
    uint64_t read_unsigned();

    /**
     * \brief. Read the value of the current CBOR signed or unsigned item.
     *
     * Reading moves on the next CBOR item.
     *
     * \return the value of the CBOR item.
     * \throws cbor_decode_error if the CBOR is invalid.
     * \throws std::logic_error if the current CBOR item isn't of signed type.
     */
    int64_t read_signed();

    /**
     * \brief. Read the value of the current CBOR boolean item.
     *
     * Reading moves on the next CBOR item. For C-DNS backwards
     * compatibility reasons, this will recognise CBOR boolean types
     * OR any integer type. In the latter case, non-zero is <code>true</code>.
     *
     * \return the value of the CBOR item.
     * \throws cbor_decode_error if the CBOR is invalid.
     * \throws std::logic_error if the current CBOR item isn't of correct type.
     */
    bool read_bool();

    /**
     * \brief Read the value of the current CBOR binary item.
     *
     * Reading moves on the next CBOR item.
     *
     * \return the contents of the CBOR item.
     * \throws cbor_decode_error if the CBOR is invalid.
     * \throws std::logic_error if the current CBOR item isn't of binary type.
     */
    byte_string read_binary();

    /**
     * \brief Read the value of the current CBOR string or binary item.
     *
     * Reading moves on the next CBOR item.
     *
     * \return the contents of the CBOR item.
     * \throws cbor_decode_error if the CBOR is invalid.
     * \throws std::logic_error if the current CBOR item isn't of string type.
     */
    std::string read_string();

    /**
     * \brief Read the details of the current CBOR array header.
     *
     * The array header is followed by CBOR items for each array value.
     * If the length is indefinite, the array values are terminated by
     * a CBOR BREAK.
     *
     * Reading moves on the next CBOR item.
     *
     * \param indefinite_length set `true` to indicate the array length is indefinite.
     * \return the number of elements in the CBOR array, if not indefinite.
     * \throws cbor_decode_error if the CBOR is invalid.
     * \throws std::logic_error if the current CBOR item isn't an array header.
     */
    uint64_t readArrayHeader(bool& indefinite_length);

    /**
     * \brief Read the details of the current CBOR map header.
     *
     * The map header is followed by a CBOR key and value item for each
     * element in the map. If the length is indefinite, the map values
     * are terminated by a CBOR BREAK.
     *
     * Reading moves on the next CBOR item.
     *
     * \param indefinite_length set `true` to indicate the array length is indefinite.
     * \return the number of elements in the CBOR map, if not indefinite.
     * \throws cbor_decode_error if the CBOR is invalid.
     * \throws std::logic_error if the current CBOR item isn't a map header.
     */
    uint64_t readMapHeader(bool& indefinite_length);

    /**
     * \brief Read the value of the current CBOR tag item.
     *
     * Reading moves on the next CBOR item.
     *
     * \return the contents of the CBOR item.
     * \throws cbor_decode_error if the CBOR is invalid.
     * \throws std::logic_error if the current CBOR item isn't of tag type.
     */
    uint64_t read_tag();

    /**
     * \brief Read the value of the current CBOR simple item.
     *
     * Note that CBOR SIMPLE float values are handled as a separate type,
     * FLOAT, and that BREAK values are handled as a separate type BREAK.
     *
     * Reading moves on the next CBOR item.
     *
     * \return the contents of the CBOR item.
     * \throws cbor_decode_error if the CBOR is invalid.
     * \throws std::logic_error if the current CBOR item isn't of simple type.
     */
    uint8_t readSimple();

    /**
     * \brief Not currently implemented.
     */
    double read_float();

    /**
     * \brief Read the current CBOR BRIEF item.
     *
     * Reading moves on the next CBOR item.
     *
     */
    void readBreak();

    /**
     * \brief Skip past the current CBOR item.
     *
     * \throws cbor_decode_error if the CBOR is invalid.
     * \throws std::logic_error if the current CBOR item isn't a time.
     */
    void skip();

protected:
    /**
     * Read more CBOR input values into the buffer.
     *
     * \param p       pointer to the buffer.
     * \param n_bytes maximum number of bytes to read.
     * \return the number of bytes read.
     * \throws cbor_end_of_input when at EOF.
     */
    virtual unsigned readBytes(uint8_t* p, std::ptrdiff_t n_bytes) = 0;

private:
    /**
     * \brief General read - assume for integer type, so works for enums.
     */
    template<typename T>
    void read_item(T& item, typename std::enable_if<std::is_signed<T>::value>::type* = 0)
    {
        item = read_signed();
    }

    template<typename T>
    void read_item(T& item, typename std::enable_if<std::is_unsigned<T>::value>::type* = 0)
    {
        item = read_unsigned();
    }

    void read_item(bool& item)
    {
        item = read_bool();
    }

    void read_item(byte_string& item)
    {
        item = read_binary();
    }

    void read_item(std::string& item)
    {
        item = read_string();
    }

    /**
     * \brief See whether more bytes need to be read.
     */
    void needRead()
    {
        if ( p_ == bufend_ )
        {
            unsigned nread = readBytes(buf_, sizeof(buf_));
            p_ = &buf_[0];
            bufend_ = &buf_[nread];
        }
    }

    /**
     * \brief Read the fundamental CBOR item values.
     *
     * This moves the read pointer past the item header.
     *
     * \param major returns the major value.
     * \param minor returns the minor value.
     * \param value returns the number from item, if appropriate.
     */
    void read_type_unsigned(unsigned& major, unsigned& minor, uint64_t& value);

    /**
     * \brief Get the CBOR item identifier.
     *
     * This does not move the read pointer.
     *
     * \param major returns the major value.
     * \param minor returns the minor value.
     */
    void major_minor(unsigned& major, unsigned& minor)
    {
        needRead();
        major = (*p_ >> 5);
        minor = (*p_ & 0x1f);
    }

    /**
     * \brief Input buffer.
     */
    uint8_t buf_[2048];

    /**
     * \brief The end of the current buffer contents.
     */
    uint8_t* bufend_;

    /**
     * \brief Pointer to the current buffer position.
     */
    uint8_t* p_;
};

/**
 * \class CborStreamDecoder
 * \brief A class for decoding basic CBOR values from an input stream.
 */
class CborStreamDecoder : public CborBaseDecoder
{
public:
    /**
     * \brief Default constructor.
     */
    explicit CborStreamDecoder(std::istream& is) : is_(is)
    {
        is_.exceptions(std::istream::badbit);
    }

protected:
    /**
     * Read more CBOR input values into the buffer.
     *
     * \param p       pointer to the buffer.
     * \param n_bytes maximum number of bytes to read.
     * \return the number of bytes read.
     * \throws cbor_end_of_input when at EOF.
     */
    virtual unsigned readBytes(uint8_t* p, std::ptrdiff_t n_bytes)
    {
        if ( is_.eof() )
            throw cbor_end_of_input();

        is_.read(reinterpret_cast<char *>(p), n_bytes);
        return is_.gcount();
    }

    /**
     * \brief The input stream.
     */
    std::istream& is_;
};

#endif
