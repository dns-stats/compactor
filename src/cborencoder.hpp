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

#ifndef CBORENCODER_HPP
#define CBORENCODER_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <stdexcept>

#include <boost/optional.hpp>

#include "bytestring.hpp"
#include "log.hpp"
#include "makeunique.hpp"
#include "parallelwriter.hpp"
#include "streamwriter.hpp"

/**
 * \class CborBaseEncoder
 * \brief Virtual base for encoding basic values to CBOR.
 *
 * This class provides basic [CBOR] encoding facilities, providing
 * methods that write the CBOR encoding of basic values. The encoded
 * CBOR is written to an internal buffer for efficiency. When the buffer
 * should be flushed, `writeBytes()` is called to write the output.
 *
 * [cbor]: http://cbor.io "CBOR website"
 */
class CborBaseEncoder
{
public:
    /**
     * \brief The default constructor.
     */
    CborBaseEncoder() : buf_(), p_(&buf_[0]) {}

    /**
     * \brief Write optional values.
     *
     * Throw if there is no value there.
     *
     * \param value the value to write.
     */
    template<typename T>
    void write(const boost::optional<T>& value)
    {
        write(*value);
    }

    /**
     * \brief Write index and optional value.
     *
     * If there is no value, write nothing.
     *
     * \param index the index to write.
     * \param value the value to write.
     */
    template<typename T>
    void write(int index, const boost::optional<T>& value)
    {
        if ( value )
            write(index, *value);
    }

    /**
     * \brief Write index and value.
     *
     * \param index the index to write.
     * \param value the value to write.
     */
    template<typename T>
    void write(int index, const T& value)
    {
        write(index);
        write(value);
    }

    /**
     * \brief Write a boolean value.
     *
     * \param value the value to write.
     */
    void write(bool value);

    /**
     * \brief Write a signed char value.
     *
     * \param value the value to write.
     */
    void write(signed char value);

    /**
     * \brief Write an unsigned char value.
     *
     * \param value the value to write.
     */
    void write(unsigned char value);

    /**
     * \brief Write a signed short value.
     *
     * \param value the value to write.
     */
    void write(short value);

    /**
     * \brief Write an unsigned short value.
     *
     * \param value the value to write.
     */
    void write(unsigned short value);

    /**
     * \brief Write a signed integer value.
     *
     * \param value the value to write.
     */
    void write(int value);

    /**
     * \brief Write an unsigned integer value.
     *
     * \param value the value to write.
     */
    void write(unsigned int value);

    /**
     * \brief Write a signed long value.
     *
     * \param value the value to write.
     */
    void write(long value);

    /**
     * \brief Write an unsigned long value.
     *
     * \param value the value to write.
     */
    void write(unsigned long value);

    /**
     * \brief Write a signed long long value.
     *
     * \param value the value to write.
     */
    void write(long long value);

    /**
     * \brief Write an unsigned long long value.
     *
     * \param value the value to write.
     */
    void write(unsigned long long value);

    /**
     * \brief Write a string as either text or byte string.
     *
     * \param str     the value to write.
     * \param is_text write as text if true, else as bytes.
     */
    void write(const char* str, bool is_text=true);

    /**
     * \brief Write a string as either text or byte string.
     *
     * \param str     the value to write.
     * \param is_text write as text if true, else as bytes.
     */
    void write(const std::string& str, bool is_text=true);

    /**
     * \brief Write a byte string.
     *
     * \param str     the value to write.
     */
    void write(const byte_string& str);

    /**
     * \brief Write the start of an array with a fixed number of elements.
     *
     * \param array_size the number of elements.
     */
    void writeArrayHeader(unsigned int array_size);

    /**
     * \brief Write the start of an array with an unspecified number of elements.
     */
    void writeArrayHeader();

    /**
     * \brief Write the start of a map with a fixed number of elements.
     *
     * \param map_size the number of elements.
     */
    void writeMapHeader(unsigned int map_size);

    /**
     * \brief Write the start of a map with an unspecified number of elements.
     */
    void writeMapHeader();

    /**
     * \brief Write a break marker, marking the end of a map or array
     *        of indefinite length.
     */
    void writeBreak();

    /**
     * \brief Force writing of any accumulated output.
     */
    void flush()
    {
        // Writing zero length output may be a problem if a filter on
        // the underlying stream is closed.
        if ( p_ != buf_ )
        {
            writeBytes(buf_, p_ - buf_);
            p_ = buf_;
        }
    }

protected:
    /**
     * \brief Write all output accumulated in the buffer.
     *
     * \param p       pointer to the buffer.
     * \param n_bytes number of bytes in the buffer.
     */
    virtual void writeBytes(const uint8_t *p, std::ptrdiff_t n_bytes) = 0;

private:
    /**
     * \brief Write a basic CBOR major type and unsigned 32bit value.
     *
     * \param cbor_type the CBOR major type.
     * \param value     additional information value.
     */
    void writeTypeValue(unsigned cbor_type, unsigned long value);

    /**
     * \brief Write a basic CBOR major type and unsigned 64bit value.
     *
     * \param cbor_type the CBOR major type.
     * \param value     additional information value.
     */
    void writeTypeValue64(unsigned cbor_type, unsigned long long value);

    /**
     * \brief Output a single encoder output byte to the internal buffer.
     *
     * \param byte the output byte.
     */
    void writeByte(uint8_t byte)
    {
        *p_++ = byte;
        if ( p_ == &buf_[sizeof(buf_)] )
            flush();
    }

    /**
     * \brief Buffer to accumulate output.
     */
    uint8_t buf_[2048];

    /**
     * \brief Next output position in buffer.
     */
    uint8_t *p_;
};

/**
 * \class CborBaseStreamFileEncoder
 * \brief A virtual base class for encoding basic CBOR values to an output file.
 */
class CborBaseStreamFileEncoder : public CborBaseEncoder
{
public:
    /**
     * \brief Default constructor.
     */
    CborBaseStreamFileEncoder(){}

    /**
     * \brief Destructor.
     */
    virtual ~CborBaseStreamFileEncoder(){}

    /**
     * \brief Open the named file for output.
     *
     * \param name the filename.
     */
    virtual void open(const std::string& name) = 0;

    /**
     * \brief Close the output file.
     */
    virtual void close() = 0;

    /**
     * \brief Returns `true` if the file is open.
     */
    virtual bool is_open() const = 0;

    /**
     * \brief Return additional extension suggested for output file type.
     */
    virtual const char* suggested_extension() = 0;

    /**
     * \brief Count of the bytes written since opening.
     */
    virtual std::uintmax_t bytes_written() = 0;

protected:
    /**
     * \brief Write all accumulated output to the file.
     *
     * \param p       pointer to the buffer.
     * \param n_bytes number of bytes in the buffer.
     */
    virtual void writeBytes(const uint8_t *p, std::ptrdiff_t n_bytes) = 0;
};

/**
 * \class CborStreamFileEncoder
 * \brief Write encoder output to a file stream.
 */
template<typename Writer>
class CborStreamFileEncoder : public CborBaseStreamFileEncoder
{
public:
    /**
     * \brief Constructor.
     *
     * \param level compression level, if any.
     */
    explicit CborStreamFileEncoder(unsigned level = 6)
        : level_(level), bytes_written_(0) {}

    /**
     * \brief Destructor.
     *
     * Make sure the file is closed.
     */
    virtual ~CborStreamFileEncoder()
    {
        if ( is_open() )
            close();
    }

    /**
     * \brief Open the output file.
     *
     * This creates a new output writer to receive the data.
     *
     * \param name the base output filename.
     */
    virtual void open(const std::string& name)
    {
        if ( writer_ )
            throw std::runtime_error("Can't open file when one already open.");

        writer_ = make_unique<Writer>(name, level_);
        bytes_written_ = 0;
    }

    /**
     * \brief Close the output file.
     */
    virtual void close()
    {
        if ( !writer_ )
            throw std::runtime_error("Can't close file when not open.");

        flush();
        writer_.reset();
    }

    /**
     * \brief Returns `true` if the file is open.
     */
    virtual bool is_open() const
    {
        return static_cast<bool>(writer_);
    }

    /**
     * \brief Return additional extension suggested for output file type.
     */
    virtual const char* suggested_extension()
    {
        return Writer::suggested_extension();
    }

    /**
     * \brief Count of the bytes written since opening.
     */
    virtual std::uintmax_t bytes_written()
    {
        return bytes_written_;
    }

protected:
    /**
     * \brief Write all accumulated output to the file.
     *
     * \param p       pointer to the buffer.
     * \param n_bytes number of bytes in the buffer.
     */
    virtual void writeBytes(const uint8_t *p, std::ptrdiff_t n_bytes)
    {
        if ( !writer_ )
            throw std::runtime_error("Can't write to file when not open.");

        writer_->writeBytes(p, n_bytes);
        bytes_written_ += n_bytes;
    }

private:
    /**
     * \brief Pointer to the output writer.
     */
    std::unique_ptr<Writer> writer_;

    /**
     * \brief The compression level, if used.
     */
    unsigned level_;

    /**
     * \brief The number of bytes written.
     */
    std::uintmax_t bytes_written_;
};

/**
 * \class CborParallelStreamFileEncoder
 * \brief A stream file encoder that writes to a temporary file
 * and when writing is finished uses the writer pool to compress
 * the temporary file to the output file.
 */
class CborParallelStreamFileEncoder : public CborStreamFileEncoder<StreamWriter>
{
public:
    /**
     * \brief Constructor.
     *
     * \param pool the parallel writer pool to use.
     */
    explicit CborParallelStreamFileEncoder(std::shared_ptr<BaseParallelWriterPool>& pool)
        : CborStreamFileEncoder<StreamWriter>(0), pool_(pool)
    {
    }

    /**
     * \brief Open the output file.
     *
     * This creates a new temporary output to receive the data.
     *
     * \param name the base output filename.
     */
    virtual void open(const std::string& name)
    {
        name_ = name;

        CborStreamFileEncoder<StreamWriter>::open(name_ + ".raw");
    }

    /**
     * \brief Close the output file.
     *
     * Close the temporary output file and compress it to the final
     * output file.
     */
    virtual void close()
    {
        CborStreamFileEncoder<StreamWriter>::close();
        pool_->compressFile(name_ + ".raw", name_);
    }

    /**
     * \brief Return the suggested extension for files using the
     * compression done by the pool used by this encoder.
     */
    virtual const char* suggested_extension()
    {
        return pool_->suggested_extension();
    }

private:
    /**
     * \brief the writer pool for this encoder.
     */
    std::shared_ptr<BaseParallelWriterPool> pool_;

    /**
     * \brief the output filename.
     */
    std::string name_;
};

#endif
