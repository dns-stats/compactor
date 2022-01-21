/*
 * Copyright 2016-2018 Internet Corporation for Assigned Names and Numbers.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Developed by Sinodun IT (www.sinodun.com)
 */

#include <iostream>

#include "config.h"

#include "log.hpp"
#include "streamwriter.hpp"

const std::string& StreamWriter::STDOUT_FILE_NAME = "-";

StreamWriter::StreamWriter(const std::string& name, unsigned leve, bool logging)
    : os_(&std::cout), name_(name), temp_name_(name + ".tmp"), logging_(logging)
{
    if ( name_ != STDOUT_FILE_NAME )
    {
        ofs_.open(temp_name_, std::ofstream::binary);
        if (logging_)
            LOG_INFO << "File handling: Opening temporary file:   " << temp_name_ ;
        if ( ofs_.fail() )
            throw std::runtime_error("Can't open file " + temp_name_);
        os_ = &ofs_;
    }
    os_->exceptions(std::ofstream::badbit);
}

StreamWriter::~StreamWriter()
{
    os_->flush();
    if ( ofs_.is_open() )
    {
        ofs_.close();
        if (logging_)
            LOG_INFO << "File handling: Renaming temporary file:  " << temp_name_.c_str() << " to " << name_.c_str();
        if ( std::rename(temp_name_.c_str(), name_.c_str()) != 0 )
            LOG_ERROR << "file rename from " << temp_name_ << " to " << name_ << " failed";
    }
}

void StreamWriter::writeBytes(const std::string& s)
{
    writeBytes(reinterpret_cast<const uint8_t *>(s.c_str()), s.length());
}

void StreamWriter::writeBytes(const uint8_t *p, std::ptrdiff_t n_bytes)
{
    os_->write(reinterpret_cast<const char *>(p), n_bytes);
}

GzipStreamWriter::GzipStreamWriter(const std::string& name, unsigned level, bool logging)
    : StreamWriter(name, level, logging)
{
    boost::iostreams::gzip_params gzparams;

    gzparams.level = level;
    gzparams.file_name = name;
    gzparams.comment = "Compressed by " PACKAGE_NAME;
    gzout_.push(boost::iostreams::gzip_compressor(gzparams));
    gzout_.push(*os_);
}

GzipStreamWriter::~GzipStreamWriter()
{
    gzout_.reset();
}

void GzipStreamWriter::writeBytes(const uint8_t *p, std::ptrdiff_t n_bytes)
{
    gzout_.write(reinterpret_cast<const char *>(p), n_bytes);
}

XzException::XzException(lzma_ret err)
    : std::runtime_error(msg(err))
{
}

const char* XzException::msg(lzma_ret err)
{
    switch(err)
    {
    case LZMA_MEM_ERROR:
        return "Memory allocation failed.";

    case LZMA_OPTIONS_ERROR:
        return "Specified preset is not supported.";

    case LZMA_UNSUPPORTED_CHECK:
        return "Specified integrity check is not supported.";

    case LZMA_FORMAT_ERROR:
        return "Memory usage limit reached.";

    case LZMA_DATA_ERROR:
        return "Input data is corrupt.";

    case LZMA_PROG_ERROR:
        return "Programming error.";

    default:
        return "No error - application error.";
    }
}

XzStreamWriter::XzStreamWriter(const std::string& name, unsigned level, bool logging)
    : StreamWriter(name, level, logging), xz_stream_(LZMA_STREAM_INIT)
{
    lzma_ret ret = lzma_easy_encoder(&xz_stream_, level, LZMA_CHECK_CRC64);
    if ( ret != LZMA_OK )
        throw XzException(ret);
}

XzStreamWriter::~XzStreamWriter()
{
    try
    {
        while ( codeLzmaStream(LZMA_FINISH) != LZMA_STREAM_END )
            ;

        lzma_end(&xz_stream_);
    }
    catch (const XzException& err)
    {
        LOG_ERROR << err.what();
    }
}

void XzStreamWriter::writeBytes(const uint8_t *p, std::ptrdiff_t n_bytes)
{
    xz_stream_.next_in = p;
    xz_stream_.avail_in = n_bytes;

    while ( xz_stream_.avail_in > 0 )
        codeLzmaStream(LZMA_RUN);
}

lzma_ret XzStreamWriter::codeLzmaStream(lzma_action action)
{
    uint8_t output_buf[8192];

    xz_stream_.next_out = output_buf;
    xz_stream_.avail_out = sizeof(output_buf);

    lzma_ret ret = lzma_code(&xz_stream_, action);
    if ( ret == LZMA_OK || ret == LZMA_STREAM_END )
        StreamWriter::writeBytes(output_buf, sizeof(output_buf) - xz_stream_.avail_out);
    else
        throw XzException(ret);
    return ret;
}
