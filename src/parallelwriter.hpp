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

#ifndef PARALLELWRITER_HPP
#define PARALLELWRITER_HPP

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>

#include "log.hpp"
#include "streamwriter.hpp"
#include "util.hpp"

/**
 * \class BaseParallelWriterPool
 * \brief Base class for all types of writer thread pools.
 */
class BaseParallelWriterPool
{
public:
    /**
     * \brief Constructor.
     */
    BaseParallelWriterPool() {}

    /**
     * \brief Destructor.
     *
     * Establish that the destructor is virtual.
     */
    virtual ~BaseParallelWriterPool() {}

    /**
     * \brief Compress input file to output file.
     *
     * Start compressing input file to output file. Typically this happens
     * in a thread managed by the pool.
     *
     * \param input  name of input file.
     * \param output name of output file.
     */
    virtual void compressFile(const std::string& input, const std::string& output) = 0;

    /**
     * \brief Signal the compression to abort.
     */
    virtual void abort() = 0;

    /**
     * \brief Wait for the compression to finish.
     */
    virtual void wait() = 0;

    /**
     * \brief Return the suggested extension for files using the
     * compression done by this pool.
     */
    virtual const char* suggested_extension() = 0;
};

/**
 * \class ParallelWriterPool
 * \brief Compress files, one file per thread.
 */
template<typename Writer>
class ParallelWriterPool : public BaseParallelWriterPool
{
    /**
     * \brief size of buffer to use when compressing.
     */
    static const unsigned OUTPUT_BUFFER_SIZE = 65536;

public:
    /**
     * \brief Constructor.
     *
     * \param max_threads maximum number of threads to use when
     * compressing.
     * \param level       the compression level to use.
     */
    ParallelWriterPool(unsigned max_threads, unsigned level)
        : level_(level), max_threads_(max_threads), nthreads_(0), abort_(false)
    {
    }

    /**
     * \brief Destructor.
     *
     * Wait for all current compressions to finish before dying.
     */
    virtual ~ParallelWriterPool()
    {
        wait();
    }

    /**
     * \brief Compress input file to output file in a separate thread.
     *
     * When the compression is finished, delete the input file.
     *
     * If the maximum number of compression threads are already in use,
     * wait until one is finished before starting.
     *
     * \param input  path of input file.
     * \param output path of output file.
     */
    virtual void compressFile(const std::string& input, const std::string& output)
    {
        std::unique_lock<std::mutex> lock(m_);
        if ( nthreads_ >= max_threads_ )
            thread_finished_.wait(lock, [&](){ return nthreads_ < max_threads_; });
        std::thread t([=]{ compressFileThread(input, output); });
        t.detach();
        ++nthreads_;
    }

    /**
     * \brief Request abort of all ongoing compressions.
     */
    virtual void abort()
    {
        abort_ = true;
    }

    /**
     * \brief Wait for all current compressions to finish.
     */
    virtual void wait()
    {
        std::unique_lock<std::mutex> lock(m_);
        if ( nthreads_ > 0 )
            thread_finished_.wait(lock, [&](){ return nthreads_ == 0; });
    }

    /**
     * \brief Return additional extension suggested for output file type.
     */
    virtual const char* suggested_extension()
    {
        return Writer::suggested_extension();
    }

private:
    /**
     * \brief Compression thread function.
     *
     * Read input file, compress to output file, and when done delete
     * input file. If the compression is aborted, delete both input
     * and output files.
     *
     * \param input  path of input file.
     * \param output path of output file.
     */
    void compressFileThread(const std::string& input, const std::string& output)
    {
        set_thread_name("comp:compress");

        try
        {
            std::ifstream ifs(input, std::ios::binary);
            if ( !ifs.is_open() )
                throw std::runtime_error("Can't open file " + input);
            ifs.exceptions(std::ifstream::badbit);

            {
                Writer writer(output, level_);
                uint8_t buf[OUTPUT_BUFFER_SIZE];

                while ( !abort_ && !ifs.eof() )
                {
                    ifs.read(reinterpret_cast<char *>(buf), sizeof(buf));
                    writer.writeBytes(buf, ifs.gcount());
                }
            }

            ifs.close();
            if ( std::remove(input.c_str()) != 0 )
                throw std::runtime_error("Can't remove file " + input);
            if ( abort_ && std::remove(output.c_str()) != 0 )
                throw std::runtime_error("Can't remove file " + output);
        }
        catch (const std::exception& err)
        {
            LOG_ERROR << err.what();
        }

        std::unique_lock<std::mutex> lock(m_);
        --nthreads_;
        thread_finished_.notify_one();
    }

    /**
     * \brief compression level.
     */
    unsigned level_;

    /**
     * \brief maximum number of simultaneous compression threads.
     *
     * In other words, maximum number of files that can be compressed
     * at once.
     */
    unsigned max_threads_;

    /**
     * \brief current number of simultaneously compression threads.
     */
    unsigned nthreads_;

    /**
     * \brief flag indicating whether compression should abort.
     */
    std::atomic_bool abort_;

    /**
     * \brief mutex guarding state.
     */
    std::mutex m_;

    /**
     * \brief condition variable to signal when a thread finishes.
     */
    std::condition_variable thread_finished_;
};

/**
 * \brief Compress input file to output file in a separate thread.
 *
 * When the output writer is a plain stream with no compression,
 * then just rename the input to the output.
 *
 * \param input  path of input file.
 * \param output path of output file.
 */
template<>
void ParallelWriterPool<StreamWriter>::compressFile(const std::string& input, const std::string& output);

#endif
