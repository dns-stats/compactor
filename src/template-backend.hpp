/*
 * Copyright 2018-2019, 2021 Internet Corporation for Assigned Names and Numbers.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 */

/**
 * \file template-backend.hpp
 * \brief Inspector output backend, templated text output.
 */

#ifndef TEMPLATE_BACKEND_HPP
#define TEMPLATE_BACKEND_HPP

#include <memory>
#include <ostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "streamwriter.hpp"

#include "backend.hpp"

/**
 * \class TemplateException
 * \brief Base exception for template errors.
 */
class TemplateException : public std::runtime_error
{
public:
    /**
     * \brief Constructor.
     *
     * \param fname     the template file.
     * \param msg       the message.
     */
    explicit TemplateException(const std::string& fname, const std::string& msg);
};

/**
 * \class TemplateLoadException
 * \brief Exception thrown for template load errors.
 */
class TemplateLoadException : public TemplateException
{
public:
    /**
     * \brief Constructor.
     *
     * \param fname     the template file.
     */
    explicit TemplateLoadException(const std::string& fname)
        : TemplateException(fname, "load failed") {}
};

/**
 * \class TemplateExpandException
 * \brief Exception thrown for template expand errors.
 */
class TemplateExpandException : public TemplateException
{
public:
    /**
     * \brief Constructor.
     *
     * \param fname     the template file.
     */
    explicit TemplateExpandException(const std::string& fname)
        : TemplateException(fname, "expand failed") {}
};

/**
 * \struct TemplateBackendOptions
 * \brief Options for the text template backend.
 */
struct TemplateBackendOptions
{
    /**
     * \brief base options.
     */
    OutputBackendOptions baseopts;

    /**
     * \brief template name
     */
    std::string template_name;

    /**
     * \brief values to include in template
     */
    std::vector<std::pair<std::string, std::string>> values;

    /**
     * \brief path to GeoIP database directory.
     */
    std::string geoip_db_dir_path;
};

/**
 * \class TemplateBackend
 * \brief Text template backend for inspector.
 */
class TemplateBackend : public OutputBackend
{
public:
    /**
     * \brief Constructor.
     *
     * \param opts              options information.
     * \param fname             output file path.
     */
    TemplateBackend(const TemplateBackendOptions& opts, const std::string& fname);

    /**
     * \brief Destructor.
     */
    virtual ~TemplateBackend();

    /**
     * \brief Output a QueryResponse.
     *
     * \param qr        the QueryResponse.
     * \param config    the configuration applying when recording the QR.
     */
    virtual void output(const QueryResponseData& qr, const Configuration& config);

    /**
     * \brief the output file path.
     *
     * \return the output file path. "" if unnamed stream, e.g. stdout.
     */
    virtual std::string output_file();

private:
    /**
     * \brief have we loaded the modifiers?
     */
    static bool loaded_modifiers;

    /**
     * \brief the options.
     */
    TemplateBackendOptions opts_;

    /**
     * \brief the output file path.
     */
    std::string output_path_;

    /**
     * \brief the output writer.
     */
    std::unique_ptr<StreamWriter> writer_;

    /**
     * \brief first line of output.
     */
    bool first_line{true};
};

#endif
