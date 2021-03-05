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

#ifndef TRANSPORTTYPE_HPP
#define TRANSPORTTYPE_HPP

/**
 * \brief the known transaction types from dnstap.
 */
enum class TransactionType
{
    NONE,
    AUTH_QUERY,
    AUTH_RESPONSE,
    RESOLVER_QUERY,
    RESOLVER_RESPONSE,
    CLIENT_QUERY,
    CLIENT_RESPONSE,
    FORWARDER_QUERY,
    FORWARDER_RESPONSE,
    STUB_QUERY,
    STUB_RESPONSE,
    TOOL_QUERY,
    TOOL_RESPONSE,
    UPDATE_QUERY,
    UPDATE_RESPONSE,
};

/**
 * \brief the known transport types.
 */
enum class TransportType
{
    UDP,
    TCP,
    DOT,
    DDOT,       /* Datagram DNS over TLS. */
    DOH
};

#endif
