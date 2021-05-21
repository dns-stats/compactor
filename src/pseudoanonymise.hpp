/*
 * Copyright 2018-2019, 2021 Internet Corporation for Assigned Names and Numbers.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Developed by Sinodun IT (www.sinodun.com)
 */

/**
 * \file pseudoanonymise.hpp
 * \brief Pseudo-anonymise IP addresses.
 */

#ifndef PSEUDOANONYMISE_HPP
#define PSEUDOANONYMISE_HPP

#include <string>

#include "config.h"

#if ENABLE_PSEUDOANONYMISATION

#include <openssl/aes.h>

#include "bytestring.hpp"
#include "capturedns.hpp"
#include "ipaddress.hpp"

/**
 * \class PseudoAnonymise
 * \brief (Pseudo)-anonymise IP addresses.
 *
 * Pseudo-anonymisation is done using AES-128 with a key. The (16 byte) key
 * may be supplied directly, or may be generate from a passphrase.
 *
 * Key generation from passphrase and pseudo-anonymisation of IPv6 addresses
 * is done using the mechanisms described in PowerDNS ipcipher. See
 * https://powerdns.org/ipcipher/. Currently there is one difference
 * compared to `ipcipher` - when generating a key from a passphrase a
 * salt of `cdnscdnscdnscdns` is used, rather than `ipcipheripcipher`.
 *
 * Pseudo-anonymisation of IPv4 addresses does not use the `ipcipher`
 * mechanism. Instead, a buffer containing 4 concatenated copies of the
 * the IPv4 address is run through AES-128 and the most significant 4
 * bytes of the result used as the pseudo-anonymised IPv4 address.
 */
class PseudoAnonymise
{
public:
    /**
     * \brief Constructor
     *
     * \param str a key pass phrase.
     */
    explicit PseudoAnonymise(const std::string& str);

    /**
     * \brief Constructor
     *
     * \param str a key pass phrase.
     * \param salt the salt to use.
     */
    explicit PseudoAnonymise(const char* str, const char* salt = "cdnscdnscdnscdns");

    /**
     * \brief Constructor
     *
     * \param key a 16 byte key.
     */
    explicit PseudoAnonymise(const byte_string& key);

    /**
     * \brief Pseudo-anonymise an address.
     *
     * \param addr the address to pseudo-anonymise.
     * \returns the pseudo-anonymised address.
     */
    IPAddress address(const IPAddress& addr) const;

    /**
     * \brief Pseudo-anonymise EDNS0.
     *
     * Pseudo-anonymise an EDNS0 option. At present, only
     * CLIENT_SUBNET affected.
     */
    byte_string edns0(const byte_string& edns0) const;

    /**
     * \brief Generate key from passphrase and salt.
     *
     * \param str  the passphrase.
     * \param salt the salt.
     */
    static byte_string generate_key(const char *str, const char *salt);

private:
    AES_KEY aes_key;
};

#else

/**
 * \class PseudoAnonymise
 * \brief Empty dummy for when not built with pseudo-anonymising.
 */
class PseudoAnonymise
{
};

#endif

#endif
