/*
 * Copyright 2018-2019 Internet Corporation for Assigned Names and Numbers.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Developed by Sinodun IT (www.sinodun.com)
 */

#include <cstring>
#include <stdexcept>

#include "config.h"

#if ENABLE_PSEUDOANONYMISATION

#include <openssl/evp.h>

#include "bytestring.hpp"
#include "ipaddress.hpp"

#include "pseudoanonymise.hpp"

PseudoAnonymise::PseudoAnonymise(const std::string& str)
    : PseudoAnonymise(str.c_str())
{
}

PseudoAnonymise::PseudoAnonymise(const char* str, const char* salt)
    : PseudoAnonymise(generate_key(str, salt))
{
}

PseudoAnonymise::PseudoAnonymise(const byte_string& key)
{
    if ( key.size() != 16 )
        throw std::logic_error("Keys must be 16 bytes long");
    if ( AES_set_encrypt_key(key.data(), key.size() * 8, &aes_key) != 0 )
        throw std::range_error("Key setup error");
}

IPAddress PseudoAnonymise::address(const IPAddress& addr) const
{
    byte_string addr_in;
    byte_string addr_out(16,'\0');

    if ( addr.is_ipv6() )
        addr_in = addr.asNetworkBinary();
    else
    {
        byte_string addr4 = addr.asNetworkBinary();
        addr_in = addr4 + addr4 + addr4 + addr4;
    }

    AES_encrypt(addr_in.data(), &addr_out.front(), &aes_key);

    return IPAddress(addr.is_ipv6() ? addr_out : addr_out.substr(0, 4));
}

byte_string PseudoAnonymise::edns0(const byte_string& edns0) const
{
    bool client_subnet_found = false;
    CaptureDNS::EDNS0 e0(CaptureDNS::INTERNET, 0, edns0);

    for ( auto& opt : e0.options() )
        if ( opt.code() == CaptureDNS::CLIENT_SUBNET )
        {
            client_subnet_found = true;
            break;
        }

    if ( !client_subnet_found )
        return edns0;

    CaptureDNS::EDNS0 res(CaptureDNS::INTERNET, 0, byte_string());

    for ( auto& opt : e0.options() )
    {
        if ( opt.code() == CaptureDNS::CLIENT_SUBNET )
        {
            byte_string opt_data = opt.data();
            uint16_t family = (opt_data[0] << 8) + opt_data[1];
            if ( family != 1 && family != 2 )
            {
                res.add_option(opt);
                continue;
            }

            uint8_t source_prefix_len = opt_data[2];
            size_t no_addr_bytes = (source_prefix_len + 7) / 8;

            if ( opt_data.size() < no_addr_bytes + 4 )
            {
                res.add_option(opt);
                continue;
            }

            uint8_t bits_to_zero = source_prefix_len % 8;
            byte_string addr(family == 1 ? 4 : 16, '\0');
            uint8_t last_byte_mask = 0xff;

            if ( bits_to_zero > 0 )
                last_byte_mask <<= (8 - bits_to_zero);

            addr.replace(0, no_addr_bytes, opt_data, 4, no_addr_bytes);
            addr[no_addr_bytes - 1] &= last_byte_mask;
            addr = address(IPAddress(addr)).asNetworkBinary();
            addr[no_addr_bytes - 1] &= last_byte_mask;
            opt_data.replace(4, no_addr_bytes, addr, 0, no_addr_bytes);
            res.add_option(CaptureDNS::EDNS0_option(CaptureDNS::CLIENT_SUBNET, opt_data));
        }
        else
        {
            res.add_option(opt);
        }
    }

    return res.rr().data();
}

byte_string PseudoAnonymise::generate_key(const char *str, const char *salt)
{
    byte_string key(16, '\0');
    int res;

    res = PKCS5_PBKDF2_HMAC_SHA1(str,
                                 std::strlen(str),
                                 reinterpret_cast<const unsigned char *>(salt),
                                 std::strlen(salt),
                                 50000,
                                 key.size(),
                                 &key.front());
    if ( !res )
        throw std::range_error("Key passphrase generate error");
    return key;
}

#endif
