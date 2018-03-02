/*
 * Copyright 2018 Internet Corporation for Assigned Names and Numbers.
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

byte_string PseudoAnonymise::opt_rdata(const byte_string& rdata) const
{
    const uint16_t OPTION_CODE_ECS = 8;
    uint16_t opt_code, opt_len;
    std::string::size_type offset = 0, len = rdata.size();
    byte_string res;

    while (offset + 4 < len)
    {
        std::string::size_type data;

        opt_code = (rdata[offset] << 8) + rdata[offset + 1];
        offset += 2;
        opt_len =  (rdata[offset] << 8) + rdata[offset + 1];
        offset += 2;

        data = offset;
        offset += opt_len;

        if ( opt_code == OPTION_CODE_ECS && opt_len > 4 )
        {
            uint16_t family = (rdata[data] << 8) + rdata[data + 1];

            if ( family == 1 || family == 2 )
            {
                uint8_t source_prefix_len = rdata[data + 2];
                uint8_t no_addr_bytes = (source_prefix_len + 7) / 8;

                if ( no_addr_bytes <= opt_len - 4 )
                {
                    if ( res.size() == 0 )
                        res = rdata;

                    uint8_t bits_to_zero = source_prefix_len % 8;
                    byte_string addr(family == 1 ? 4 : 16, '\0');
                    uint8_t last_byte_mask = 0xff;

                    if ( bits_to_zero > 0 )
                        last_byte_mask <<= (8 - bits_to_zero);

                    addr.replace(0, no_addr_bytes, rdata, data + 4, no_addr_bytes);
                    addr[no_addr_bytes - 1] &= last_byte_mask;
                    addr = address(IPAddress(addr)).asNetworkBinary();
                    addr[no_addr_bytes - 1] &= last_byte_mask;
                    res.replace(data + 4, no_addr_bytes, addr, 0, no_addr_bytes);
                }
            }
        }
    }

    return res.size() > 0 ? res : rdata;
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
