#include <vector>
#include <memory>
#include <cstring>
#include <cassert>

#include <cryptopp/modes.h>
#include <cryptopp/sha.h>
#include <cryptopp/rsa.h>
#include <cryptopp/rdrand.h>
#include <cryptopp/aes.h>

#include <logger.h>
#include "cipher.h"

#define ROUND_BLOCK(n,block) ((n) + ((block) - ((n) % (block))) % (block))

using namespace dint;


std::shared_ptr<bytes> dint::sha256(const uint8_t *buf, size_t len)
{
    using namespace CryptoPP;
    static SHA256 hash;

    bytes_ptr digest = std::make_shared<bytes>();
    digest->resize(hash.DigestSize());

    hash.Update((byte*) buf, len);
    hash.Final((byte*) digest->data());

    return digest;
}

AESCipher::AESCipher(const bytes &key, const size_t key_size)
        : m_key (key.cbegin(), key.cbegin()),
            m_enc(), m_dec(),
            m_keysize (key_size)
{
    if (key.size() < key_size)
        throw std::invalid_argument("not enough bytes for given key size");

    m_enc.SetKey((const byte*)m_key.data(), key_size);
    m_dec.SetKey((const byte*)m_key.data(), key_size);
}

AESCipher::AESCipher(const uint8_t *key, const size_t bytes, const size_t key_size)
        : m_key (bytes, 0),
            m_enc(), m_dec(),
            m_keysize (key_size)
{
    if (bytes < key_size)
        throw std::invalid_argument("not enough bytes for given key size");

    memcpy(m_key.data(), key, bytes);
    m_enc.SetKey((const byte*)m_key.data(), key_size);
    m_dec.SetKey((const byte*)m_key.data(), key_size);
}

AESCipher::AESCipher(const CryptoPP::Integer &key, const size_t key_size)
        : m_key (),
            m_enc(), m_dec(),
            m_keysize(key_size)
{

    // get bytes of shared key
    size_t bytes = key.MinEncodedSize();
    bytes = bytes > 16 ? bytes : 16;

    m_key.resize(bytes);
    key.Encode((byte*)m_key.data(), bytes);

    m_enc.SetKey((const byte*)m_key.data(), key_size);
    m_dec.SetKey((const byte*)m_key.data(), key_size);
}

std::shared_ptr<bytes>
AESCipher::encrypt(const bytes &plain, size_t prepend)
{
    const size_t N = plain.size();
    size_t n = ROUND_BLOCK(N+prepend, BLOCK_SIZE);

    bytes plain_cpy (0);
    const bytes *blocks  = &plain;
    if (N < n)
    {
        // resize to multiple of block size
        plain_cpy.reserve(n);
        if (prepend > 0) {
            if (prepend >= 4)  plain_cpy.push_back((N & 0xff000000l) >> 24);
            if (prepend >= 3)  plain_cpy.push_back((N & 0xff00000l)  >> 16);
            if (prepend >= 2)  plain_cpy.push_back((N & 0xff00l)     >>  8);
            plain_cpy.push_back(N & 0xffl);
        }

        plain_cpy.insert(plain_cpy.end(), plain.begin(), plain.end());
        blocks = &plain_cpy;
    }

    // create buffer to store ciphered bytes
    auto enc_blocks { std::make_shared<bytes>(n) };
    memcpy(enc_blocks->data(), blocks->data(), N);

    m_enc.ProcessData((byte*)enc_blocks->data(), (byte*)blocks->data(), n);

    // return encrypted block
    return enc_blocks;
}


std::shared_ptr<bytes>
AESCipher::decrypt(const bytes &blocks, size_t len_bytes, size_t offset)
{
    // assume block size is multiple of block size
    const size_t n = blocks.size()-offset;
    assert ((n % AESCipher::BLOCK_SIZE) == 0);

    // create buffer to store deciphered bytes
    auto dec_blocks { std::make_shared<bytes>(n) };

    m_dec.ProcessData((byte*)dec_blocks->data(), (byte*)blocks.data()+offset, n);

    // trim off padding
    if (len_bytes > 0) {
        size_t N = 0;
        const uint8_t *p = dec_blocks->data();
        switch (len_bytes)
        {
            // TODO: take into account host endianess more cleanly... meh good enough
            case 1:
                N = *p;
                break;
            case 2:
                N = (*p << 8) + *(p+1);
                break;
            case 3:
                N = (*p << 16) + (*(p+1) << 8) + *(p+2);
                break;
            default:
                N = (*p << 24) + (*(p+1) << 16) + (*(p+2) << 8) + *(p+3);
        }

        // remove the length from decrypted block
        auto trimmed_block { std::make_shared<bytes>() };
        trimmed_block->resize(N);
        memcpy(trimmed_block->data(), dec_blocks->data()+len_bytes, N);

        return trimmed_block;
    }

    return dec_blocks;
}
