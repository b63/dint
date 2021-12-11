#ifndef DINT_CIPHER_H
#define DINT_CIPHER_H

#include <vector>
#include <memory>
#include <cstring>
#include <cassert>

#include <cryptopp/modes.h>
#include <cryptopp/sha.h>
#include <cryptopp/rdrand.h>
#include <cryptopp/rsa.h>
#include <cryptopp/aes.h>

#define ROUND_BLOCK(n,block) ((n) + ((block) - ((n) % (block))) % (block))

namespace dint
{
    using bytes     = std::vector<uint8_t>;
    using bytes_ptr = std::shared_ptr<std::vector<uint8_t>>;
    using byte      = CryptoPP::byte;

    std::shared_ptr<bytes> sha256(const uint8_t *buf, size_t len);

    template <class Key>
    std::shared_ptr<bytes>
    rsa_encrypt(Key &k, const std::vector<uint8_t> &data)
    {
        static auto rdrand {CryptoPP::RDRAND()};

        CryptoPP::RSAES_OAEP_SHA_Encryptor ec  (k);

        const size_t max_size = ec.FixedMaxPlaintextLength();
        const size_t maxc_size = ec.FixedCiphertextLength();
        const size_t dsize = data.size();
        assert (0 != max_size);

        size_t offset = 0;

        auto cipher {std::make_shared<bytes>()};
        cipher->reserve(maxc_size * ceil(dsize / (double)max_size));

        while (offset < dsize)
        {
            const size_t len = (dsize - offset < max_size ? dsize - offset : max_size);
            const size_t ecl = ec.CiphertextLength(len);

            const size_t coffset = cipher->size();
            cipher->resize(coffset + ecl);
            ec.Encrypt(rdrand, (byte*)data.data()+offset, len, (byte*)cipher->data()+coffset);
            offset += len;
        }

        return cipher;
    }


    template <class Key>
    std::shared_ptr<bytes>
    rsa_decrypt(const Key &k, const uint8_t *buffer, size_t length)
    {
        static auto rdrand {CryptoPP::RDRAND()};
        CryptoPP::RSAES_OAEP_SHA_Decryptor dc {k};

        const size_t max_size = dc.FixedMaxPlaintextLength();
        const size_t maxc_size = dc.FixedCiphertextLength();
        assert (0 != max_size);

        size_t offset = 0;
        size_t poffset = 0;

        auto plaintext {std::make_shared<bytes>()};
        plaintext->reserve(max_size * ceil(length / (double)maxc_size));

        while (offset < length)
        {
            const size_t len = (length - offset < maxc_size ? length - offset : maxc_size);
            const size_t epl = dc.MaxPlaintextLength(len);

            if (plaintext->size() < poffset + epl)
                plaintext->resize(poffset + epl);

            CryptoPP::DecodingResult result = dc.Decrypt(rdrand, (byte*)buffer+offset, len, (byte*)plaintext->data()+poffset);
            assert(result.isValidCoding);
            assert(result.messageLength <= epl);

            offset += len;
            poffset += result.messageLength;
        }
        plaintext->resize(poffset);

        return plaintext;
    }

    template <class Key>
    inline 
    std::shared_ptr<bytes> rsa_decrypt(const Key &k, const bytes &buffer)
    {
        return rsa_decrypt(k,buffer.data(), buffer.size());
    }

    inline std::shared_ptr<CryptoPP::RSA::PrivateKey> random_rsa_key(const size_t keysize = 1024) {
        static auto rand {CryptoPP::RDRAND()};;
        auto pkey {std::make_shared<CryptoPP::RSA::PrivateKey>()};
        pkey->GenerateRandomWithKeySize(rand, keysize);
        return pkey;
    }

    inline std::shared_ptr<bytes> sha256(const bytes &data) {
        return sha256(data.data(), data.size());
    }


    class Cipher
    {
    public:
        virtual std::shared_ptr<std::vector<uint8_t>>
            encrypt(const std::vector<uint8_t> &blocks, size_t prepend = 0) = 0;
        virtual std::shared_ptr<std::vector<uint8_t>>
            decrypt(const std::vector<uint8_t> &blocks, size_t len = 0, size_t offset = 0) = 0;
    protected:
        Cipher() {};
    };

    class AESCipher : public Cipher
    {
    private:
        std::vector<uint8_t> m_key;
        CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption m_enc;
        CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption m_dec;

    public:
        const static size_t BLOCK_SIZE = 16;
        const size_t m_keysize;

        AESCipher(const std::vector<uint8_t> &key, const size_t key_size = 16);
        AESCipher(const uint8_t *key, const size_t bytes, const size_t key_size = 16);
        AESCipher(const CryptoPP::Integer &key, const size_t key_size = 16);

        std::shared_ptr<std::vector<uint8_t>>
            encrypt(const std::vector<uint8_t> &plain, size_t prepend);

        std::shared_ptr<std::vector<uint8_t>>
            decrypt(const std::vector<uint8_t> &blocks, size_t len_bytes, size_t offset = 0);

    };

}

#endif
