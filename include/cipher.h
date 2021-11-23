#ifndef DINT_CIPHER_H
#define DINT_CIPHER_H

#include <vector>
#include <memory>
#include <cstring>
#include <cassert>

#include <cryptopp/modes.h>
#include <cryptopp/aes.h>

#define ROUND_BLOCK(n,block) ((n) + ((block) - ((n) % (block))) % (block))

namespace dint
{
    typedef CryptoPP::byte byte;

    class Cipher
    {
        public:
            virtual std::shared_ptr<std::vector<char>>
                encrypt(const std::vector<char> &blocks);
            virtual std::shared_ptr<std::vector<char>>
                decrypt(const std::vector<char> &blocks, size_t len, size_t offset);
        protected:
            Cipher();

    };

    class AESCipher : public Cipher
    {
    private:
        const std::vector<char> m_key;
        CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption m_enc;
        CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption m_dec;

    public:
        size_t BLOCK_SIZE = 16;

        AESCipher(const std::vector<char> &key, const size_t key_size)
            : m_key (key.cbegin(), key.cbegin()+key_size),
             m_enc(), m_dec()
        {
            m_enc.SetKey((const byte*)m_key.data(), m_key.size());
            m_dec.SetKey((const byte*)m_key.data(), m_key.size());
        }

        std::shared_ptr<std::vector<char>>
            encrypt(const std::vector<char> &plain)
            {
                const size_t N = plain.size();
                size_t n = ROUND_BLOCK(n, BLOCK_SIZE);

                std::vector<char> plain_cpy (0);
                const std::vector<char> *blocks  = &plain;
                if (N < n)
                {
                    // resize to plain to multiple of block size
                    plain_cpy.resize(n);
                    memcpy(plain_cpy.data(), plain.data(), N);
                    blocks = &plain_cpy;
                }

                // create buffer to store ciphered bytes
                auto enc_blocks { std::make_shared<std::vector<char>>(n) };
                enc_blocks->resize(n);
                memcpy(enc_blocks->data(), blocks->data(), N);

                m_enc.ProcessData((byte*)enc_blocks->data(), (byte*)blocks->data(), n);

                // return encrypted block
                return enc_blocks;
            }


        std::shared_ptr<std::vector<char>>
            decrypt(const std::vector<char> &blocks, size_t offset=0, size_t len_bytes=2)
            {
                // assume block size is multiple of block size
                assert ((blocks.size() % BLOCK_SIZE) == 0);
                const size_t n = blocks.size();

                // create buffer to store ciphered bytes
                auto dec_blocks { std::make_shared<std::vector<char>>(n) };
                dec_blocks->resize(n);

                m_dec.ProcessData((byte*)dec_blocks->data(), (byte*)blocks.data(), n);

                // trim off padding
                size_t N = 0;
                switch (len_bytes)
                {
                    case 1:
                        N = (size_t) (*dec_blocks)[offset];
                        break;
                    case 2:
                        N = *((uint16_t*)dec_blocks->data()+offset);
                        break;
                    default:
                        N = *((uint32_t*)dec_blocks->data()+offset);
                }

                if (offset + N < n)
                {
                    dec_blocks->resize(N + offset);
                }

                return dec_blocks;
            }

    };

}

#endif
