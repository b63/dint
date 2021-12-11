#include <cstdio>
#include <sstream>
#include <iostream>
#include <memory>
#include <cmath>

#include <cryptopp/modes.h>
#include <cryptopp/rdrand.h>
#include <cryptopp/integer.h>
#include <cryptopp/rsa.h>
#include <cryptopp/nbtheory.h>

#include <logger.h>
#include "util.h"

using namespace CryptoPP;

std::shared_ptr<std::vector<uint8_t>>
rsa_encrypt(const RSAES_OAEP_SHA_Encryptor &ec, const std::vector<uint8_t> &data)
{
    auto rdrand {RDRAND()};

    const size_t max_size = ec.FixedMaxPlaintextLength();
    const size_t maxc_size = ec.FixedCiphertextLength();
    const size_t dsize = data.size();
    assert (0 != max_size);

    size_t offset = 0;

    auto cipher {std::make_shared<std::vector<uint8_t>>()};
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

    LOG("cipher text\n");
    LOGBUF(*cipher, 80, true);

    return cipher;
}


std::shared_ptr<std::vector<uint8_t>>
rsa_decrypt(const RSAES_OAEP_SHA_Decryptor &dc, const std::vector<uint8_t> &cipher)
{
    auto rdrand {RDRAND()};

    const size_t max_size = dc.FixedMaxPlaintextLength();
    const size_t maxc_size = dc.FixedCiphertextLength();
    const size_t csize = cipher.size();
    assert (0 != max_size);

    size_t offset = 0;
    size_t poffset = 0;

    auto plaintext {std::make_shared<std::vector<uint8_t>>()};
    plaintext->reserve(max_size * ceil(csize / (double)maxc_size));

    while (offset < csize)
    {
        const size_t len = (csize - offset < maxc_size ? csize - offset : maxc_size);
        const size_t epl = dc.MaxPlaintextLength(len);

        if (plaintext->size() < poffset + epl)
            plaintext->resize(poffset + epl);

        DecodingResult result = dc.Decrypt(rdrand, (byte*)cipher.data()+offset, len, (byte*)plaintext->data()+poffset);
        assert(result.isValidCoding);
        assert(result.messageLength <= epl);

        offset += len;
        poffset += result.messageLength;
    }
    plaintext->resize(poffset);

    LOG("plain text\n");
    LOGBUF(*plaintext, -1, false);

    return plaintext;
}

int main(int argc, char **argv)
{

    start_logger(stdout);
    buf_print_enable(true);

    auto rdrand {RDRAND()};

    RSA::PrivateKey priv_key;
    priv_key.GenerateRandomWithKeySize(rdrand, 4096);
    RSA::PublicKey pub_key (priv_key);

    // print generate parameter
    LOG("n = %s\n", IntToString<Integer>(priv_key.GetModulus(), 10).c_str());
    LOG("p = %s\n", IntToString<Integer>(priv_key.GetPrime1(), 10).c_str());
    LOG("q = %s\n", IntToString<Integer>(priv_key.GetPrime2(), 10).c_str());
    LOG("d = %s\n", IntToString<Integer>(priv_key.GetPrivateExponent(), 10).c_str());
    LOG("e = %s\n", IntToString<Integer>(priv_key.GetPublicExponent(), 10).c_str());

    // encryptors/decryptors
    RSAES_OAEP_SHA_Encryptor enc_pub  (pub_key);
    RSAES_OAEP_SHA_Decryptor dec_priv (priv_key);

    std::string text;
    std::cout << "Plain text:  ";
    std::getline(std::cin, text);

    std::vector<uint8_t> plaintext (text.begin(), text.end());

    LOGBUF(plaintext, -1, true );

    LOG("encrypt with public key, decrypt with private key\n");
    auto r_cipher = rsa_encrypt(enc_pub, plaintext);
    auto r_plain  = rsa_decrypt(dec_priv, *r_cipher);

    return 0;
}



