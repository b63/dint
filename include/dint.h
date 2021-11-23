#ifndef DINT_H
#define DINT_H

#define DINT_VERSION_MAJOR 0x36
#define DINT_VERSION_MINOR 0x39
#define DINT_VERSION  (((DINT_VERSION_MAJOR & 0xff) << 8) | (DINT_VERSION_MINOR & 0xff))
#define SAME_VERSION(version) ((version) == DINT_VERSION)
#define COMPATIBLE_VERSION(version)  ((version >> 8) == DINT_VERSION_MAJOR)

#define VERSION_BYTES  2
#define MSG_TYPE_BYTES 2
#define CIPHER_SUITE_BYTES 2
#define CIPHER_SUITE_LENGHT_BYTES 1
#define YO_RECORD_FIELD_BYTES 1

#include <memory>
#include <vector>
#include <string>

#include <cryptopp/integer.h>

namespace dint {
    enum struct smstate_t {
        OPEN = 0,
        SEND_YO,
        RECV_YO,
        SEND_VERIFICATION,
        RECV_VERIFICATION,
        CLOSED,
    };

    enum struct msg_t : uint16_t {
        YO = 0,
        VERIFICATION,
        PAYLOAD,
        CLOSING,
        NO_CIPHER,
    };

    enum struct ciphersuite_t : uint16_t {
        DH_WITH_AES_128_HMAC_SHA_256 = 0xaa,
        ECDH_WITH_AES_128_HMAC_SHA_256 = 0xab,
    };

    enum struct yo_record_t : uint8_t {
        SELECTED_CIPHER_SUITE = 0x1,
        SERVER_CERT = 0x10,
        CLIENT_CERT = 0x1a,
        CIPHER_SUITES = 0x1b,
        CIPHER_KEYS = 0x1d
    };

    struct header_t {
        explicit header_t(){}
        header_t(const msg_t &type, uint16_t version, size_t offset, size_t length)
            : type(type), version(version), offset(offset), length(length){}

        // type of the message contained in the record
        msg_t type;
        // version given in the record
        uint16_t version;
        // offset in bytes from start of record to actual payload for 
        // the given header type
        size_t offset;
        // length of the payload
        size_t length; 
    };

    struct dhe_params_t {
        std::shared_ptr<std::vector<char>> g;
        std::shared_ptr<std::vector<char>> p;
        std::shared_ptr<std::vector<char>> pub_key;
    };

    struct dhe_state_t {
        CryptoPP::Integer p;
        CryptoPP::Integer g;
        CryptoPP::Integer priv_key;
        CryptoPP::Integer shared_key;
    };



    std::shared_ptr<header_t> read_header(const std::vector<char> &buffer);
}

#endif
