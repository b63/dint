#ifndef DINT_H
#define DINT_H

#define DINT_VERSION_MAJOR 0x4
#define DINT_VERSION_MINOR 0x2
#define DINT_VERSION  (((DINT_VERSION_MAJOR & 0xf) << 4) | (DINT_VERSION_MINOR & 0xf))
#define SAME_VERSION(version) ((version) == DINT_VERSION)
#define COMPATIBLE_VERSION(version)  ((version >> 4) == DINT_VERSION_MAJOR)


#include <memory>
#include <vector>
#include <cstdint>
#include <cassert>
#include <string>

#include <cryptopp/integer.h>

// number of bytes to use for version
#define VERSION_BYTES  1
// number of bytes to use to indicate message type
#define MSG_TYPE_BYTES 1
// number of bytes to indicate cipher-suite
#define CIPHER_SUITE_BYTES 1
// number of bytes to store size of cipher suite list
#define YO_MSG_CS_LENGHT_BYTES 1
// number of bytes for field type in YO records
#define YO_MSG_FIELD_BYTES 1
// number of bytes for total length of message (after header)
#define MSG_LENGTH_BYTES 2
// number of bytes for verification block size
#define VERIFY_LENGTH_BYTES 3
// minimum number of bytes for the header
#define MIN_HEADER_LENGTH (VERSION_BYTES + MSG_TYPE_BYTES + MSG_LENGTH_BYTES)
// number of bytes for length of PAYLOAD message 
#define PAYLOAD_LENGTH_BYTES 4
// number of types till the mesasge type in header
#define MSG_TYPE_OFFSET 2

namespace dint {
    // constants for various offets/lengths
    using bytes     = std::vector<uint8_t>;
    using bytes_ptr = std::shared_ptr<std::vector<uint8_t>>;

    namespace MSG {
        constexpr size_t TYPE_OFFSET = 1;
        constexpr size_t TYPE_BYTES = 1;
        namespace YO {
            constexpr size_t LENGTH = 4;
            constexpr size_t FIELD  = 1;

            // listing cipher suites
            namespace CSUITES {
                // number of bytes for each cipher suite (integral type for ciphersuite_t)
                constexpr size_t SUITE = 1;
                // bytes for length of list
                constexpr size_t LIST  = 1;
            }

            // ciper key params (key-exchange parameters)
            namespace CKP {
                constexpr size_t LENGTH = 4;
                constexpr size_t TYPE = 1;

                // cipher key params for DH over group Zp
                namespace DHMODP {
                    constexpr size_t P = 2;
                    constexpr size_t G = 1;
                    constexpr size_t PK = 2;
                }
            }
            // rsa public keys
            namespace RSA_KEY {
                constexpr size_t LENGTH = 4;
            }
        }

        namespace VERIFY {
            constexpr size_t LENGTH = 3;
        }

        namespace CLOSING {
            constexpr size_t LENGTH = 2;
        }

        namespace PAYLOAD {
            constexpr size_t LENGTH = 4;
        }

        namespace NO_CIPHER {
            constexpr size_t LENGTH = 2;
        }
    }

    enum struct smstate_t {
        OPEN = 0,
        SEND_YO,
        WAIT_YO,
        RECV_YO,
        SEND_VERIFICATION,
        RECV_VERIFICATION,
        SEND_ALERT_NO_CIPHER,
        CLOSED,
    };

    enum struct msg_t : uint8_t {
        YO = 0,
        VERIFICATION,
        PAYLOAD,
        CLOSING,
        NO_CIPHER,
    };

    enum struct ciphersuite_t : uint8_t {
        MODPDH_WITH_AES_128_SHA_256 = 0xaa,
        ECDH_WITH_AES_128_SHA_256 = 0xab,
    };

    enum struct yo_field_t : uint8_t {
        CIPHER_KEY_PARAMS = 0x1,
        SERVER_CERT = 0x10,
        CLIENT_CERT = 0x1a,
        CIPHER_SUITES = 0x1b
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
        std::shared_ptr<std::vector<uint8_t>> g;
        std::shared_ptr<std::vector<uint8_t>> p;
        std::shared_ptr<std::vector<uint8_t>> pub_key;
    };

    struct dhe_state_t {
        CryptoPP::Integer p;
        CryptoPP::Integer g;
        CryptoPP::Integer priv_key;
        CryptoPP::Integer shared_key;
    };
}

#endif
