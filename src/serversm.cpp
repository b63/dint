#include <cassert>
#include <vector>
#include <stdexcept>
#include <cstring>
#include <array>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cryptopp/modes.h>
#include <cryptopp/rdrand.h>
#include <cryptopp/integer.h>
#include <cryptopp/nbtheory.h>

#include <logger.h>
#include "serversm.h"
#include "util.h"
#include "cipher.h"
#include "exceptions.h"


using namespace dint;

// DH MODP groups from RFC3526
constexpr std::array<const char*, 2> DH_PARAMS_G {"2", "2"};
constexpr std::array<const char*, 2> DH_PARAMS_P {
    // g = 2, p =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\
    29024E088A67CC74020BBEA63B139B22514A08798E3404DD\
    EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\
    E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
    EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D\
    C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F\
    83655D23DCA3AD961C62F356208552BB9ED529077096966D\
    670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFFh",
    // g = 2, p =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\
    29024E088A67CC74020BBEA63B139B22514A08798E3404DD\
    EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\
    E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
    EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D\
    C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F\
    83655D23DCA3AD961C62F356208552BB9ED529077096966D\
    670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
    E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9\
    DE2BCBF6955817183995497CEA956AE515D2261898FA0510\
    15728E5A8AACAA68FFFFFFFFFFFFFFFFh"
};

std::shared_ptr<std::vector<ciphersuite_t>>
get_cipher_suites(const bytes &record, const header_t &header);


ServerSM::ServerSM()
    : m_state (smstate_t::CLOSED),
    m_ec {nullptr},
    m_rsa_priv {random_rsa_key()},
    m_rsa_pub {nullptr},
    m_send_block {nullptr},
    m_recv_block {nullptr}
{
    // TODO: use a fixed RSA key instead of generating random every tiem
    LOGF("server's RSA key: n = %s\n", CryptoPP::IntToString<CryptoPP::Integer>
            (m_rsa_priv->GetModulus(), 10).c_str());
    LOGF("server's RSA key: e = %s\n", CryptoPP::IntToString<CryptoPP::Integer>
            (m_rsa_priv->GetPublicExponent(), 10).c_str());
}

void ServerSM::start_protocol()
{
    m_state = smstate_t::WAIT_YO;
    m_cstate.clear();
}


std::shared_ptr<bytes> ServerSM::close()
{
    if (m_state != smstate_t::CLOSED)
    {
        m_state = smstate_t::CLOSED;
        return create_header(msg_t::CLOSING, 0);
    }

    return nullptr;
}

std::shared_ptr<const bytes> ServerSM::get_payload()
{
    if (m_state == smstate_t::SEND_YO)
    {
        if (m_enc_cparams == nullptr) {
            throw InvalidState("keys-exchange parameters have not been generated");
        }

        const CryptoPP::Integer &rsa_n {m_rsa_priv->GetModulus()};
        const CryptoPP::Integer &rsa_e {m_rsa_priv->GetPublicExponent()};
        const size_t min_n = rsa_n.MinEncodedSize();
        const size_t min_e = rsa_e.MinEncodedSize();

        // check that n and e both fit
        assert(min_n < ~(static_cast<size_t>(-1) << (8*MSG::YO::RSA_KEY::LENGTH)));
        assert(min_e < ~(static_cast<size_t>(-1) << (8*MSG::YO::RSA_KEY::LENGTH)));

        size_t rsa_keys_size = min_n + min_e + MSG::YO::RSA_KEY::LENGTH*2;
        size_t max_size = m_enc_cparams->size() + rsa_keys_size + MSG::YO::FIELD;

        // contents will be encrypted
        bytes contents;
        contents.reserve(max_size);
        // insert the key-exchange parameters
        contents.insert(contents.end(), m_enc_cparams->begin(), m_enc_cparams->end());

        // create field header
        add_record_field<MSG::YO::RSA_KEY::LENGTH>(contents, yo_field_t::SERVER_CERT, rsa_keys_size);
        size_t offset = contents.size();
        // insert the modulus
        offset = write_integer(contents, offset, rsa_n, MSG::YO::RSA_KEY::LENGTH);
        // insert the public exponent
        offset = write_integer(contents, offset, rsa_e, MSG::YO::RSA_KEY::LENGTH);

        // ecrypt using clients public key
        auto contents_enc {rsa_encrypt(*m_rsa_pub, contents)};

        // create header
        std::shared_ptr<bytes> block {create_header(msg_t::YO, contents_enc->size())};
        block->insert(block->end(), contents_enc->begin(), contents_enc->end());

        // save a copy for vertification step later
        const size_t n = block->size();
        m_send_block = std::make_shared<bytes>();
        m_send_block->reserve(n);
        m_send_block->insert(m_send_block->end(), block->begin(), block->end());

        m_state = smstate_t::RECV_YO;
        return block;
    }
    else if (m_state == smstate_t::SEND_VERIFICATION)
    {
        auto v_ptr {m_ec->encrypt(*sha256(*m_recv_block), VERIFY_LENGTH_BYTES)};

        auto payload {create_header(msg_t::VERIFICATION, v_ptr->size())};
        payload->insert(payload->end(), v_ptr->begin(), v_ptr->end());

        m_recv_block = nullptr;
        m_state = smstate_t::OPEN;
        return payload;
    }
    else if (m_state == smstate_t::SEND_ALERT_NO_CIPHER)
    {
        auto payload {create_header(msg_t::NO_CIPHER, 2)};
        payload->push_back(1);
        payload->push_back(static_cast<uint8_t>(ciphersuite_t::MODPDH_WITH_AES_128_SHA_256));

        m_state = smstate_t::CLOSED;
        return payload;
    }

    throw InvalidState("invalid call to get_payload");
}


std::shared_ptr<bytes>
    ServerSM::encode_payload(const bytes &data)
{
    if (m_state != smstate_t::OPEN)
        throw InvalidState("sate needs to OPEN to encode payloads");

    auto blocks = m_ec->encrypt(data, MSG::PAYLOAD::LENGTH);
    auto message = create_header(msg_t::PAYLOAD, blocks->size());
    message->insert(message->end(), blocks->begin(), blocks->end());

    return message;
}


std::shared_ptr<bytes>
    ServerSM::decode_payload(const bytes &data,
            std::shared_ptr<const header_t> header)
{
    if (m_state != smstate_t::OPEN)
        throw InvalidState("state needs to be OPEN to decode payloads");

    auto blocks = m_ec->decrypt(data, MSG::PAYLOAD::LENGTH);
    return blocks;
}

int ServerSM::process_record(const bytes &record,
        std::shared_ptr<const header_t> header)
{
    // read in the header fields if not given
    if (!header) {
        header = parse_header(record);
    }

    // check for version compatibility
    if (!COMPATIBLE_VERSION(header->version))
    {
        throw VersionMismatch(header->version, DINT_VERSION);
    }

    if (header->type == msg_t::CLOSING)
    {
        // bail
        // TODO: add some cleanup if needed
        m_state = smstate_t::CLOSED;
        return 1;
    }


    switch (m_state)
    {
        case smstate_t::WAIT_YO:
            if (header->type == msg_t::YO)
            {
                process_client_yo_record(record, *header);
                if (m_state == smstate_t::SEND_ALERT_NO_CIPHER)
                    break;

                m_state = smstate_t::SEND_YO;

                // make a copy of received data for verification step
                m_recv_block = std::make_shared<bytes>();
                m_recv_block->reserve(record.size());
                m_recv_block->insert(m_recv_block->end(), record.begin(), record.end());
            }
            else
            {
                throw InvalidState("expected record with YO message");
            }
            break;

        case smstate_t::RECV_YO:
            if (header->type == msg_t::YO)
            {
                process_client_cipher_params(record, *header);
                m_state = smstate_t::RECV_VERIFICATION;

                // extend the copy of received data for verification step
                m_recv_block->insert(m_recv_block->end(), record.begin(), record.end());
            }
            else
            {
                throw InvalidState("expected record with YO message containing cipher params");
            }
            break;


            break;

        case smstate_t::SEND_VERIFICATION:
            throw InvalidState("not expecting to process record in SEND_VERIFICATION state");
            break;

        case smstate_t::RECV_VERIFICATION:
            if (header->type == msg_t::VERIFICATION)
            {
                process_client_verification(record, *header);
                m_send_block = nullptr;
                m_state = smstate_t::SEND_VERIFICATION;
            }
            break;
        case smstate_t::OPEN:
            break;

        default:
            throw InvalidState("unexpected state");
    }

    // state is not closed
    return 0;
}


void ServerSM::process_client_verification(const bytes &record,
        const header_t &header)
{
    try {
        size_t offset = header.offset;

        bytes record_data (record.cbegin()+offset, record.end());
        auto dec {m_ec->decrypt(record_data, MSG::VERIFY::LENGTH, 0)};

        std::shared_ptr<bytes> sha_sendblock {sha256(*m_send_block)};

        const size_t n = dec->size();
        if (n != sha_sendblock->size())
            throw VerificationFailed("length of sent and recieved blocks differ");

        if (memcmp(sha_sendblock->data(), dec->data(), n))
            throw VerificationFailed("sent and received blocks differ");
    } catch (std::out_of_range &e) {
        throw IncompleteRecord("record smaller than expected");
    }

}

void ServerSM::process_client_cipher_params(const bytes &enc_record,
        const header_t &header)
{
    using namespace CryptoPP;

    if (m_cstate.size() == 0) {
        throw InvalidState("cipher keys not generated");
    }

    // one byte to encode how many ciper suites are given
    assert(YO_MSG_CS_LENGHT_BYTES == 1);
    try {
        auto dec_record {rsa_decrypt(*m_rsa_priv, enc_record.data()+header.offset, header.length)};
        // TODO: change when other cipher suites are implmeneted
        assert(m_cipher == ciphersuite_t::MODPDH_WITH_AES_128_SHA_256);

        assert(MSG::YO::FIELD == 1);

        size_t n = 0;
        yo_field_t field_type = static_cast<yo_field_t>(dec_record->at(n));
        n += MSG::YO::FIELD;

        if (field_type == yo_field_t::CIPHER_KEY_PARAMS)
        {
            // the field only contains the public key
            const size_t pklen = read_int(*dec_record, n, MSG::YO::CKP::LENGTH);
            n += MSG::YO::CKP::LENGTH;
            // check if key key can be read
            if (pklen + n > dec_record->size())
                throw IncompleteRecord("record not large enough for key");

            // generate the shared key using public key from client
            Integer pub_key ((byte*) (dec_record->data() + n), pklen);
            Integer shared_key {a_exp_b_mod_c(pub_key, m_cstate.at(2), m_cstate.at(0))};

            // create cipher using shared key
            m_ec = std::shared_ptr<Cipher>(new AESCipher(shared_key, 16));
            // save shared key -- don't
            m_cstate.clear();
        } else {
            throw InvalidRecord("expected cipher key params field at this point in record");
        }
    } catch (std::out_of_range &e) {
        throw IncompleteRecord("record smaller than expected");
    }
}

void ServerSM::process_client_yo_record(const bytes &record,
        const header_t &header)
{
    // one byte to encode how many ciper suites are given
    assert(YO_MSG_CS_LENGHT_BYTES == 1);
    try {
        size_t n = header.offset;
        yo_field_t field_type = static_cast<yo_field_t>(record.at(n));
        if (field_type == yo_field_t::CIPHER_SUITES)
        {
            size_t len = record.at(n+1);
            n += 2;
            // check for any supported cipher suites
            int found = -1;
            for (size_t i = 0; i < len; ++i)
            {
                if (record.at(n+i) == static_cast<uint8_t>(ciphersuite_t::MODPDH_WITH_AES_128_SHA_256))
                {
                    found = record.at(n+i);
                    break;
                }
            }
            n += len;

            if (found < 0) {
                m_state = smstate_t::SEND_ALERT_NO_CIPHER;
                return;
            }

            // generate the params for the selected cipher suite
            m_cipher = static_cast<ciphersuite_t>(found);
            generate_cipher_keys();
        } else {
            throw InvalidRecord("expected cipher suite field at this point in record");
        }

        // read in client rsa public key
        if (static_cast<yo_field_t>(record.at(n++)) != yo_field_t::CLIENT_CERT)
            throw InvalidRecord("expected client public key at this point in record");

        // get size of CLIENT_CERT field
        const size_t pkblock = read_int(record, n, MSG::YO::RSA_KEY::LENGTH);
        n += MSG::YO::RSA_KEY::LENGTH;
        if (n + pkblock > record.size())
            throw IncompleteRecord("not enough bytes for full rsa key");

        // read in modulo base n
        size_t len = read_int(record, n, MSG::YO::RSA_KEY::LENGTH);
        n += MSG::YO::RSA_KEY::LENGTH;
        if (n + len > record.size()) throw IncompleteRecord("not enough bytes for n");

        CryptoPP::Integer rsa_n ((byte*)record.data()+n, len);
        LOGF("clients's RSA public key: n = %s\n", CryptoPP::IntToString<CryptoPP::Integer>(rsa_n, 10).c_str());
        n += len;

        // read in the exponent e
        len = read_int(record, n, MSG::YO::RSA_KEY::LENGTH);
        n += MSG::YO::RSA_KEY::LENGTH;
        if (n + len > record.size()) throw IncompleteRecord("not enough bytes for e");

        CryptoPP::Integer rsa_e ((byte*)record.data()+n, len);
        LOGF("clients's RSA public key: e = %s\n", CryptoPP::IntToString<CryptoPP::Integer>(rsa_e, 10).c_str());
        n += len;

        // initialize client's RSA public key
        m_rsa_pub = std::make_shared<CryptoPP::RSA::PublicKey>();
        m_rsa_pub->Initialize(rsa_n, rsa_e);

        m_state = smstate_t::SEND_YO;
    } catch (std::out_of_range &e) {
        throw IncompleteRecord("record smaller than expected");
    }
}


void ServerSM::generate_cipher_keys()
{
    using namespace CryptoPP;

    if (m_cipher == ciphersuite_t::MODPDH_WITH_AES_128_SHA_256)
    {
        // Diffie-Hellman over Zp
        auto rdrand {RDRAND()};
        size_t rand_i {rand() % DH_PARAMS_G.size()};
        Integer g (DH_PARAMS_G[rand_i]);
        Integer p (DH_PARAMS_P[rand_i]);
        if (!CryptoPP::IsPrime(p))
        {
            LOGERR("param at index %i is not prime\n", rand_i);
            std::string pstr {IntToString<Integer>(p, 10)};
            LOGERR("%s\n", pstr.c_str());
            throw Exception("unable to choose DH group/prime");
        }

        /* RFC3526: if you use a group whose strength is 128 bits, you must use more than 256 bits of
         * randomness in the exponent used in the Diffie-Hellman calculation. */
        Integer b (rdrand, 2*p.BitCount());

        Integer pub_key {a_exp_b_mod_c(g, b, p)};

        const size_t gn  = g.MinEncodedSize();
        const size_t pn  = p.MinEncodedSize();
        const size_t bn  = b.MinEncodedSize();
        const size_t pkn = pub_key.MinEncodedSize();

        const size_t n = MSG::YO::CKP::TYPE
                      + (MSG::YO::CKP::DHMODP::G  + gn) 
                      + (MSG::YO::CKP::DHMODP::P  + pn) 
                      + (MSG::YO::CKP::DHMODP::PK + pkn);

        size_t i = 0;
        m_enc_cparams = create_record_field<MSG::YO::CKP::LENGTH>(yo_field_t::CIPHER_KEY_PARAMS, n);
        // add type of cipher suite for which parameters follow
        assert(MSG::YO::CKP::TYPE == 1);
        *m_enc_cparams << static_cast<uint8_t>(ciphersuite_t::MODPDH_WITH_AES_128_SHA_256);

        // group order
        assert(MSG::YO::CKP::DHMODP::G == 1);
        *m_enc_cparams << static_cast<uint8_t>(gn);
        m_enc_cparams->resize((i = m_enc_cparams->size()) + gn);
        g.Encode((byte*)(m_enc_cparams->data()+i), gn);

        // prime
        assert(MSG::YO::CKP::DHMODP::P == 2);
        *m_enc_cparams << static_cast<uint16_t>(pn);
        m_enc_cparams->resize((i = m_enc_cparams->size()) + pn);
        p.Encode((byte*)(m_enc_cparams->data()+i), pn);

        // public key
        assert(MSG::YO::CKP::DHMODP::PK == 2);
        *m_enc_cparams << static_cast<uint16_t>(pkn);
        m_enc_cparams->resize((i = m_enc_cparams->size()) + pkn);
        pub_key.Encode((byte*)(m_enc_cparams->data()+i), pkn);

        // store params as Integers for later use
        m_cstate.clear();
        m_cstate.reserve(4);
        m_cstate.push_back(p);
        m_cstate.push_back(g);
        m_cstate.push_back(b);
    }
    else
    {
        assert("other cipher suites not currently implemented.");
    }
}
