#include <cassert>
#include <vector>
#include <stdexcept>
#include <cstring>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cryptopp/rdrand.h>
#include <cryptopp/integer.h>
#include <cryptopp/nbtheory.h>

#include <logger.h>
#include "clientsm.h"
#include "cipher.h"
#include "util.h"
#include "exceptions.h"

using namespace dint;

std::shared_ptr<std::vector<ciphersuite_t>>
get_cipher_suites(const bytes &record, const header_t &header);


ClientSM::ClientSM(bool require_certificate)
    : m_state (smstate_t::CLOSED) , 
    m_cert (require_certificate),
    m_ec {nullptr},
    m_rsa_priv {random_rsa_key()},
    m_rsa_pub {nullptr},
    m_send_block {nullptr},
    m_recv_block {nullptr}
{
    // TODO: use a fixed RSA key instead of generating random every tiem
}


void ClientSM::start_protocol()
{
    // create initial message to send to server
    assert(MSG::YO::CSUITES::LIST  == 1);
    assert(MSG::YO::CSUITES::SUITE == 1);
    auto suites = create_record_field<0>(yo_field_t::CIPHER_SUITES, 
            MSG::YO::CSUITES::LIST + MSG::YO::CSUITES::SUITE * 1);
    // add length of list
    push_int(*suites, MSG::YO::CSUITES::LIST, 1);
    // add cipher suites -- just one for now
    push_int(*suites, MSG::YO::CSUITES::SUITE, static_cast<uint8_t>(ciphersuite_t::MODPDH_WITH_AES_128_SHA_256));

    // add client's rsa public key
    const CryptoPP::Integer &rsa_n {m_rsa_priv->GetModulus()};
    const CryptoPP::Integer &rsa_e {m_rsa_priv->GetPublicExponent()};
    const size_t min_n = rsa_n.MinEncodedSize();
    const size_t min_e = rsa_e.MinEncodedSize();

    // check that n and e both fit
    assert(min_n < ~(static_cast<size_t>(-1) << (8*MSG::YO::RSA_KEY::LENGTH)));
    assert(min_e < ~(static_cast<size_t>(-1) << (8*MSG::YO::RSA_KEY::LENGTH)));

    size_t rsa_keys_size = min_n + min_e + MSG::YO::RSA_KEY::LENGTH*2;
    // contents will be encrypted
    auto pub_key {create_record_field<MSG::YO::RSA_KEY::LENGTH>(yo_field_t::CLIENT_CERT, rsa_keys_size)};

    {
        size_t offset = pub_key->size();
        pub_key->resize(rsa_keys_size + offset);

        // insert the modulus
        offset = write_integer(*pub_key, offset, rsa_n, MSG::YO::RSA_KEY::LENGTH);
        // insert public exponent
        offset = write_integer(*pub_key, offset, rsa_e, MSG::YO::RSA_KEY::LENGTH);

        LOGF("client's RSA key: n = %s\n", CryptoPP::IntToString<CryptoPP::Integer>
                (rsa_n, 10).c_str());
        LOGF("client's RSA key: e = %s\n", CryptoPP::IntToString<CryptoPP::Integer>
                (rsa_e, 10).c_str());
    }

    // combine two fields to create full message
    m_send_block = create_header(msg_t::YO, suites->size() + pub_key->size());
    m_send_block->insert(m_send_block->end(), suites->begin(), suites->end());
    m_send_block->insert(m_send_block->end(), pub_key->begin(), pub_key->end());

    m_state = smstate_t::SEND_YO;
}


std::shared_ptr<bytes> ClientSM::close()
{
    if (m_state != smstate_t::CLOSED)
    {
        m_state = smstate_t::CLOSED;
        return create_header(msg_t::CLOSING, 0);
    }

    return nullptr;
}

std::shared_ptr<const bytes> ClientSM::get_payload()
{
    if (m_state == smstate_t::SEND_YO)
    {
        m_state = smstate_t::RECV_YO;
        return m_send_block;
    }
    else if (m_state == smstate_t::SEND_VERIFICATION)
    {
        if (/*m_cstate.size() == 0 ||*/ m_enc_cparams == nullptr) {
            throw InvalidState("key-exchange parameters have not been generated");
        }

        if (m_rsa_pub == nullptr)
            throw InvalidState("server's rsa public key not available");

        // compute SHA256 digest of handshake, encrypted using AES cipher
        std::shared_ptr<bytes> v_ptr {m_ec->encrypt(*sha256(*m_recv_block), MSG::VERIFY::LENGTH)};
        m_recv_block = nullptr;

        // YO record containing client's public key (encrypted with server's rsa public key)
        auto yo_cipher_msg {create_header(msg_t::YO, m_enc_cparams->size())};
        yo_cipher_msg->insert(yo_cipher_msg->end(), m_enc_cparams->begin(), m_enc_cparams->end());
        // add yo-record to m_send_block for later verification
        m_send_block->insert(m_send_block->end(), yo_cipher_msg->begin(), yo_cipher_msg->end());

        // veirfy record containing hash of data received by client
        auto verify_msg {create_header(msg_t::VERIFICATION, v_ptr->size())};
        verify_msg->insert(verify_msg->end(), v_ptr->begin(), v_ptr->end());

        // combine two messages
        auto joined_msg {std::make_shared<bytes>()};
        joined_msg->reserve(yo_cipher_msg->size() + verify_msg->size());
        joined_msg->insert(joined_msg->begin(), yo_cipher_msg->begin(), yo_cipher_msg->end());
        joined_msg->insert(joined_msg->end(), verify_msg->begin(), verify_msg->end());

        m_state = smstate_t::RECV_VERIFICATION;
        return joined_msg;
    }
    else if (m_state == smstate_t::OPEN)
    {
        if (m_recv_block == nullptr) return nullptr;
        std::shared_ptr<bytes> t {m_recv_block};
        m_recv_block = nullptr;
        return t;
    }

    throw InvalidState("invalid call to get_payload");
}


std::shared_ptr<bytes>
    ClientSM::encode_payload(const bytes &data)
{
    if (m_state != smstate_t::OPEN)
        throw InvalidState("sate needs to OPEN to encode payloads");

    auto blocks = m_ec->encrypt(data, MSG::PAYLOAD::LENGTH);
    auto message = create_header(msg_t::PAYLOAD, blocks->size());
    message->insert(message->end(), blocks->begin(), blocks->end());

    return message;
}


std::shared_ptr<bytes>
    ClientSM::decode_payload(const bytes &data,
            std::shared_ptr<const header_t> header)
{
    if (m_state != smstate_t::OPEN)
        throw InvalidState("state needs to be OPEN to decode payloads");

    auto blocks = m_ec->decrypt(data, MSG::PAYLOAD::LENGTH);

    return blocks;
}


int ClientSM::process_record(const bytes &record,
        std::shared_ptr<const header_t> header)
{
    // read in the header fields if not given
    if (!header) {
        header = parse_header(record);
    }

    // check for version compatibility
    if (!COMPATIBLE_VERSION(header->version)) {
        throw VersionMismatch(header->version, DINT_VERSION);
    }

    if (header->type == msg_t::CLOSING) {
        // bail
        // TODO: add some cleanup if needed
        m_state = smstate_t::CLOSED;
        return 1;
    }


    switch (m_state)
    {
        case smstate_t::RECV_YO:
            if (header->type == msg_t::NO_CIPHER)
            {
                throw CipherSuiteMismatch(std::move(
                            *get_cipher_suites(record, *header)));
            }
            else if (header->type == msg_t::YO)
            {
                process_server_yo_record(record, *header);
                m_state = smstate_t::SEND_VERIFICATION;

                // make a copy of received data for verification step
                m_recv_block = std::make_shared<bytes>();
                m_recv_block->insert(m_recv_block->begin(), record.begin(), record.end());
            }
            else
            {
                throw InvalidState("expected record with YO message");
            }
            break;

        case smstate_t::SEND_VERIFICATION:
            throw InvalidState("not expecting to process record in SEND_VERIFICATION state");
            break;

        case smstate_t::RECV_VERIFICATION:
            if (header->type == msg_t::VERIFICATION)
            {
                process_server_verification(record, *header);
                m_send_block = nullptr;
                m_state = smstate_t::OPEN;
            }
            break;

        case smstate_t::OPEN:
            throw InvalidState("unexpected header type");
            break;

        default:
            throw InvalidState("unexpected state");
    }

    // state is not closed
    return 0;
}


void ClientSM::process_server_verification(const bytes &record,
        const header_t &header)
{
    try {
        size_t offset = header.offset;

        bytes record_data (record.cbegin()+offset, record.end());
        auto dec {m_ec->decrypt(record_data, MSG::VERIFY::LENGTH)};

        std::shared_ptr<bytes> sha_sendblock {sha256(*m_send_block)};

        const size_t n = dec->size();
        if (dec->size() != sha_sendblock->size())
            throw VerificationFailed("length of sent and recieved blocks differ");

        if (memcmp(sha_sendblock->data(), dec->data(), n))
            throw VerificationFailed("sent and received blocks differ");
    } catch (std::out_of_range &e) {
        throw IncompleteRecord("record smaller than expected");
    }

}

void ClientSM::process_server_yo_record(const bytes &enc_record,
        const header_t &header)
{

    try {
        // decrypt the record using  private key
        auto dec_record = rsa_decrypt(*m_rsa_priv, enc_record.data()+header.offset, header.length);

        size_t n = 0;
        assert(MSG::YO::FIELD == 1);
        yo_field_t field_type = static_cast<yo_field_t>(dec_record->at(n++));

        if (field_type != yo_field_t::CIPHER_KEY_PARAMS) {
            throw InvalidRecord("expected cipher suite field at this point in record");
        }

        const size_t cblock = read_int(*dec_record, n, MSG::YO::CKP::LENGTH);
        n += MSG::YO::CKP::LENGTH;

        if (n+cblock > dec_record->size())
            throw IncompleteRecord("record does not contain full key-exchange params");

        m_cipher = static_cast<ciphersuite_t>(dec_record->at(n));
        switch (m_cipher)
        {
            case ciphersuite_t::MODPDH_WITH_AES_128_SHA_256:
                process_dhe_params(*dec_record, n);
                break;

            default:
                assert("ciphersuite not yet implemented");
                break;
        }
        n += cblock;

        field_type = static_cast<yo_field_t>(dec_record->at(n++));
        if (field_type != yo_field_t::SERVER_CERT)
            throw InvalidRecord("expected server public key");

        // read server's rsa public key here

        const size_t pkblock = read_int(*dec_record, n, MSG::YO::RSA_KEY::LENGTH);
        n += MSG::YO::RSA_KEY::LENGTH;

        if (n + pkblock > dec_record->size())
            throw IncompleteRecord("record does not contain full rsa key");

        // read in the modulus
        size_t len = read_int(*dec_record, n, MSG::YO::RSA_KEY::LENGTH);
        n += MSG::YO::RSA_KEY::LENGTH;
        if (n + len > dec_record->size()) throw IncompleteRecord("not enough bytes for n");

        CryptoPP::Integer rsa_n {(byte*) dec_record->data()+n, len};
        LOGF("server's RSA public key: n = %s\n", CryptoPP::IntToString<CryptoPP::Integer>(rsa_n, 10).c_str());
        n += len;

        // read in the public exponent
        len = read_int(*dec_record, n, MSG::YO::RSA_KEY::LENGTH);
        n += MSG::YO::RSA_KEY::LENGTH;
        if (n + len > dec_record->size()) throw IncompleteRecord("not enough bytes for e");

        CryptoPP::Integer rsa_e {(byte*) dec_record->data()+n, len};
        LOGF("server's RSA public key: e = %s\n", CryptoPP::IntToString<CryptoPP::Integer>(rsa_e, 10).c_str());
        n += len;

        // initialize servers's RSA public key
        m_rsa_pub = std::make_shared<CryptoPP::RSA::PublicKey>();
        m_rsa_pub->Initialize(rsa_n, rsa_e);

        // all server cipher params parsed and received, now generate the
        // public/private key pair to send to sender
        generate_cipher_keys();
    } catch (std::out_of_range &e) {
        throw IncompleteRecord("record smaller than expected");
    }
}


void ClientSM::generate_cipher_keys()
{
    using namespace CryptoPP;
    if (m_cparams.size() == 0) {
        throw InvalidState("no cipher params");
    }

    if (m_rsa_pub == nullptr)
        throw InvalidState("server's rsa key not available");

    if (m_cipher == ciphersuite_t::MODPDH_WITH_AES_128_SHA_256)
    {
        auto rdrand {RDRAND()};
        Integer p ((byte*)m_cparams.at(0)->data(), m_cparams.at(0)->size());
        Integer g ((byte*)m_cparams.at(1)->data(), m_cparams.at(1)->size());

        if (!CryptoPP::IsPrime(p))
        {
            LOGERR("integer provided is not prime\n");
            std::string pstr {IntToString<Integer>(p, 10)};
            LOGERR("%s\n", pstr.c_str());
            throw Exception("invalid DH group/prime provided");
        }

        // Diffie-Hellman over Zp
        Integer b (rdrand, 2*p.BitCount());
        Integer srv_pub_key ((byte*)m_cparams.at(2)->data(), m_cparams.at(2)->size());
        m_cparams.clear(); // not needed

        Integer client_pub_key {a_exp_b_mod_c(g, b, p)};
        Integer shared_key {a_exp_b_mod_c(srv_pub_key, b, p)};

        //// use shared key to create block AES cipher
        m_ec = std::make_shared<AESCipher>(shared_key, 16);


        // send public key to server
        // get size of public key
        const size_t pkn = client_pub_key.MinEncodedSize();

        // create field header and length
        auto contents {create_record_field<MSG::YO::CKP::LENGTH>(yo_field_t::CIPHER_KEY_PARAMS, pkn)};
        size_t offset = contents->size();
        contents->resize(offset + pkn);
        // write key to buffer
        client_pub_key.Encode((byte*)contents->data()+offset, pkn);

        // encrypt key using server's rsa public key
        m_enc_cparams = rsa_encrypt(*m_rsa_pub, *contents);

        // store computed keys as Integers for later use
        //m_cstate.clear();
        //m_cstate.reserve(3);
        //m_cstate.push_back(p);
        //m_cstate.push_back(g);
        //m_cstate.push_back(priv_key);
    }
    else
    {
        assert("other cipher suites not currently implemented.");
    }
}


void ClientSM::process_dhe_params(const bytes &record, size_t offset)
{
    try {
        assert(record.at(offset++) == static_cast<uint8_t>(ciphersuite_t::MODPDH_WITH_AES_128_SHA_256));

        // read group order
        assert(MSG::YO::CKP::DHMODP::G == 1);
        size_t n (record.at(offset++));
        auto g {std::make_shared<bytes>(n)};
        memcpy(g->data(), record.data()+offset, n);
        offset += n;

        // read prime
        assert(MSG::YO::CKP::DHMODP::P == 2);
        n = INT16(record.at(offset), record.at(offset+1));
        auto p {std::make_shared<bytes>(n)};
        memcpy(p->data(), record.data()+offset+2, n);
        offset += n+2;

        // read the key
        assert(MSG::YO::CKP::DHMODP::PK == 2);
        n = INT16(record.at(offset), record.at(offset+1));
        offset += 2;
        auto pkey {std::make_shared<bytes>(n)};
        memcpy(pkey->data(), record.data()+offset, n);
        offset += n;

        m_cparams.clear();
        m_cparams.reserve(3);
        m_cparams.push_back(p);
        m_cparams.push_back(g);
        m_cparams.push_back(pkey);

    } catch (std::out_of_range &e) {
        throw IncompleteRecord("record smaller than expected when reading DHE params");
    }
}



std::shared_ptr<std::vector<ciphersuite_t>>
get_cipher_suites(const bytes &record, const header_t &header)
{

    assert(YO_MSG_CS_LENGHT_BYTES == 1);
    assert(CIPHER_SUITE_BYTES == 1);

    size_t offset = header.offset;
    size_t num_ciphers_bytes (record.at(offset));
    offset += YO_MSG_CS_LENGHT_BYTES;

    if (offset + num_ciphers_bytes> record.size())
        throw IncompleteRecord("number of cipher suites and record length mismatch");

    auto vec {std::make_shared<std::vector<ciphersuite_t>>()};
    vec->reserve(num_ciphers_bytes/CIPHER_SUITE_BYTES);

    const size_t n = record.size();
    for (size_t j = offset; j < n; j += CIPHER_SUITE_BYTES)
    {
        vec->push_back(static_cast<ciphersuite_t>(record[j]));
    }

    return vec;
}


