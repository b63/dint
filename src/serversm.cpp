#include <cassert>
#include <vector>
#include <stdexcept>
#include <cstring>

#include <cryptopp/rdrand.h>
#include <cryptopp/integer.h>

#include "serversm.h"
#include "cipher.h"
#include "exceptions.h"

#define CHAR_INT16(ptr) ((static_cast<int>(*(ptr)) << 8) | static_cast<int>(*((ptr) + 1)) )
#define INT16(h,l) static_cast<uint16_t>((static_cast<uint16_t>(h) << 8) | static_cast<uint16_t>(l) )

using namespace dint;

std::shared_ptr<std::vector<ciphersuite_t>>
get_cipher_suites(const std::vector<char> &record, const header_t &header);

inline void put_int16(std::vector<char> &vec, const uint16_t val)
{
    vec.push_back((val & 0xff00) >> 8);
    vec.push_back(val & 0xff);
}

ServerSM::ServerSM(bool require_certificate)
    : m_state (smstate_t::CLOSED) , m_cert (require_certificate)
{

}

void ServerSM::start_protocol()
{
    size_t n = VERSION_BYTES+MSG_TYPE_BYTES + YO_RECORD_FIELD_BYTES;
    n += CIPHER_SUITE_LENGHT_BYTES + CIPHER_SUITE_BYTES * 1;

    m_send_block = std::make_shared<std::vector<char>>(n);

    m_send_block->reserve(n);
    // version
    put_int16(*m_send_block, DINT_VERSION);
    // message type
    put_int16(*m_send_block, (uint16_t) msg_t::YO);
    // cipher suite field
    put_int16(*m_send_block, (uint16_t) yo_record_t::CIPHER_SUITES);
    // number of ciphers suites (in bytes)
    put_int16(*m_send_block, (char) CIPHER_SUITE_BYTES);
    // specify acceptable cipher suite(s)
    put_int16(*m_send_block, (uint16_t) ciphersuite_t::DH_WITH_AES_128_HMAC_SHA_256);

    m_state = smstate_t::SEND_YO;
}


std::shared_ptr<std::vector<char>> ServerSM::get_payload()
{
    if (m_state == smstate_t::SEND_YO)
    {
        return m_send_block;
    }
    else if (m_state == smstate_t::SEND_VERIFICATION)
    {
        auto v_ptr {m_ec->encrypt(*m_recv_block)};
        size_t n = v_ptr->size();
        size_t N = n + MSG_TYPE_BYTES + VERSION_BYTES + 2;

        auto payload {std::make_shared<std::vector<char>>(N)};
        put_int16(*payload, (uint16_t) DINT_VERSION);
        put_int16(*payload, (uint16_t) msg_t::VERIFICATION);
        put_int16(*payload, static_cast<uint16_t>(n));

        payload->resize(N);
        memcpy(payload->data(), v_ptr->data(), n);

        return payload;
    }

    throw InvalidState("invalid call to get_payload");
}


int ServerSM::process_record(const std::vector<char> &record,
        std::shared_ptr<const header_t> header)
{
    // read in the header fields if not given
    if (!header) {
        header = read_header(record);
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
        case smstate_t::RECV_YO:
            if (header->type == msg_t::NO_CIPHER)
            {
                throw CipherSuiteMismatch(std::move(
                            *get_cipher_suites(record, *header)));
            }
            else if (header->type == msg_t::YO)
            {
                process_client_yo_record(record, *header);
                m_state = smstate_t::SEND_VERIFICATION;

                // make a copy of received data for verification step
                m_recv_block->clear();
                m_recv_block->resize(record.size());
                memcpy(m_recv_block->data(), record.data(), record.size());
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
                process_client_verification(record, *header);
                m_state = smstate_t::OPEN;
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


void ServerSM::process_server_verification(const std::vector<char> &record,
        const header_t &header)
{
    try {
        size_t offset = header.offset;

        std::vector<char> record_data (record.cbegin()+offset, record.end());
        auto dec {m_ec->decrypt(record_data, 0, 2)};

        size_t n = record_data.size();
        if (memcmp(m_send_block->data(), dec->data(), n))
            throw VerificationFailed("sent and received blocks differ");
    } catch (std::out_of_range &e) {
        throw IncompleteRecord("record smaller than expected");
    }

}

void ServerSM::process_client_yo_record(const std::vector<char> &record,
        const header_t &header)
{

    try {
        size_t n = header.offset;
        yo_record_t field_type = static_cast<yo_record_t>(record.at(n));
        if (field_type == yo_record_t::SERVER_CERT)
        {
            // TODO: establish veracity of server certificate here
            assert("public key certificates support not yet available");
            size_t len =INT16(record.at(n+1), record.at(n+2));
            n += len + 2 + 1;
        }

        field_type = static_cast<yo_record_t>(record.at(n++));
        if (field_type != yo_record_t::SELECTED_CIPHER_SUITE) {
            throw InvalidRecord("expected cipher suite field at this point in record");
        }

        m_cipher = static_cast<ciphersuite_t>(INT16(record.at(n), record.at(n+1)));
        n += 2;
        size_t cblock = INT16(record.at(n), record.at(n+1));
        switch (m_cipher)
        {
            case ciphersuite_t::DH_WITH_AES_128_HMAC_SHA_256:
                process_dhe_params(record, n);
                break;

            default:
                assert("ciphersuite not yet implemented");
                break;
        }
        n += cblock;

        if (n > record.size())
            throw IncompleteRecord("record does not contain cipher key");

        // all server cipher params parsed and received, now generate the
        // public/private key pair to send to sender
        generate_cipher_keys();
    } catch (std::out_of_range &e) {
        throw IncompleteRecord("record smaller than expected");
    }
}


void ServerSM::generate_cipher_keys()
{
    using namespace CryptoPP;
    if (!m_cparams) {
        throw InvalidState("no cipher params");
    }

    if (m_cipher == ciphersuite_t::DH_WITH_AES_128_HMAC_SHA_256)
    {
        auto rdrand {RDRAND()};
        dhe_params_t *params {static_cast<dhe_params_t*>(m_cparams)};
        Integer g (params->g->data());
        Integer p (params->p->data());
        Integer b (rdrand, p.BitCount());
        Integer pub_key (params->pub_key->data());

        Integer priv_key {a_exp_b_mod_c(g, b, p)};
        Integer shared_key {a_times_b_mod_c(pub_key, priv_key, p)};

        size_t n = shared_key.MinEncodedSize();
        auto skey_bytes {std::make_shared<std::vector<char>>(n)};
        skey_bytes->resize(n);
        shared_key.Encode((CryptoPP::byte*)(skey_bytes->data()), n);

        // store computed keys as Integers for later use
        m_cstate = new dhe_state_t{p, g, priv_key, shared_key };
        // insantiate cipher with shared key
        m_ec = std::make_shared<Cipher>(*skey_bytes);
    }
    else
    {
        assert("other cipher suites not currently implemented.");
    }
}


void ServerSM::process_dhe_params(const std::vector<char> &record, size_t offset)
{
    try {
        size_t cblock = INT16(record.at(offset), record.at(offset+1));
        size_t i = offset + 2;;

        // read group order
        size_t n (record.at(i++));
        auto g {std::make_shared<std::vector<char>>(n)};
        g->resize(n);
        memcpy(g->data(), record.data()+i, n);

        // read prime
        i += n;
        n = record.at(i++);
        auto p {std::make_shared<std::vector<char>>(n)};
        p->resize(n);
        memcpy(p->data(), record.data()+i, n);
        i += n;

        // read the key
        n = INT16(record.at(i), record.at(i+1));
        i += 2;
        auto pkey {std::make_shared<std::vector<char>>(n)};
        pkey->resize(n);
        memcpy(pkey->data(), record.data()+i, n);
        i += n;

        m_cparams = new dhe_params_t{g, p, pkey};

        if (cblock != offset-i) {
            throw IncompleteRecord("reported ciper param block size and actual size does not match");
        }

    } catch (std::out_of_range &e) {
        throw IncompleteRecord("record smaller than expected when reading DH params");
    }
}



std::shared_ptr<std::vector<ciphersuite_t>>
get_cipher_suites(const std::vector<char> &record, const header_t &header)
{

    assert(CIPHER_SUITE_LENGHT_BYTES == 1);
    assert(CIPHER_SUITE_BYTES == 2);

    size_t offset = header.offset;
    size_t num_ciphers_bytes (record.at(offset));
    offset += CIPHER_SUITE_LENGHT_BYTES;

    if (offset + num_ciphers_bytes> record.size())
        throw IncompleteRecord("number of cipher suites and record length mismatch");

    auto vec {std::make_shared<std::vector<ciphersuite_t>>(num_ciphers_bytes/CIPHER_SUITE_BYTES)};

    const size_t n = record.size();
    for (size_t j = offset; j < n; j += CIPHER_SUITE_BYTES)
    {
        vec->push_back(static_cast<ciphersuite_t>(
                    INT16(record[j], record[j+1])
                ));
    }

    return vec;
}

b
