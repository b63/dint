#ifndef DINT_SERVERSM_H
#define DINT_SERVERSM_H

#include <string>
#include <memory>
#include <vector>

#include <cryptopp/integer.h>

#include "dint.h"
#include "cipher.h"

namespace dint {
    class ServerSM
    {
    public:
        ServerSM();
        std::shared_ptr<bytes> close();
        void reset();

        void start_protocol();
        int process_record(const bytes &record, std::shared_ptr<const header_t> header = nullptr);
        std::shared_ptr<const bytes> get_payload();

        std::shared_ptr<bytes>
            encode_payload(const bytes &data);
        std::shared_ptr<bytes>
            decode_payload(const bytes &data,
                    std::shared_ptr<const header_t> header = nullptr);
        std::shared_ptr<bytes> get_closing_msg();

        smstate_t state() {
            return m_state;
        }


    private:
        smstate_t m_state;
        ciphersuite_t m_cipher;
        bool m_cert;
        std::shared_ptr<bytes> m_recv_block;
        std::shared_ptr<bytes> m_send_block;
        std::vector<std::shared_ptr<bytes>> m_bufs;
        std::shared_ptr<Cipher> m_ec;

        std::vector<CryptoPP::Integer> m_cstate;
        std::shared_ptr<bytes> m_enc_cparams;

        // client's private key
        std::shared_ptr<CryptoPP::RSA::PrivateKey> m_rsa_priv;
        // **server's** public key
        std::shared_ptr<CryptoPP::RSA::PublicKey> m_rsa_pub;

        void process_client_yo_record(const bytes &record, const header_t &header);
        void process_client_cipher_params(const bytes &record, const header_t &header);
        void process_client_verification(const bytes &record, const header_t &header);
        void handle_no_cipher_found(const bytes &record, const header_t &header);
        void generate_cipher_keys();
    };
}

#endif
