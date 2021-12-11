#ifndef DINT_CLIENTSM_H 
#define DINT_CLIENTSM_H

#include <string>
#include <memory>
#include <vector>

#include "dint.h"
#include "cipher.h"

namespace dint {
    class ClientSM
    {
    public:
        ClientSM(bool require_certificate = false);
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

        std::shared_ptr<Cipher> m_ec;
        std::vector<std::shared_ptr<bytes>> m_cparams;
        //std::vector<CryptoPP::Integer> m_cstate;

        // server's private key
        std::shared_ptr<CryptoPP::RSA::PrivateKey> m_rsa_priv;
        // **client's** public key
        std::shared_ptr<CryptoPP::RSA::PublicKey> m_rsa_pub;

        std::shared_ptr<bytes> m_enc_cparams;

        void process_server_yo_record(const bytes &record, const header_t &header);
        void process_server_verification(const bytes &record, const header_t &header);
        void process_dhe_params(const bytes &record, size_t offset);
        void generate_cipher_keys();
    };
}


#endif
