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
        void close();
        void reset();
        void start_protocol();
        int process_record(const std::vector<char> &record, std::shared_ptr<const header_t> header = nullptr);
        std::shared_ptr<std::vector<char>> get_payload();
        smstate_t state();


    private:
        smstate_t m_state;
        ciphersuite_t m_cipher;
        bool m_cert;
        std::shared_ptr<std::vector<char>> m_recv_block;
        std::shared_ptr<std::vector<char>> m_send_block;
        std::shared_ptr<Cipher> m_ec;

        void *m_cparams;
        void *m_cstate;

        void process_server_yo_record(const std::vector<char> &record, const header_t &header);
        void process_server_verification(const std::vector<char> &record, const header_t &header);
        void process_dhe_params(const std::vector<char> &record, size_t offset);
        void generate_cipher_keys();
    };
}


#endif
