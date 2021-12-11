#ifndef DINT_CLIENT_H 
#define DINT_CLIENT_H

#include <string>
#include <memory>
#include <vector>

#include <netdb.h> 


#include "dint.h"
#include "clientsm.h"

namespace dint {
    class Client
    {
    public:
        Client(const std::string &name, int port);
        ~Client();
        std::shared_ptr<std::vector<uint8_t>> read_msg();
        void write(const std::vector<uint8_t> &str);
        void writeln(const std::vector<uint8_t>  &str);
        void flush();
        void close_sock();
        void connect();
        bool poll_sig = false;

    private:
        void start_socket();
        void start_sm();
        void _writeln(const std::vector<uint8_t> &buf);

        std::shared_ptr<ClientSM> m_sm;
        std::string m_srv_name;

        std::vector<uint8_t> m_snd_buf;
        std::vector<uint8_t> m_rcv_buf;
        addrinfo *m_addrinfo;
        sockaddr_storage m_addr;
        socklen_t m_addrlen;
        int m_port;
        int m_sockfd;
    };
}

#endif
