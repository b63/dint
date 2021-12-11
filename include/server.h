#ifndef DINT_SERVER_H 
#define DINT_SERVER_H

#include <string>
#include <memory>
#include <vector>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h> 


#include "dint.h"
#include "clientsm.h"
#include "serversm.h"


namespace dint {
    class Server
    {
    public:
        Server(const std::string &name = "localhost", int port = 8000);
        Server(int sockfd);
        ~Server();
        void write(const std::string &str);
        void writeln(const std::vector<uint8_t> &buf);
        std::shared_ptr<std::vector<uint8_t>> read_msg();
        void flush();
        void close_sock();
        void listen();
        bool poll_sig = false;

    private:
        void start_socket();
        void start_sm();

        std::shared_ptr<ServerSM> m_sm;
        sockaddr_storage m_addr;
        int m_listenfd;
        int m_sockfd;
        int m_port;
        std::string m_name;

        std::vector<uint8_t> m_snd_buf;
        std::vector<uint8_t> m_rcv_buf;

        void _writeln(const std::vector<uint8_t> &buf);
    };
}

#endif
