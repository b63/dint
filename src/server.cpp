#include <string>
#include <memory>
#include <vector>
#include <thread>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h> 
#include <error.h>
#include <fcntl.h>

#include "dint.h"
#include "cipher.h"
#include "clientsm.h"
#include "serversm.h"
#include "server.h"
#include "exceptions.h"
#include "util.h"

#include <logger.h>

constexpr auto net_accept = accept;
constexpr auto net_listen = listen;
using namespace dint;

Server::Server(const std::string &name, int port)
    : m_port (port),
    m_name (name),
    m_rcv_buf (),
    m_snd_buf ()
{
    start_socket();
}

// use existing open socket
Server::Server(int sockfd)
    : m_sockfd (sockfd),
    m_listenfd (-1),
    m_rcv_buf (),
    m_snd_buf ()
{
    char name[INET6_ADDRSTRLEN];

    sockaddr_storage addr;
    socklen_t size = sizeof addr;
    if (getsockname(m_sockfd, (sockaddr*)&addr, &size) == -1) {
        throw Exception(strerror(errno));
    }


    if(sock_addrport((sockaddr*)&addr, name, INET6_ADDRSTRLEN, &m_port)) {
        throw Exception(strerror(errno));
    }

    m_name = std::string(name);

    // set socketfd as non-blocking
    int flags = fcntl(m_sockfd, F_GETFL, 0);
    fcntl(m_sockfd, F_SETFL, flags | O_NONBLOCK);

    LOGF("using existing socket: %s %i\n", name, m_port);
    start_sm();
}

void Server::start_socket()
{
    addrinfo hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // ipv4
    hints.ai_socktype = SOCK_STREAM; // tcp
    hints.ai_flags  = AI_PASSIVE; // use hostip

    const std::string port_ptr {std::to_string(m_port)};
    const char *host = m_name.c_str();

    addrinfo *res;
    int err = getaddrinfo(*host ? host : nullptr, port_ptr.c_str(), &hints, &res);
    if (err) {
        throw Exception(gai_strerror(err));
    }

    // creat a socket with addr/sock type/and protocl
    m_listenfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    setsockopt(m_listenfd, SOL_SOCKET, SO_REUSEADDR, "1", sizeof(char*));

    // bind socket to port
    if (bind(m_listenfd, res->ai_addr, res->ai_addrlen)) {
        freeaddrinfo(res);
        throw Exception(strerror(errno));
    }

    socklen_t size = sizeof m_addr;
    freeaddrinfo(res);
    if (getsockname(m_listenfd, (sockaddr*)&m_addr, &size) == -1) {
        throw Exception(strerror(errno));
    }
}

Server::~Server() {
    if (m_sockfd)
    {
        shutdown(m_sockfd, 2);
    }
}

void Server::close_sock()
{
    if (m_sockfd)
    {
        auto msg = m_sm->close();
        if (msg)
            _writeln(*msg);
    }
}

void Server::listen()
{

    char str_addr [INET6_ADDRSTRLEN ];
    int port;
    if(sock_addrport((sockaddr*)&m_addr, str_addr, INET6_ADDRSTRLEN, &port)) {
        throw Exception(strerror(errno));
    }

    // listen for connections
    if (net_listen(m_listenfd, 5)) {
        throw Exception(strerror(errno));
    }

    sockaddr_storage cl_addr;
    socklen_t cl_addr_size = sizeof cl_addr;

    LOGFC(tcolors::GREEN, "server listening %s:%i\n", str_addr, port);
    m_sockfd = net_accept(m_listenfd, (sockaddr*) &cl_addr, &cl_addr_size);

    if (m_sockfd < 0) {
        throw Exception(strerror(errno));
    }

    // set socketfd as non-blocking
    int flags = fcntl(m_sockfd, F_GETFL, 0);
    fcntl(m_sockfd, F_SETFL, flags | O_NONBLOCK);

    start_sm();
}


void Server::writeln(const bytes &buf)
{
    // combine any buffered data with given data
    bytes all_buf;
    all_buf.reserve(buf.size() + m_snd_buf.size());

    if (m_snd_buf.size() > 0)
    {
        all_buf.insert(all_buf.end(), m_snd_buf.begin(), m_snd_buf.end());
        m_snd_buf.clear();
    }
    all_buf.insert(all_buf.end(), buf.begin(), buf.end());

    if (all_buf.size() == 0)
        return;


    auto payload = m_sm->encode_payload(all_buf);
    _writeln(*payload);
}


void Server::_writeln(const bytes &buf)
{
    int sent = 0, err = 0;
    const size_t len {buf.size()};

    while (sent < len) {
        err = send(m_sockfd, buf.data()+sent, len-sent, 0);

        if (err == -1) {
            throw Exception(strerror(errno));
        } else {
            sent += err;
        }
    }
    LOGFC(tcolors::GREEN, "SENT %i/%lu bytes\n", sent, len);
}


// TODO: implement this
//std::shared_ptr<bytes> Server::read_msg_until(const std::string &chars)
//{
//}


std::shared_ptr<bytes> Server::read_msg()
{
    m_rcv_buf.clear();
    assert(MSG::TYPE_BYTES == 1);

    constexpr size_t prefix_size = MSG::TYPE_OFFSET + MSG::TYPE_BYTES;
    m_rcv_buf.resize(prefix_size);

    // keep reading until we have at least the header
    int read = 0, err = 0;
    read = poll_recv(m_sockfd, (char*)(m_rcv_buf.data()), prefix_size, -1., &poll_sig);
    if (read < prefix_size)
        throw Exception("unable to read header prefix");

    msg_t msg_type = static_cast<msg_t>(m_rcv_buf.at(MSG::TYPE_OFFSET));
    const size_t msg_length_bytes = get_msg_length(msg_type);
    const size_t header_size = prefix_size + msg_length_bytes;
    m_rcv_buf.resize(header_size);

    read += poll_recv(m_sockfd, (char*)(m_rcv_buf.data()+read), msg_length_bytes, -1., &poll_sig);
    if (read < header_size)
        throw Exception("unable to read full header");

    // parse the header to see how long of a message we should read in
    auto header {parse_header(m_rcv_buf)};
    auto msg {std::make_shared<bytes>()};
    const size_t target_size = header->length;

    // separate the data and header into separate vectors if payload
    if (header->type == msg_t::PAYLOAD)
    {
        // only store the payload (not the header)
        read = 0;
        msg->resize(target_size);
    }
    else if (header->type == msg_t::CLOSING)
    {
        throw Exception("socket closed by other end");
    }
    else 
    {
        // include header and everything else
        read = m_rcv_buf.size();
        msg->reserve(read + target_size);
        msg->insert(msg->begin(), m_rcv_buf.begin(), m_rcv_buf.end());
        msg->resize(read + target_size);
    }

    read = poll_recv(m_sockfd, (char*)(msg->data()+read), target_size, -1., &poll_sig);
    if (read < target_size)
        throw Exception("unable to read full message");

    // decode meassage if message is type PAYLOAD
    if (m_sm->state() == smstate_t::OPEN && header->type == msg_t::PAYLOAD) {
        msg = m_sm->decode_payload(*msg, header);
    }

    return msg;
}


void Server::start_sm()
{
    m_sm = std::make_shared<ServerSM>();
    m_sm->start_protocol();

    // read in initial message from client (ClientYo)
    auto clientmsg {read_msg()};

    // process client's message
    m_sm->process_record(*clientmsg, nullptr);

    // generate the reply (ServerYo)
    auto servermsg {m_sm->get_payload()};
    _writeln(*servermsg); // send to client

    // read client's message (ClientYo with cipher info)
    clientmsg = read_msg();
    // process client' message
    m_sm->process_record(*clientmsg, nullptr);
    // read client's message againt (verification - hash of recvied message)
    clientmsg = read_msg();
    // process client' message
    m_sm->process_record(*clientmsg, nullptr);
    // generate reply (hash of recv messages)
    servermsg = m_sm->get_payload();
    _writeln(*servermsg); // send to client

    // both client/server should be in OPEN state
    if (m_sm->state() != smstate_t::OPEN) {
        throw Exception("handshake unsuccessful");
    } else {
        LOGFC(tcolors::GREEN, "server state open\n");
    }
}



