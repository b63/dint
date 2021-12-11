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

#include <logger.h>
#include "dint.h"
#include "cipher.h"
#include "clientsm.h"
#include "serversm.h"
#include "client.h"
#include "exceptions.h"
#include "util.h"


constexpr auto net_connect = connect;
using namespace dint;

Client::Client(const std::string &name, int port)
    : m_srv_name (name),
    m_port (port),
    m_sm {nullptr}
{
    start_socket();
}


void Client::start_socket()
{
    addrinfo hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;     // ipv4 or ipv6
    hints.ai_socktype = SOCK_STREAM; // tcp
    hints.ai_flags  = AI_PASSIVE;    // use hostip

    const std::string port_ptr {std::to_string(m_port)};

    addrinfo *res;
    int err = getaddrinfo(m_srv_name.c_str(), port_ptr.c_str(), &hints, &res);
    if (err) {
        throw gai_strerror(err);
    }

    // create a socket with addr/sock type/and protocl
    m_sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    m_addrinfo = res;
}

Client::~Client() 
{
    if (!m_sockfd)
    {
        shutdown(m_sockfd, SHUT_RD);
    }
}

void Client::close_sock()
{
    if (!m_sockfd)
    {
        auto msg = m_sm->close();
        if (msg)
            _writeln(*msg);
    }
}

void Client::connect()
{
    // create socket connection to remote host
    char str_addr [INET6_ADDRSTRLEN ];
    int port;
    if(sock_addrport(m_addrinfo, str_addr, INET6_ADDRSTRLEN, &port)) {
        throw Exception(strerror(errno));
    }

    int err = net_connect(m_sockfd, m_addrinfo->ai_addr, m_addrinfo->ai_addrlen);

    if (err) {
        freeaddrinfo(m_addrinfo);
        m_addrinfo = nullptr;
        throw Exception(strerror(errno));
    }

    m_addrlen = sizeof m_addr;
    err = getpeername(m_sockfd, (sockaddr*)&m_addr, &m_addrlen);
    freeaddrinfo(m_addrinfo);
    m_addrinfo = nullptr;

    if (err) {
        throw Exception(strerror(errno));
    }

    // set socketfd as non-blocking
    int flags = fcntl(m_sockfd, F_GETFL, 0);
    fcntl(m_sockfd, F_SETFL, flags | O_NONBLOCK);

    start_sm();
}

void Client::writeln(const bytes &buf)
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


void Client::_writeln(const bytes &buf)
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

std::shared_ptr<bytes> Client::read_msg()
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


void Client::start_sm()
{
    m_sm = std::make_shared<ClientSM>();
    m_sm->start_protocol();

    // send initial message to server
    auto clientmsg {m_sm->get_payload()};
    _writeln(*clientmsg);

    // read reply from server (ServerYo)
    auto servermsg {read_msg()};

    // process server's message
    m_sm->process_record(*servermsg, nullptr);

    // generate reply (cipher info/verification)
    clientmsg = m_sm->get_payload();
    _writeln(*clientmsg); // send to server

    // read server's message (verfication)
    servermsg = read_msg();
    m_sm->process_record(*servermsg, nullptr);

    // both client/server should be in OPEN state
    if (m_sm->state() != smstate_t::OPEN) {
        throw Exception("handshake unsuccessful");
    } else {
        LOGFC(tcolors::GREEN, "client state open\n");
    }
}

