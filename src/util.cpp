#include <memory>
#include <vector>
#include <string>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cassert>
#include <thread>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h> 
#include <error.h>

#include "dint.h"
#include "exceptions.h"
#include "util.h"

namespace dint {
    std::shared_ptr<header_t> parse_header(const bytes &buffer)
    {
        try {
            assert(VERSION_BYTES == 1);
            assert(MSG_TYPE_BYTES == 1);

            const uint8_t version (buffer.at(0));
            const msg_t msg_type {static_cast<msg_t>(buffer.at(1))};

            size_t offset (VERSION_BYTES + MSG_TYPE_BYTES);

            // get number of byte used to store length
            size_t bytes = get_msg_length(msg_type);

            // TODO: implement better way to read different sized integers
            // edit: meh god enough
            size_t length = read_int(buffer, offset, bytes);;

            return std::make_shared<header_t>(msg_type, version, offset+bytes, length);
        }
        catch(std::out_of_range &e)
        {
            throw IncompleteRecord("record length not enough for header");
        }
    }

    std::shared_ptr<bytes> create_header(msg_t type, uint16_t length)
    {
        size_t n = VERSION_BYTES + MSG_TYPE_BYTES;
        size_t _bytes = get_msg_length(type);
        n += _bytes;

        auto block {std::make_shared<bytes>()};
        block->reserve(n);

        // version
        block->push_back(DINT_VERSION);
        // message type
        block->push_back(static_cast<uint8_t>(type));
        // message length
        switch (_bytes)
        {
            // NOTE: intentional fallthrough
            case 4:
                block->push_back((length & 0xff000000l) >> 24);
            case 3:
                block->push_back((length & 0xff0000l)   >> 16);
            case 2:
                block->push_back((length & 0xff00l)     >>  8);
            case 1:
                block->push_back((length & 0xffl)            );
            case 0:
                break;
            default:
                throw std::invalid_argument("length must be 1 or 4");
        }

        return block;
    }

    int sock_addrport(addrinfo *addr, char *str, size_t len, int *port)
    {
        void *sin_addr = addr->ai_addr;
        if (addr->ai_family == AF_INET) {
            sin_addr = &((sockaddr_in*)addr->ai_addr)->sin_addr;
            *port    =  ntohs(((sockaddr_in*)addr->ai_addr)->sin_port);
        } else if (addr->ai_family == AF_INET6) {
            sin_addr = &((sockaddr_in6*)addr->ai_addr)->sin6_addr;
            *port    =  ntohs(((sockaddr_in6*)addr->ai_addr)->sin6_port);
        }
        const char *ptr = inet_ntop(addr->ai_family, sin_addr, str, len);

        return !ptr;
    }

    int sock_addrport(sockaddr *addr, char *str, size_t len, int *port)
    {
        void *sin_addr = addr;
        if (addr->sa_family == AF_INET) {
            sin_addr = &((sockaddr_in*)addr)->sin_addr;
            *port    =  ntohs(((sockaddr_in*)addr)->sin_port);
        } else if (addr->sa_family == AF_INET6) {
            sin_addr = &((sockaddr_in6*)addr)->sin6_addr;
            *port    =  ntohs(((sockaddr_in6*)addr)->sin6_port);
        }

        const char *ptr = inet_ntop(addr->sa_family, sin_addr, str, len);

        return !ptr;
    }

    int poll_recv(int sockfd, char *ptr, size_t length, double timeout, bool *signal)
    {
        time_t start = time(0);
        const bool ignore = (timeout < 0.0f);

        int read = 0;
        int err = 0; 
        while (read < length) {
            err = recv(sockfd, ptr+read, length-read, 0);

            if (err < 0) 
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                {
                    // would have blocked if socket was not O_NONBLOCK
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    if ((!ignore && timeout <= difftime(time(0), start)) || (signal && *signal))
                        return read;
                    std::chrono::high_resolution_clock::now();
                    continue;
                } else if (read > 0)
                {
                    return read;
                }

                throw dint::Exception(strerror(errno));
            }
            else if (err == 0) {
                // socket got closed
                if (read <= 0)
                    throw dint::Exception("closed while reading");
                else
                    return read;
            }
            else {
                // ok
                read += err;
            }
        }

        return read;
    }

    bytes &operator<<(bytes &buf, uint8_t value)
    {
        buf.push_back(value);
        return buf;
    }

    bytes &operator<<(bytes &buf, uint16_t value)
    {
        buf.push_back((value & 0xff00) >> 8);
        buf.push_back((value &   0xff)     );
        return buf;
    }

    bytes &operator<<(bytes &buf, uint32_t value)
    {
        buf.push_back((value & 0xff000000) >> 24);
        buf.push_back((value & 0x00ff0000) >> 16);
        buf.push_back((value & 0x0000ff00) >>  8);
        buf.push_back((value & 0x000000ff)      );
        return buf;
    }

    size_t write_integer(bytes &buffer, size_t offset, const CryptoPP::Integer &n, size_t width)
    {
        const size_t min_size = n.MinEncodedSize();
        if(offset + min_size + width>= buffer.size()) {
            buffer.resize(width + offset + min_size );
        }

        if (width > 0)
        {
            for (int i = 0; i < width; ++i)
                buffer[offset+i] = ((min_size >> 8*(width-i-1)) & 0xff);
        }
        n.Encode((CryptoPP::byte*)buffer.data()+offset+width, min_size);

        return width + offset + min_size;
    }

}
