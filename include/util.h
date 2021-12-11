#ifndef DINT_UTIL_H
#define DINT_UTIL_H

#include <memory>
#include <vector>
#include <string>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cassert>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h> 
#include <error.h>

#include "dint.h"

#define CHAR_INT16(ptr) ((static_cast<int>(*(ptr)) << 8) | static_cast<int>(*((ptr) + 1)) )
#define INT16(h,l) static_cast<uint16_t>((static_cast<uint16_t>(h) << 8) | static_cast<uint16_t>(l) )

namespace dint {

    std::shared_ptr<header_t> parse_header(const std::vector<uint8_t> &buffer);
    int poll_recv(int sockfd, char *ptr, size_t length, double timeout=-1.0l, bool *signal = nullptr );

    std::shared_ptr<std::vector<uint8_t>> create_header(msg_t type, uint16_t length);

    inline void put_int16(std::vector<uint8_t> &vec, const uint16_t val)
    {
        vec.push_back((val & 0xff00) >> 8);
        vec.push_back(val & 0xff);
    }

    size_t write_integer(bytes &buffer, size_t offset, const CryptoPP::Integer &n, size_t width);


    inline size_t read_int(const bytes &buf, size_t offset, int width)
    {
        size_t n = 0;
        for (int i = 0; i < width; ++i)
            n = ((n << 8) | buf.at(offset + i));
        return n;
    }

    inline void push_int(bytes &buf, int width, size_t x)
    {
        size_t n = 0;
        for (int i = 8*(width-1); i >= 0; i -= 8)
            buf.push_back(static_cast<uint8_t>((x >> i) & 0xff));
    }


    constexpr size_t get_msg_length(const msg_t type )
    {
        size_t bytes = 0;
        switch (type)
        {
            case msg_t::VERIFICATION:
                bytes = MSG::VERIFY::LENGTH;
                break;
            case msg_t::PAYLOAD:
                bytes = MSG::PAYLOAD::LENGTH;
                break;
            case msg_t::YO:
                bytes = MSG::YO::LENGTH;
                break;
            case msg_t::NO_CIPHER:
                bytes = MSG::NO_CIPHER::LENGTH;
                break;
            case msg_t::CLOSING:
                bytes = MSG::CLOSING::LENGTH;
                break;
        }

        return bytes;
    }


    template <size_t LEN>
    std::shared_ptr<std::vector<uint8_t>>
    create_record_field(yo_field_t field, size_t length)
    {
        assert(MSG::YO::FIELD == 1);
        std::shared_ptr<bytes> block {std::make_shared<bytes>()};
        block->reserve(length + LEN + MSG::YO::FIELD);
        block->push_back(static_cast<uint8_t>(field));
        if (LEN == 0)
            return block;

        push_int(*block, LEN, length);
        return block;
    }


    template <size_t LEN>
    inline void add_record_field(std::vector<uint8_t> &vec, yo_field_t field, size_t length)
    {
        vec.push_back(static_cast<uint8_t>(field));
        for (int i = 8*(LEN-1); i >= 0; i -= 8)
            vec.push_back(static_cast<uint8_t>((length >> i) & 0xff));
    }

    int sock_addrport(addrinfo *addr, char *str, size_t len, int *port);
    int sock_addrport(sockaddr *addr, char *str, size_t len, int *port);

    std::vector<uint8_t> & operator<<(std::vector<uint8_t> &buf, uint8_t value);
    std::vector<uint8_t> &operator<<(std::vector<uint8_t> &buf, uint16_t value);
    std::vector<uint8_t> &operator<<(std::vector<uint8_t> &buf, uint32_t value);
}


#endif
