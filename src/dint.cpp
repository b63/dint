#include <vector> 
#include <memory> 
#include <stdexcept> 

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h> 

#include <cassert> 

#include "dint.h"

#define CHAR_INT16(ptr) ((static_cast<int>(*(ptr)) << 8) | static_cast<int>(*((ptr) + 1)) )
#define INT16(h,l) static_cast<uint16_t>((static_cast<uint16_t>(h) << 8) | static_cast<uint16_t>(l) )

using namespace dint;


std::shared_ptr<header_t> read_header(const std::vector<char> &buffer)
{
    try {
        assert(VERSION_BYTES == 2);
        const uint16_t version (INT16(buffer.at(0), buffer.at(1)));

        assert(MSG_TYPE_BYTES == 2);
        const msg_t msg_type {static_cast<msg_t>(INT16(buffer.at(2), buffer.at(3)))};

        // same number of bytes for length for all message types for now
        const size_t length (INT16(buffer.at(4), buffer.at(5)));
        const size_t offset (VERSION_BYTES + MSG_TYPE_BYTES + 2);

        return std::make_shared<header_t>(msg_type, version, offset, length);
    }
    catch(std::out_of_range &e)
    {
        throw IncompleteRecord("record length not enough for header");
    }
}
