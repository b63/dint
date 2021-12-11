#ifndef DINT_EXCEPTIONS_H
#define DINT_EXCEPTIONS_H

#include <stdexcept>
#include <vector>
#include <string>
#include <cstdlib>

#include "dint.h"

namespace dint {
    class CipherSuiteMismatch : public std::exception
    {
    public:
        CipherSuiteMismatch(const std::vector<ciphersuite_t> &vec) throw()
            : m_suites(vec) {};
        const char * what() const throw() {
            return "no common cipher suite found";
        }
    private:
        std::vector<ciphersuite_t> m_suites;
    };


    class VersionMismatch : public std::exception
    {
    private:
        uint8_t server_v;
        uint8_t client_v;

    public: 
        VersionMismatch(uint8_t server, uint8_t client)
            : server_v (server), client_v (client)
        {}

        const char * what() const throw()
        {
            return "verion of tls do not match";
        }

    };


    class Exception : public std::exception
    {
        public:
        Exception(const char *msg)
            : m_msg(msg)
        {}

        const char * what() const throw() {
            return m_msg.c_str();
        }

        private:
            std::string m_msg;
    };

    class IncompleteRecord : public Exception
    {
    public:
        IncompleteRecord(const char *msg)
            : Exception(msg)
        { }
    };

    class InvalidRecord : public Exception
    {
    public:
        InvalidRecord(const char *msg)
            : Exception (msg)
        { }
    };

    class InvalidState : public Exception
    {
    public:
        InvalidState(const char *msg)
            : Exception (msg)
        { }
    };

    class VerificationFailed : public Exception
    {
    public:
        VerificationFailed(const char *msg)
            : Exception (msg)
        { }
    };
}
#endif
