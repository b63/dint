#ifndef DINT_EXCEPTIONS_H
#define DINT_EXCEPTIONS_H

#include <stdexcept>
#include <vector>
#include <string>

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
        uint16_t server_v;
        uint16_t client_v;

    public: 
        VersionMismatch(uint16_t server, uint16_t client)
            : server_v (server), client_v (client)
        {}

        const char * what() const throw()
        {
            return "verion of tls do not match";
        }

    };

    class IncompleteRecord : public std::exception
    {
    private:
        std::string m_msg;
    public:
        IncompleteRecord(const char *msg)
            : m_msg (msg)
        { }

        const char * what() const throw () {
            return m_msg.c_str();
        }
    };

    class InvalidRecord : public std::exception
    {
    private:
        std::string m_msg;
    public:
        InvalidRecord(const char *msg)
            : m_msg (msg)
        { }

        const char * what() const throw () {
            return m_msg.c_str();
        }
    };

    class InvalidState : public std::exception
    {
    private:
        std::string m_msg;
    public:
        InvalidState(const char *msg)
            : m_msg (msg)
        { }

        const char * what() const throw () {
            return m_msg.c_str();
        }
    };

    class VerificationFailed : public std::exception
    {
    private:
        std::string m_msg;
    public:
        VerificationFailed(const char *msg)
            : m_msg (msg)
        { }

        const char * what() const throw () {
            return m_msg.c_str();
        }
    };
}
#endif
