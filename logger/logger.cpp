#include <sstream>

#include <cstdio>
#include <cstring>
#include <cstdarg>
#include <sys/types.h>
#include <unistd.h>
#include <error.h>

#include "logger.h"

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

constexpr const char *HEX_BYTE = \
"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222\
32425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444546\
4748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696\
a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d\
8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b\
1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4\
d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f\
8f9fafbfcfdfeff";

FILE *logfd = 0;
bool close_fd = false;
bool printbuf = false;
pid_t parentpid = 0;
const char *LOGDIR = "/tmp";

void close_logger()
{
    if (logfd!=nullptr)
        fclose(logfd);
    logfd = nullptr;
}

// questionable hack to ensure logfd is closed
class EOBJ
{
    public:
        ~EOBJ(){
            if (getpid() == parentpid && close_fd)
                close_logger();
        }
};

const EOBJ _obj{};

void buf_print_enable(bool state)
{
    printbuf = state;
}

void start_logger(const char *fp)
{
    std::stringstream ss;
    ss << LOGDIR << "/" << fp;
    std::string filep {ss.str()};

    logfd = fopen(filep.c_str(), "a");

    if (logfd == nullptr)
        throw Exception("unable to open logfile");

    time_t t = time(0);
    fprintf(logfd, "---- LOG STARTING %s ---- \n", ctime(&t));
    fflush(logfd);
    parentpid = getpid();
    close_fd = true;
}


void start_logger(FILE *fp)
{
    logfd = fp;

    time_t t = time(0);
    fprintf(logfd, "---- LOG STARTING ----\n%s", ctime(&t));
    fflush(logfd);
    parentpid = getpid();
}

void _log_function(const char *fname, const char *color, FILE *f)
{
    if (f == nullptr)
        f = logfd;

    if (f == nullptr)
        throw Exception("log file is not open");

    const char *start = strchr(fname, ' ');
    const char *end = strrchr(fname, ')');

    std::string fname_str (fname);
    if (fname_str.find("lambda") != std::string::npos){
        fname_str = fname_str.substr(0, 20) + "...::lambda";
    } else if (start && end)
        fname_str  = fname_str.substr(start-fname+1, end-start+1);

    if (color)
        fprintf(f, "%s[%s](%i) ", color, fname_str.c_str(), getpid());
    else
        fprintf(f, "[%s](%i) ", fname_str.c_str(), getpid());
    fflush(f);
}

void _log_buf(const std::vector<uint8_t> &buf, size_t max, bool hex)
{
    if (logfd == nullptr)
        throw Exception("log file is not open");

    const size_t maxcol = (hex ? 32 : 80);
    const size_t n = buf.size();
    max = (max < n ? max : n);

    fprintf(logfd, "size %lu\n", n);
    if (!printbuf) {
        fflush(logfd);
        return;
    }

    size_t col = 0;
    for (size_t i = 0; i < max; ++i)
    {
        char a = buf[i];
        char as[4] = {a, 0, 0, 0};
        const char *str = as;

        if (!hex)
        {
            // print raw byte
            switch (a)
            {
                case '\r':
                    str = "\\r";
                    break;
                case '\n':
                    str = "\\n";
                    break;
                case '\t':
                    str = "\\t";
                    break;
            }
        }
        else
        {
            // print as hex
            as[0] = HEX_BYTE[static_cast<uint8_t>(a)*2];
            as[1] = HEX_BYTE[static_cast<uint8_t>(a)*2+1];
            as[2] = ((col & 1) ? ' ' : 0);
        }

        if (!(++col % maxcol) && i+1 != max)
            fprintf(logfd, "%s\n", str);
        else
            fprintf(logfd, "%s", str);
    }

    if (max < n) {
        fprintf(logfd, "...\n");
    } else {
        fprintf(logfd, "\n");
    }

    fflush(logfd);
}


void _log_error(const char *fmt...)
{
    va_list args;
    va_start(args, fmt);

    fprintf(stderr, "%s", tcolors::RED);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "%s", tcolors::RESET);

    fflush(stderr);
    va_end(args);
}

void _log(const char *fmt...)
{
    if (logfd == nullptr)
        throw Exception("log file is not open");

    va_list args;
    va_start(args, fmt);
    vfprintf(logfd, fmt, args);
    fflush(logfd);
    va_end(args);
}

void _log_color(const char *fmt...)
{
    if (logfd == nullptr)
        throw Exception("log file is not open");

    va_list args;
    va_start(args, fmt);

    vfprintf(logfd, fmt, args);
    fprintf(logfd, "%s", tcolors::RESET);

    fflush(logfd);
    va_end(args);
}

void _log_color_clear(const char *fmt...)
{
    if (logfd == nullptr)
        throw Exception("log file is not open");

    va_list args;
    va_start(args, fmt);

    fprintf(logfd, "%s", tcolors::RESET);
    vfprintf(logfd, fmt, args);
    fprintf(logfd, "%s", tcolors::RESET);

    fflush(logfd);
    va_end(args);
}

void _log_color_set(const char *color, const char *fmt...)
{
    if (logfd == nullptr)
        throw Exception("log file is not open");

    va_list args;
    va_start(args, fmt);

    fprintf(logfd, "%s", color);
    vfprintf(logfd, fmt, args);
    fprintf(logfd, "%s", tcolors::RESET);

    fflush(logfd);
    va_end(args);
}
