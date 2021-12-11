#ifndef PROXY_LOGGER_H
#define PROXY_LOGGER_H

#include <cstdio>
#include <cstdlib>
#include <cstdarg>
#include <vector>
#include <cstdint>

// TODO: rewrite jerry-rigged logging functionality properly

#define LOGF _log_function(__PRETTY_FUNCTION__, nullptr);_log
#define LOG  _log

#define LOGFC          _log_function(__PRETTY_FUNCTION__,nullptr);_log_color_set
#define LOGCF(color)   _log_function(__PRETTY_FUNCTION__,color);_log_color
#define LOGCFC(color)  _log_function(__PRETTY_FUNCTION__,color);_log_color_set
#define LOGCFR(color)  _log_function(__PRETTY_FUNCTION__,color);_log_color_clear

#define LOGERR         _log_function(__PRETTY_FUNCTION__,nullptr,stderr);_log_error
#define LOGBUF         _log_function(__PRETTY_FUNCTION__,nullptr);_log_buf


namespace tcolors {
    /* codes from https://www.codegrepper.com/code-examples/actionscript/terminal+color+escape+codes */
    constexpr const char *RESET = "\033[0m";
    constexpr const char *BLACK = "\033[30m";
    constexpr const char *RED = "\033[31m";
    constexpr const char *GREEN = "\033[32m";
    constexpr const char *YELLOW = "\033[33m";
    constexpr const char *BLUE = "\033[34m";
    constexpr const char *MAGENTA = "\033[35m";
    constexpr const char *CYAN = "\033[36m";
    constexpr const char *WHITE = "\033[37m";
}


void buf_print_enable(bool state);
void start_logger(FILE *fp);
void start_logger(const char *fp);
void _log_function(const char *fname, const char *color, FILE *f = nullptr);
void _log_error(const char *fmt...);
void _log(const char *fmt...);
void _log_color(const char *fmt...);
void _log_color_clear(const char *fmt...);
void _log_color_set(const char *color, const char *fmt...);
void _log_buf(const std::vector<uint8_t> &buf, size_t max = 50, bool hex = false);

#endif
