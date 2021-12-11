#include <cstdio>
#include <sstream>
#include <thread>
#include <iostream>

#include <logger.h>
#include "dint_public.h"
#include "server.h"

volatile bool quit = false;

void print_received_msgs(dint::Server *s)
{
    try {
        while (!quit)
        {
            auto msg = s->read_msg();
            std::stringstream ss;
            ss << "<< %" << msg->size() << "s\n";
            printf(ss.str().c_str(), msg->data());
        }
    } catch(const std::exception &e) {
        LOGERR("reader: %s\n", e.what());
        quit = true;
    }
}

void writer_msg(dint::Server *s) {
    while (!quit) {
        std::string line;
        std::cout << ">> ";

        // the way its bailing is 90% unacceptable
        if (!std::getline(std::cin, line) || quit)
        {
            printf("Quit.\n");
            quit = true;
            s->poll_sig = true;
            break;
        }

        std::vector<uint8_t> buf (line.size(), 0);
        memcpy(buf.data(), line.c_str(), line.size());
        s->writeln(buf);
    }
}

int main(int argc, char **argv)
{
    if (argc != 1 && argc != 2 && argc != 3) {
        printf("test_server1 <port> [name]\n");
        exit(1);
    }

    start_logger(stdout);

    int port          = (argc == 1 ? 5000 : atoi(argv[1]));
    const char * name = (argc == 1 ? "127.0.0.1" : (argc == 3 ? argv[2] : ""));


    dint::Server s(name, port);
    s.listen();

    std::thread reader (print_received_msgs, &s);
    std::thread writer (writer_msg, &s);

    reader.join();
    writer.join();

    return 0;
}

