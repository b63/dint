#include <cstdio>
#include <sstream>
#include <thread>
#include <iostream>

#include <logger.h>
#include "dint.h"
#include "client.h"


volatile bool quit = false;

void print_received_msgs(dint::Client *c)
{
    try {
        while (!quit)
        {
            auto msg = c->read_msg();
            std::stringstream ss;
            ss << "<< %" << msg->size() << "s\n";
            printf(ss.str().c_str(), msg->data());
        }
    } catch(const std::exception &e) {
        LOGERR("reader: %s\n", e.what());
        quit = true;
    }
}

void writer_msg(dint::Client *c) {
    while (!quit) {
        std::string line;
        std::cout << ">> ";
        if (!std::getline(std::cin, line) || quit)
        {
            printf("Quit.\n");
            quit = true;
            c->poll_sig = true;
            break;
        }

        std::vector<uint8_t> buf (line.size(), 0);
        memcpy(buf.data(), line.c_str(), line.size());
        c->writeln(buf);
    }
}

int main(int argc, char **argv)
{
    if (argc != 1 && argc != 3) {
        printf("test_client1 <name> <port>\n");
        exit(1);
    }

    start_logger(stdout);
    int port          = (argc == 1 ? 5000 : atoi(argv[2]));
    const char * name = (argc == 1 ? "127.0.0.1" : argv[1]);

    dint::Client c(name, port);
    c.connect();

    std::thread reader (print_received_msgs, &c);
    std::thread writer (writer_msg, &c);

    reader.join();
    writer.join();

    return 0;
}
