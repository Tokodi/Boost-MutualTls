#include "server.h"

#include <iostream>

int main(int argc, char* argv[]) {
    if(argc != 2) {
        std::cout << "Usage: server <port>" << std::endl;
        return 1;
    }

    server myServer(atoi(argv[1]));

    return 0;
}
