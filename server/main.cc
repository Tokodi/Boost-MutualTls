#include "server.h"

#include <iostream>
#include <memory>

int main(int argc, char* argv[]) {
    if(argc != 2) {
        std::cout << "Usage: server <port>" << std::endl;
        return -1;
    }

    std::unique_ptr<server> myServer;
    try {
        myServer = std::make_unique<server>(atoi(argv[1]));
    } catch (...) {
        std::cout << "[Main] Could not initialize server" << std::endl;
        return -1;
    }

    myServer->start();

    std::string input;
    std::cin >> input;

    myServer->stop();

    return 0;
}
