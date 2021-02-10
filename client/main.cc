#include "client.h"

#include <iostream>
#include <memory>

int main(int argc, char* argv[]) {
    if(argc != 3) {
        std::cout << "Usage: client <host> <port>" << std::endl;
        return -1;
    }

    std::unique_ptr<client> myClient;
    try {
        myClient = std::make_unique<client>(std::string(argv[1]), atoi(argv[2]));
    } catch (...) {
        std::cout << "[Main] Could not initialize client" << std::endl;
        return -1;
    }

    std::string message;
    std::cout << "> ";
    std::cin >> message;

    myClient->send(message.c_str(), message.length());

    return 0;
}
