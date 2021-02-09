#include "client.h"

#include <iostream>

int main(int argc, char* argv[]) {
    if(argc != 3) {
        std::cout << "Usage: client <host> <port>" << std::endl;
        return 1;
    }

    client myClient(std::string(argv[1]), atoi(argv[2]));

    std::string message;
    std::cout << "> ";
    std::cin >> message;

    myClient.send(message.c_str(), message.length());

    return 0;
}
