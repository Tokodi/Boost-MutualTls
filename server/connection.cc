#include "connection.h"

#include <iostream>

connection::connection(boost::asio::ip::tcp::socket socket, boost::asio::ssl::context& sslContext)
    : _socket(std::move(socket), sslContext) {}

void connection::start() {
    boost::system::error_code error;

    _socket.handshake(boost::asio::ssl::stream_base::server, error);
    if (error) {
        std::cout << "[Connection] ("
                  << _socket.lowest_layer().remote_endpoint()
                  << ") Handshake failed with client ("
                  << error.message() << ")" << std::endl;
        return;
    } else {
        std::cout << "[Connection] ("
                  << _socket.lowest_layer().remote_endpoint()
                  << ") Successfull handshake with client" << std::endl;
        _socket.lowest_layer().non_blocking(true); // NOTE: Set it here, so it works...
    }

    read();
}

void connection::read() {
    _socket.async_read_some(boost::asio::buffer(_buffer, MAX_READ_BYTES),
                      std::bind(&connection::onRead,
                                std::enable_shared_from_this<connection>::shared_from_this(),
                                std::placeholders::_1, std::placeholders::_2));
}

void connection::onRead(boost::system::error_code error, std::size_t bytesReceived) {
    if (!error) {
        std::cout << "[Connection] ("
                  << _socket.lowest_layer().remote_endpoint()
                  << ") Read " << bytesReceived << " bytes: " << std::string(_buffer, bytesReceived) << std::endl;
    } else {
        std::cout << "[Connection] ("
                  << _socket.lowest_layer().remote_endpoint()
                  << ") Read error (" << error.message() << ")" << std::endl;
    }
    read();
}
