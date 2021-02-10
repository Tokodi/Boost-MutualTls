#include "connection.h"

#include <iostream>

connection::connection(boost::asio::ip::tcp::socket socket, boost::asio::ssl::context& sslContext)
    : _sslSocket(std::move(socket), sslContext) {}

void connection::start() {
    boost::system::error_code error;

    _sslSocket.handshake(boost::asio::ssl::stream_base::server, error);
    if (error) {
        std::cout << "[Connection] ("
                  << _sslSocket.lowest_layer().remote_endpoint()
                  << ") Handshake failed with client ("
                  << error.message() << ")" << std::endl;
        return;
    } else {
        std::cout << "[Connection] ("
                  << _sslSocket.lowest_layer().remote_endpoint()
                  << ") Successful handshake with client" << std::endl;
        _sslSocket.lowest_layer().non_blocking(true); // NOTE: Set it here, so it works...
    }

    read();
}

void connection::read() {
    _sslSocket.async_read_some(boost::asio::buffer(_buffer, MAX_READ_BYTES),
                      std::bind(&connection::onRead,
                                std::enable_shared_from_this<connection>::shared_from_this(),
                                std::placeholders::_1, std::placeholders::_2));
}

void connection::onRead(boost::system::error_code error, std::size_t bytesReceived) {
    if (!error) {
        std::cout << "[Connection] ("
                  << _sslSocket.lowest_layer().remote_endpoint()
                  << ") Read " << bytesReceived << " bytes: " << std::string(_buffer, bytesReceived) << std::endl;
    } else {
        if (error == boost::asio::error::eof) {
            std::cout << "[Connection] ("
                      << _sslSocket.lowest_layer().remote_endpoint()
                      << ") Client disconnected" << std::endl;
        } else if (error == boost::asio::error::operation_aborted) {
            std::cout << "[Connection] ("
                      << _sslSocket.lowest_layer().remote_endpoint()
                      << ") Operation aborted" << std::endl;
        } else if (error == boost::asio::error::bad_descriptor) {
            std::cout << "[Connection] ("
                      << _sslSocket.lowest_layer().remote_endpoint()
                      << ") Client disconnected abnormally" << std::endl;
        } else  {
            std::cout << "[Connection] ("
                      << _sslSocket.lowest_layer().remote_endpoint()
                      << ") Read error (" << error.message() << ")" << std::endl;
        }

        boost::system::error_code ec;
        _sslSocket.shutdown(ec);
        if (error != boost::asio::error::eof) {
            std::cout << "[Connection] Could not shut SSL connection properly" << std::endl;
        }
        _sslSocket.lowest_layer().close();

        return;
    }
    read();
}
