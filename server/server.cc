#include "server.h"
#include "connection.h"

#include <iostream>
#include <memory>

server::server(const std::uint16_t port)
    : _port(port)
    , _acceptor(_ioContext, boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v6::any(), port))
    , _sslContext(boost::asio::ssl::context::tlsv12_server) {
        initializeTls();
        accept();
        _ioContext.run();
}

void server::initializeTls() {
    boost::system::error_code error;

    _sslContext.set_options(boost::asio::ssl::context::default_workarounds, error);
    if (error) {
        std::cout << "Could not set ssl context options (" << error.message() << ")" << std::endl;
        return;
    }

    _sslContext.set_password_callback(std::bind(&server::getPassword, this), error);
    if (error) {
        std::cout << "Could not set password callback (" << error.message() << ")" << std::endl;
        return;
    }

    _sslContext.use_certificate_file("../certs/server.crt", boost::asio::ssl::context::pem, error);
    if (error) {
        std::cout << "Could not set certificate file (" << error.message() << ")" << std::endl;
        return;
    }

    _sslContext.use_private_key_file("../certs/server.key", boost::asio::ssl::context::pem, error);
    if (error) {
        std::cout << "Could not set private key (" << error.message() << ")" << std::endl;
        return;
    }
}

void server::accept() {
    _acceptor.async_accept(
        [this](const boost::system::error_code& error, boost::asio::ip::tcp::socket socket) {
            if (!error) {
                std::cout << "Client connected (" << socket.remote_endpoint() << ")" << std::endl;
                //socket.non_blocking(true); // If set here, handshake fails with "resource temporarly unavailable"
                std::make_shared<connection>(std::move(socket), _sslContext)->start();
            }
            accept();
        }
    );
}

std::string server::getPassword() const {
    return "test";
}
