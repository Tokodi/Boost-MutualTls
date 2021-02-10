#include "server.h"
#include "connection.h"

#include <exception>
#include <iostream>
#include <memory>

server::server(const std::uint16_t port)
    : _port(port)
    , _acceptor(_ioContext, boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v6::any(), port))
    , _sslContext(boost::asio::ssl::context::tlsv12_server) {
        initializeTls();
        accept();

        std::cout << "[Server] Initialized succesfully. Waiting for connections..." << std::endl;

        _ioContext.run(); // NOTE: Calling run() blocks
}

void server::initializeTls() try {
    boost::system::error_code error;

    _sslContext.set_options(boost::asio::ssl::context::default_workarounds, error);
    if (error) {
        std::cout << "[Server] Could not set ssl context options (" << error.message() << ")" << std::endl;
        throw std::runtime_error("TLS Config error");
    }

    _sslContext.set_password_callback(std::bind(&server::getPassword, this), error);
    if (error) {
        std::cout << "[Server] Could not set password callback (" << error.message() << ")" << std::endl;
        throw std::runtime_error("TLS Config error");
    }

    _sslContext.use_certificate_file("../certs/server.crt", boost::asio::ssl::context::pem, error);
    if (error) {
        std::cout << "[Server] Could not set certificate file (" << error.message() << ")" << std::endl;
        throw std::runtime_error("TLS Config error");
    }

    _sslContext.use_private_key_file("../certs/server.key", boost::asio::ssl::context::pem, error);
    if (error) {
        std::cout << "[Server] Could not set private key (" << error.message() << ")" << std::endl;
        throw std::runtime_error("TLS Config error");
    }

    _sslContext.set_verify_mode(boost::asio::ssl::verify_peer | boost::asio::ssl::verify_fail_if_no_peer_cert, error);
    if (error) {
        std::cout << "[Server] Could not set verify mode (" << error.message() << ")" << std::endl;
        throw std::runtime_error("TLS Config error");
    }

    _sslContext.set_verify_callback(std::bind(&server::verifyCertificate, this, std::placeholders::_1, std::placeholders::_2), error);
    if (error) {
        std::cout << "[Server] Could not set verify callback function (" << error.message() << ")" << std::endl;
        throw std::runtime_error("TLS Config error");
    }

    _sslContext.load_verify_file("../certs/ca.pem", error);
    if (error) {
        std::cout << "[Server] Could not load CA cert file (" << error.message() << ")" << std::endl;
        throw std::runtime_error("TLS Config error");
    }
} catch (...) {
    std::cout << "[Server] Tls initialization failed" << std::endl;
    throw std::runtime_error("TLS Config error");
}

void server::accept() {
    _acceptor.async_accept(
        [this](const boost::system::error_code& error, boost::asio::ip::tcp::socket socket) {
            if (!error) {
                std::cout << "Client connected (" << socket.remote_endpoint() << ")" << std::endl;
                //socket.non_blocking(true); // NOTE: If set here, handshake fails with "resource temporarly unavailable"
                std::make_shared<connection>(std::move(socket), _sslContext)->start();
            }
            accept();
        }
    );
}

std::string server::getPassword() const {
    return "test";
}

bool server::verifyCertificate(bool preverified, boost::asio::ssl::verify_context& ctx) {
    // The verify callback can be used to check whether the certificate that is
    // being presented is valid for the peer. For example, RFC 2818 describes
    // the steps involved in doing this for HTTPS. Consult the OpenSSL
    // documentation for more details. Note that the callback is called once
    // for each certificate in the certificate chain, starting from the root
    // certificate authority.

    char subjectName[256];
    X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
    X509_NAME_oneline(X509_get_subject_name(cert), subjectName, 256);
    std::cout << "Verifying " << subjectName << std::endl;
    if (preverified)
        std::cout << "Verified!" << std::endl;
    else
        std::cout << "Verification failed!" << std::endl;

    return preverified;
}
