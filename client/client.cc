#include "client.h"

#include <iostream>

client::client(const std::string remoteIp, const std::uint16_t remotePort)
    : _remoteIp(remoteIp)
    , _remotePort(remotePort)
    , _remoteEndpoint(boost::asio::ip::address::from_string(remoteIp), remotePort)
    , _sslContext(boost::asio::ssl::context::tlsv12_client)
    , _sslSocket(_ioContext, _sslContext) {
        initializeTls();
        connect();
}

void client::connect() try {
    boost::system::error_code error;
    _sslSocket.lowest_layer().connect(_remoteEndpoint, error);
    if (error) {
        std::cout << "Could not connect to remote endpoint (" << error.message() << ")" << std::endl;
        throw;
    }

    _sslSocket.handshake(boost::asio::ssl::stream_base::client, error);
    if (error) {
        std::cout << "Handshake failed with server (" << error.message() << ")" << std::endl;
        throw;
    }

    std::cout << "Successfully connected to server" << std::endl;
} catch (...) {
    std::cout << "Could not connect to server" << std::endl;
    throw;
}

void client::send(const char* message, std::size_t messageLength) {
    boost::system::error_code error;
    boost::asio::write(_sslSocket, boost::asio::buffer(message, messageLength));
    if (error) {
        std::cout << "Could not write message to stream (" << error.message() << ")" << std::endl;
        return;
    }
}

void client::initializeTls() try {
    boost::system::error_code error;

    _sslContext.set_options(boost::asio::ssl::context::default_workarounds, error);
    if (error) {
        std::cout << "Could not set ssl context options (" << error.message() << ")" << std::endl;
        throw;
    }

    _sslContext.load_verify_file("../certs/ca.pem", error);
    if (error) {
        std::cout << "Could not load CA cert file (" << error.message() << ")" << std::endl;
        throw;
    }

    _sslSocket.set_verify_mode(boost::asio::ssl::verify_peer, error);
    if (error) {
        std::cout << "Could not set verify mode (" << error.message() << ")" << std::endl;
        throw;
    }

    _sslSocket.set_verify_callback(std::bind(&client::verifyCertificate, this, std::placeholders::_1, std::placeholders::_2), error);
    if (error) {
        std::cout << "Could not set verify callback function (" << error.message() << ")" << std::endl;
        throw;
    }
} catch (...) {
    std::cout << "Tls initialization failed" << std::endl;
    throw;
}

bool client::verifyCertificate(bool preverified, boost::asio::ssl::verify_context& ctx) {
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

    return preverified;
}
