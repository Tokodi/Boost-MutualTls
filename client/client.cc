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

void client::send(const char* message, std::size_t messageLength) {
    boost::system::error_code error;
    boost::asio::write(_sslSocket, boost::asio::buffer(message, messageLength));
    if (error) {
        std::cout << "[Client] Could not write message to stream (" << error.message() << ")" << std::endl;
        return;
    }
}

void client::initializeTls() try {
    boost::system::error_code error;

    _sslContext.set_options(boost::asio::ssl::context::default_workarounds, error);
    if (error) {
        std::cout << "[Client] Could not set ssl context options (" << error.message() << ")" << std::endl;
        throw std::runtime_error("TLS Config error");
    }

    _sslContext.set_password_callback(std::bind(&client::getPassword, this), error);
    if (error) {
        std::cout << "[Client] Could not set password callback (" << error.message() << ")" << std::endl;
        throw std::runtime_error("TLS Config error");
    }

    _sslContext.use_certificate_file("../certs/client.crt", boost::asio::ssl::context::pem, error);
    if (error) {
        std::cout << "[Client] Could not set certificate file (" << error.message() << ")" << std::endl;
        throw std::runtime_error("TLS Config error");
    }

    _sslContext.use_private_key_file("../certs/client.key", boost::asio::ssl::context::pem, error);
    if (error) {
        std::cout << "[Client] Could not set private key (" << error.message() << ")" << std::endl;
        throw std::runtime_error("TLS Config error");
    }

    // NOTE: In client mode (sslContext(tlsv12_client)) verify_fail_if_no_peer_cert flag is ignored
    // https://www.openssl.org/docs/man1.0.2/man3/SSL_CTX_set_verify.html
    _sslContext.set_verify_mode(boost::asio::ssl::verify_peer, error);
    if (error) {
        std::cout << "[Client] Could not set verify mode (" << error.message() << ")" << std::endl;
        throw std::runtime_error("TLS Config error");
    }

    _sslContext.set_verify_callback(std::bind(&client::verifyCertificate, this, std::placeholders::_1, std::placeholders::_2), error);
    if (error) {
        std::cout << "[Client] Could not set verify callback function (" << error.message() << ")" << std::endl;
        throw std::runtime_error("TLS Config error");
    }

    _sslContext.load_verify_file("../certs/ca.pem", error);
    if (error) {
        std::cout << "[Client] Could not load CA cert file (" << error.message() << ")" << std::endl;
        throw std::runtime_error("TLS Config error");
    }

} catch (...) {
    std::cout << "[Client] Tls initialization failed" << std::endl;
    throw std::runtime_error("TLS Config error");
}

void client::connect() try {
    boost::system::error_code error;
    _sslSocket.lowest_layer().connect(_remoteEndpoint, error);
    if (error) {
        std::cout << "[Client] Could not connect to remote endpoint (" << error.message() << ")" << std::endl;
        throw std::runtime_error("Connect error");
    }

    _sslSocket.handshake(boost::asio::ssl::stream_base::client, error);
    if (error) {
        std::cout << "[Client] Handshake failed with server (" << error.message() << ")" << std::endl;
        throw std::runtime_error("Connect error");
    } else {
        std::cout << "[Client] Successful handshake with server" << std::endl;
    }

    std::cout << "[Client] Successfully connected to server" << std::endl;
} catch (...) {
    std::cout << "[Client] Could not connect to server" << std::endl;
    throw std::runtime_error("Connect error");
}

std::string client::getPassword() const {
    return "clientKeyPass";
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
    std::cout << "[Client] Verifying " << subjectName << std::endl;
    if (preverified)
        std::cout << "[Client] Verified!" << std::endl;
    else
        std::cout << "[Client] Verification failed!" << std::endl;

    return preverified;
}
