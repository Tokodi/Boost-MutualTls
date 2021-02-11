#include "client.h"

#include <exception>
#include <iostream>

client::client(const std::string remoteIp, const std::uint16_t remotePort)
    : _remoteIp(remoteIp)
    , _remotePort(remotePort)
    , _remoteEndpoint(boost::asio::ip::address::from_string(remoteIp), remotePort)
    , _sslContext(boost::asio::ssl::context::tlsv12_client) {
        initializeTls();
        connect();
}

client::~client() {
    boost::system::error_code error;
    // NOTE: https://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
    _sslSocketPtr->shutdown(error);
    if (error != boost::asio::error::eof) {
        std::cout << "[Client] Could not shut SSL connection properly" << std::endl;
    }
    _sslSocketPtr->lowest_layer().close();
}

void client::send(const char* message, std::size_t messageLength) {
    boost::system::error_code error;
    boost::asio::write(*_sslSocketPtr, boost::asio::buffer(message, messageLength));
    if (error) {
        std::cout << "[Client] Could not write message to stream (" << error.message() << ")" << std::endl;
        return;
    }
}

void client::initializeTls() try {
    boost::system::error_code error;

    _sslContext.set_options(boost::asio::ssl::context::default_workarounds, error);
    if (error) {
        throw std::runtime_error("Could not set SSL context options (" + error.message() + ")");
    }

    _sslContext.set_password_callback(std::bind(&client::getPassword, this), error);
    if (error) {
        throw std::runtime_error("Could not set password callback (" + error.message() + ")");
    }

    _sslContext.use_certificate_file("../certs/client.crt", boost::asio::ssl::context::pem, error);
    if (error) {
        throw std::runtime_error("Could not set certificate file (" + error.message() + ")");
    }

    _sslContext.use_private_key_file("../certs/client.key", boost::asio::ssl::context::pem, error);
    if (error) {
        throw std::runtime_error("Could not set private key file (" + error.message() + ")");
    }

    _sslContext.load_verify_file("../certs/ca.pem", error);
    if (error) {
        throw std::runtime_error("Could not load CA certificate file (" + error.message() + ")");
    }

    // NOTE: In client mode (sslContext(tlsv12_client)) verify_fail_if_no_peer_cert flag is ignored
    // https://www.openssl.org/docs/man1.0.2/man3/SSL_CTX_set_verify.html
    _sslContext.set_verify_mode(boost::asio::ssl::verify_peer, error);
    if (error) {
        throw std::runtime_error("Could not set verify mode (" + error.message() + ")");
    }

    _sslContext.set_verify_callback(std::bind(&client::verifyCertificate, this, std::placeholders::_1, std::placeholders::_2), error);
    if (error) {
        throw std::runtime_error("Could not set verify callback function (" + error.message() + ")");
    }

    // NOTE: Initialize socket after sslContext is initialized so the settings are applied (does not work otherwise)
    _sslSocketPtr = std::make_unique<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>(_ioContext, _sslContext);
} catch (const std::runtime_error& ex) {
    std::cout << "[Client] TLS initialization error: " << ex.what() << std::endl;
    throw std::runtime_error("TLS initialization error");
}

void client::connect() try {
    boost::system::error_code error;
    _sslSocketPtr->lowest_layer().connect(_remoteEndpoint, error);
    if (error) {
        throw std::runtime_error("Could not connect to remote endpoint (" + error.message() + ")");
    }

    _sslSocketPtr->handshake(boost::asio::ssl::stream_base::client, error);
    if (error) {
        throw std::runtime_error("TLS handshake failure (" + error.message() + ")");
    } else {
        std::cout << "[Client] Successful handshake with server" << std::endl;
    }

    std::cout << "[Client] Successfully connected to server" << std::endl;
} catch (const std::runtime_error& ex) {
    std::cout << "[Client] Could not connect to server: " << ex.what() << std::endl;
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

    char subjectName[MAX_SUBJECT_SIZE];
    X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
    X509_NAME_oneline(X509_get_subject_name(cert), subjectName, MAX_SUBJECT_SIZE);
    std::cout << "[Client] Verifying " << subjectName << std::endl;
    if (preverified)
        std::cout << "[Client] Verified!" << std::endl;
    else
        std::cout << "[Client] Verification failed!" << std::endl;

    return preverified;
}
