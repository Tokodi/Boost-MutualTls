#pragma once

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

class client {
  public:
    client(const std::string remoteIp, const std::uint16_t remotePort);

    void send(const char* message, std::size_t messageLength);

  private:
    void connect();
    void initializeTls();
    bool verifyCertificate(bool preverified, boost::asio::ssl::verify_context& ctx);

  private:
    const std::string _remoteIp;
    const std::uint16_t _remotePort = UINT16_MAX;

    bool _isConnected = false;

    std::uint8_t _request[256];
    std::uint8_t _reply[256];

    boost::asio::io_context _ioContext;
    boost::asio::ip::tcp::endpoint _remoteEndpoint;
    boost::asio::ssl::context _sslContext;
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> _sslSocket;
};
