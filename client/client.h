#pragma once

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include <memory>

class client {
  public:
    client(const std::string remoteIp, const std::uint16_t remotePort);
    virtual ~client();

    void send(const char* message, std::size_t messageLength);

  private:
    void initializeTls();
    void connect();

    std::string getPassword() const;
    bool verifyCertificate(bool preverified, boost::asio::ssl::verify_context& ctx);

  private:
    static constexpr std::uint32_t MAX_SUBJECT_SIZE = 256;

    const std::string _remoteIp;
    const std::uint16_t _remotePort = UINT16_MAX;

    boost::asio::io_context _ioContext;
    boost::asio::ip::tcp::endpoint _remoteEndpoint;
    boost::asio::ssl::context _sslContext;
    std::unique_ptr<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>> _sslSocketPtr;
};
