#pragma once

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include <thread>

class server {
  public:
    server(const std::uint16_t port);

    void start();
    void stop();

  private:
    void initializeTls();
    void accept();

    std::string getPassword() const;
    bool certVerifyCB(bool preverified, boost::asio::ssl::verify_context& ctx);

  private:
    std::uint16_t _port;
    std::thread _ioContextThread;

    boost::asio::io_context _ioContext;
    boost::asio::ip::tcp::acceptor _acceptor;
    boost::asio::ssl::context _sslContext;
};
