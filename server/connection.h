#pragma once

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

class connection : public std::enable_shared_from_this<connection> {
  public:
    connection(boost::asio::ip::tcp::socket socket, boost::asio::ssl::context& sslContext);

    void start();

  private:
    void read();
    void onRead(boost::system::error_code error, std::size_t bytesReceived);

  private:
    char _buffer[1024];
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> _socket;
};
