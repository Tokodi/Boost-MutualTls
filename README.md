# BoostTls

Simple example of server-client communication with TLS, implemented in C++ with Boost::Asio::Ssl.

## Build

In repo root:
```shell
mkdir build
cd build
cmake ..
make -j
```

```shell
cd certs
./generate.sh
```

## Dependency

* boost >= 1.66  
* openssl
