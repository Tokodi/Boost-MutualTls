
########################################################################################################################
#                                               Certificate Authority                                                  #
########################################################################################################################

# Create our CA key and cert to self sign certs with
openssl req -new -x509 -keyout ca.key -out ca.pem -days 30 -passout pass:caPass <<EOF
CA
TestCA
TestCityCA
TestCompCA
TestProjCA
TestHostCA
testCA@mail.com
.
.
EOF

########################################################################################################################
#                                                       Client                                                         #
########################################################################################################################

# Generate client private key
openssl genrsa -out client.key -aes128 -passout pass:clientKeyPass 2048

# Create Certificate Signing Requests for client's private key
openssl req -key client.key -new -out client.csr -passin pass:clientKeyPass <<EOF
CL
TestCL
TestCityCL
TestCompCL
TestProjCL
TestHostCL
testCL@mail.com
.
.
EOF

# Create client's certificate by signing it with CA key
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out client.crt -days 30 -sha256 -passin pass:caPass

########################################################################################################################
#                                                       Server                                                         #
########################################################################################################################

# Generate server private key
openssl genrsa -out server.key -aes128 -passout pass:serverKeyPass 2048

# Create Certificate Signing Requests for server's private key
openssl req -key server.key -new -out server.csr -passin pass:serverKeyPass <<EOF
SV
TestSV
TestCitySV
TestCompSV
TestProjSV
TestHostSV
testSV@mail.com
.
.
EOF

# Create server's certificate by signing it with CA key
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.crt -days 30 -sha256 -passin pass:caPass
