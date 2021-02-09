# Create our CA key and cert to self sign certs with          // Clients get this certificate (ca.crt) to check if the server cert is signed with this
openssl req -new -x509 -keyout ca.key -out ca.pem -days 30 -passin "pass:test" -passout "pass:test" <<EOF
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

# Generate server private key
openssl genrsa -out server.key -aes128 -passout pass:test 2048

# Create Certificate Signing Requests for server's private key
openssl req -key server.key -new -out server.csr -passin "pass:test" <<EOF
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

# Create servers certificate by signing it with CA key
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.crt -days 30 -sha256 -passin "pass:test"
