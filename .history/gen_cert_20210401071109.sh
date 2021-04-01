# generate keys
openssl genpkey -algorithm ED25519 > CA.key
openssl genpkey -algorithm ED25519 > Client.key
openssl genpkey -algorithm ED25519 > Server.key

# generate reqs
openssl req -out ca.req -key ca.key -new
openssl req -out server.req -key server.key -new
openssl req -out client.req -key client.key -new

# generate certs
openssl x509 -req -in ca.req -out ca.crt \
            -sha256 -days 5000 -signkey ca.key
openssl x509 -req -in server.req -out server.crt \
            -sha256 -CAcreateserial -days 365 \
            -CA ca.crt -CAkey ca.key
openssl x509 -req -in client.req -out client.crt \
            -sha256 -CAcreateserial -days 265 \
            -CA ca.crt -CAkey ca.key
