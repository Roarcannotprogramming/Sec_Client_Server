# generate keys
openssl genpkey -algorithm ED25519 > CA.key
openssl genpkey -algorithm ED25519 > Client.key
openssl genpkey -algorithm ED25519 > Server.key

# generate reqs
openssl req -out CA.req -key CA.key -new
openssl req -out Server.req -key Server.key -new
openssl req -out Client.req -key Client.key -new

# generate certs
openssl x509 -req -in CA.req -out CA.crt \
             -days 5000 -signkey CA.key
openssl x509 -req -in Server.req -out Server.crt \
             -CAcreateserial -days 365 \
             -CA CA.crt -CAkey CA.key
openssl x509 -req -in Client.req -out Client.crt \
             -CAcreateserial -days 365 \
             -CA CA.crt -CAkey CA.key
