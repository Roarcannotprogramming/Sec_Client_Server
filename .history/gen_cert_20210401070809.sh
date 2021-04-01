# generate keys
openssl genpkey -algorithm ED25519 > CA.key
openssl genpkey -algorithm ED25519 > Client.key
openssl genpkey -algorithm ED25519 > Server.key

# generate req
openssl req -out ca.req -key ca.key -new
openssl req -out server.req -key server.key -new
openssl req -out client.req -key client.key -new
