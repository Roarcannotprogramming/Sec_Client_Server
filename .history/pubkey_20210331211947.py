import rsa
import base64
import os
 
from OpenSSL.crypto import PKey
from OpenSSL.crypto import TYPE_RSA, FILETYPE_PEM, FILETYPE_ASN1
from OpenSSL.crypto import dump_privatekey, dump_publickey, load_certificate



pk = PKey()
pk.generate_key(TYPE_RSA, 4096)
pub = dump_publickey(FILETYPE_PEM, pk)
pri = dump_privatekey(FILETYPE_ASN1, pk)
 
pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(pub)
prikey = rsa.PrivateKey.load_pkcs1(pri, 'DER')
 
os.system("openssl req -new -x509 -key privkey.pem -out cacert.pem -days 1095")
print(pubkey.save_pkcs1())
print(prikey.save_pkcs1())
 
data = rsa.encrypt(b'hello', pubkey)
data = base64.b64encode(data)
 
print(data)
 
data0 = rsa.decrypt(base64.b64decode(data), prikey)
print(data0)
