import rsa
import base64
 
from OpenSSL.crypto import PKey
from OpenSSL.crypto import TYPE_RSA, FILETYPE_PEM, FILETYPE_ASN1
from OpenSSL.crypto import dump_privatekey, dump_publickey


pk = PKey()
pk.generate_key(TYPE_RSA, 512)
pub = dump_publickey(FILETYPE_PEM, pk)
pri = dump_privatekey(FILETYPE_ASN1, pk)
 
pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(pub)
prikey = rsa.PrivateKey.load_pkcs1(pri, 'DER')
 
print(pubkey.save_pkcs1())
print(prikey.save_pkcs1())
 
data = rsa.encrypt(b'hello', pubkey)
data = base64.b64encode(data)
 
print(data)
 
data0 = rsa.decrypt(base64.b64decode(data), prikey)
print(data0)
————————————————
版权声明：本文为CSDN博主「火星Boy」的原创文章，遵循CC 4.0 BY-SA版权协议，转载请附上原文出处链接及本声明。
原文链接：https://blog.csdn.net/huangqingsong_5678/article/details/79358806