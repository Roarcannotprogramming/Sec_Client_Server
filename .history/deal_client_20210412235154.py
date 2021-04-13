
import OpenSSL, ssl, socket
cmds = ['help', 'cd', 'get', 'post', 'ls', 'pwd', 'rm', 'md', 'conn']

def deal_client(ca, key, cert):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.check_hostname = False
    context.load_cert_chain(certfile=cert, keyfile=key)
    context.load_verify_locations(ca)
    context.verify_mode = ssl.CERT_REQUIRED


    while True:
        cmd = input("$")
        cmd_list = cmd.split()
        print(cmd_list)

deal_client('CA.crt', 'Client.key', 'Client.crt')