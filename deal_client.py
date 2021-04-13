
import OpenSSL, ssl, socket
cmds = ['help', 'cd', 'get', 'post', 'ls', 'pwd', 'rm', 'md', 'exit']

def deal_client(ca, key, cert):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.check_hostname = False
    context.load_cert_chain(certfile=cert, keyfile=key)
    context.load_verify_locations(ca)
    context.verify_mode = ssl.CERT_REQUIRED

    cmd = input("connect: (Format IP_ADDR/HOST_NAME PORT, eg 127.0.0.1 23333) ").split()
    remote_host = cmd[0]
    remote_port = cmd[1]

    with socket.socket() as sock:
        with context.wrap_socket(sock, server_side=False) as ssock:
            ssock.connect((remote_host, remote_port))
            ftp = FtpProtocol(ssock, is_server=False)

    while True:
        cmd = input("$")
        cmd_list = cmd.split()
        print(cmd_list)

deal_client('CA.crt', 'Client.key', 'Client.crt')