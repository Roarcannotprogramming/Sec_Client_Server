
import OpenSSL, ssl, socket
cmds = ['help', 'cd', 'get', 'post', 'ls', 'pwd', 'rm', 'md', 'conn']

def deal_client(ca, key, cert):

    while True:
        cmd = input("$")
        cmd_list = cmd.split()
        print(cmd_list)

deal_client()