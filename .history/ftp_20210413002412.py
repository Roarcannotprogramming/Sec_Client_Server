import socket, ssl, os, sys, re, shutil, select, threading, OpenSSL

"""
        00  01  02  03  04  05  06  07  08  09  0a  0b  0c  0d  0e  0f  10  11  12  13  14  15  16  17  18  19  1a  1b  1c  1d  1e  1f 
0x00   | version  | hb |    request    |            unused            |                            path length                        |
0x04   |                      package length (1)                      |                        package length (2)                     |
0x08   |                      package length (3)                      |                        package length (4)                     |    
0x0c   |                         unused                               |                            unused                             |

"""

class ProtocalError(Exception):
    pass

class FtpProtocol:
    MAGIC = b'v1me'

    # Requests
    GET_FILE_LIST = 1
    GET_FILE = 2
    POST_FILE = 3
    GET_CWD = 4
    CHANGE_CWD = 5
    MAKE_DIR = 6
    DEL_FILE = 7
    TRANS_ERROR = 8

    # Max length of single content is 16M
    # CONTENT_MAX_LENGTH = 0xfffff0
    CONTENT_MAX_LENGTH = 0xf0
    HEADER_LEN = 0x10

    BASE_PATH = b'/home/v1me/project/Sec_Client_Server'

    def __init__(self, ssock, is_server, version=1):
        if version != 1:
            raise ProtocalError("Version error")

        if not isinstance(ssock, ssl.SSLSocket):
            raise ProtocalError("Socket type error")

        self.version = version
        self.ssock = ssock
        self.request = 0
        self.hb = False
        self.root = b''
        self.current_recv = b''
        rstr = r"[\/\\\:\*\?\"\<\>\|]".encode()  # '/ \ : * ? " < > |'
        self.name = ssock.getpeercert()['subject'][4][0][1].encode()
        print(self.ssock)
        for i in rstr:
            if i in self.name:
                raise ProtocalError("Invalid common name")
        self.is_server = is_server
        if self.is_server:
            self.root = self.name
            p = os.path.join(self.BASE_PATH, self.root)
            if not os.path.isdir(p):
                os.makedirs(p)

    def get_file_list(self, path):
        assert(isinstance(path, bytes))
        self.request = self.GET_FILE_LIST
        self.path = path
        self.path_len = len(path)
        self.content = b''
        self.package_len = self.HEADER_LEN + self.path_len
        if self.path_len <= 0 or self.path_len >= 0x10000:
            raise ProtocalError("Path length error")
        self.__send(self.__pack())

        header = self.__recv(self.HEADER_LEN)
        self.version , self.hb, self.request, self.path_len, self.package_len = self.__check_format(header)
        print(self.package_len)
        s = self.__recv(self.package_len - self.HEADER_LEN)
        print(s[:self.path_len], s[self.path_len:])


    def get_file(self, path, local_path):
        assert(isinstance(path, bytes))
        self.request = self.GET_FILE
        self.path = path
        self.path_len = len(path)
        self.content = b''
        self.package_len = self.HEADER_LEN + self.path_len
        if self.path_len <= 0 or self.path_len >= 0x10000:
            raise ProtocalError("Path length error")
        self.__send(self.__pack())

        header = self.__recv(self.HEADER_LEN)
        self.version , self.hb, self.request, self.path_len, self.package_len = self.__check_format(header)
        print(self.package_len)
        s = self.__recv(self.package_len - self.HEADER_LEN)
        print(s[:self.path_len], s[self.path_len:])
        with open(local_path, 'wb+') as f:
            f.write(s[self.path_len:])


    def post_file(self, path, file_path = None, file_content = None):
        if (file_path and file_content):
            raise ProtocalError("File must be unique")
        assert(isinstance(path, bytes))

        self.request = self.POST_FILE
        self.path = path
        self.path_len = len(path)
        if self.path_len <= 0 or self.path_len >= 0x10000:
            raise ProtocalError("Path length error")

        if file_path:
            self.package_len = self.HEADER_LEN + self.path_len + os.path.getsize(file_path)
            self.content = b''
            print(self.package_len)
            with open(file_path, 'rb') as f:
                self.__send(self.__pack(check_single=False))
                while True:
                    s = f.read(self.CONTENT_MAX_LENGTH)
                    if not s:
                        break
                    self.__send(s)

        if file_content:
            self.package_len = self.HEADER_LEN + self.path_len + len(file_content)
            self.content = file_content
            self.__send(self.__pack())


        header = self.__recv(self.HEADER_LEN)
        self.version , self.hb, self.request, self.path_len, self.package_len = self.__check_format(header)
        print(self.package_len)
        s = self.__recv(self.package_len - self.HEADER_LEN)
        print(s[:self.path_len], s[self.path_len:])

        
    def get_cwd(self):
        self.request = self.GET_CWD
        self.path = b''
        self.path_len = 0
        self.content = b''
        self.package_len = self.HEADER_LEN + self.path_len
        self.__send(self.__pack())

        header = self.__recv(self.HEADER_LEN)
        self.version , self.hb, self.request, self.path_len, self.package_len = self.__check_format(header)
        # print(self.package_len)
        s = self.__recv(self.package_len - self.HEADER_LEN)
        # print(s[:self.path_len], s[self.path_len:])
        return s[self.path_len:]


    def change_cwd(self, path):
        assert(isinstance(path, bytes))
        self.request = self.CHANGE_CWD
        self.path = path
        self.path_len = len(path)
        self.content = b''
        self.package_len = self.HEADER_LEN + self.path_len
        if self.path_len <= 0 or self.path_len >= 0x10000:
            raise ProtocalError("Path length error")
        self.__send(self.__pack())

        header = self.__recv(self.HEADER_LEN)
        self.version , self.hb, self.request, self.path_len, self.package_len = self.__check_format(header)
        print(self.package_len)
        s = self.__recv(self.package_len - self.HEADER_LEN)
        print(s[:self.path_len], s[self.path_len:])


    def make_dir(self, path):
        assert(isinstance(path, bytes))
        self.request = self.MAKE_DIR
        self.path = path
        self.path_len = len(path)
        self.content = b''
        self.package_len = self.HEADER_LEN + self.path_len
        if self.path_len <= 0 or self.path_len >= 0x10000:
            raise ProtocalError("Path length error")
        self.__send(self.__pack())

        header = self.__recv(self.HEADER_LEN)
        self.version , self.hb, self.request, self.path_len, self.package_len = self.__check_format(header)
        print(self.package_len)
        s = self.__recv(self.package_len - self.HEADER_LEN)
        print(s[:self.path_len], s[self.path_len:])


    def del_file(self, path):
        assert(isinstance(path, bytes))
        self.request = self.DEL_FILE
        self.path = path
        self.path_len = len(path)
        self.content = b''
        self.package_len = self.HEADER_LEN + self.path_len
        if self.path_len <= 0 or self.path_len >= 0x10000:
            raise ProtocalError("Path length error")
        self.__send(self.__pack())

        header = self.__recv(self.HEADER_LEN)
        self.version , self.hb, self.request, self.path_len, self.package_len = self.__check_format(header)
        print(self.package_len)
        s = self.__recv(self.package_len - self.HEADER_LEN)
        print(s[:self.path_len], s[self.path_len:])

    
    def server_deal(self):
        print(self.ssock)
        while True:
            header = self.__recv(self.HEADER_LEN)
            self.version , self.hb, self.request, self.path_len, self.package_len = self.__check_format(header)
            print(self.version, self.hb, self.request, self.path_len, self.package_len)
            if self.hb:
                self.path_len = 0
                self.package_len = self.HEADER_LEN
                self.path = b''
                self.content = b''
                continue

            if self.request == self.GET_FILE_LIST:
                self.path = self.__recv(self.path_len) 
                self.content = self.__recv(self.package_len - self.HEADER_LEN - self.path_len)
                try:
                    p = self.__os_check_path(self.path)
                    ls = '\n'.join(map(lambda x: x.decode('utf-8'), os.listdir(p)))
                    self.content = ls.encode()
                    self.__send(self.__pack())
                    continue

                except Exception:
                    self.content = b'Invalid path'
                    self.request = self.TRANS_ERROR
                    self.__send(self.__pack())
                    continue

            if self.request == self.GET_FILE:
                self.path = self.__recv(self.path_len)
                self.content = self.__recv(self.package_len - self.HEADER_LEN - self.path_len)
                # print(self.path, self.content)
                try:
                    p = self.__os_check_path(self.path)
                    with open(p, 'rb') as f:
                        self.path_len = len(self.path)
                        self.package_len = self.HEADER_LEN + self.path_len + os.path.getsize(p)
                        # print(self.package_len)
                        self.__send(self.__pack(False))
                        while True:
                            s = f.read(self.CONTENT_MAX_LENGTH)
                            if not s:
                                break
                            self.content = s
                            self.__send(s)
                    continue

                except Exception:
                    self.content = b'Invalid path'
                    self.request = self.TRANS_ERROR
                    self.__send(self.__pack())
                    continue

            if self.request == self.POST_FILE:
                self.path = self.__recv(self.path_len)
                self.content = self.__recv(self.package_len - self.HEADER_LEN - self.path_len)
                # print(self.content)
                try:
                    p = self.__os_check_path(self.path)
                    with open(p, 'wb+') as f:
                        f.write(self.content)
                    self.content = b'Done'
                    self.__send(self.__pack())
                    continue
                except Exception:
                    self.content = b'Invalid path'
                    self.request = self.TRANS_ERROR
                    self.__send(self.__pack())
                    continue

            if self.request == self.GET_CWD:
                self.path = self.__recv(self.path_len)
                self.content = self.__recv(self.package_len - self.HEADER_LEN - self.path_len)
                self.content = self.root
                self.__send(self.__pack())
                continue
                

            if self.request == self.CHANGE_CWD:
                self.path = self.__recv(self.path_len)
                self.content = self.__recv(self.package_len - self.HEADER_LEN - self.path_len)
                try:
                    p = self.__os_check_path(self.path)
                    if os.path.isdir(p):
                        self.content = os.path.relpath(p, self.BASE_PATH)
                        self.root = os.path.relpath(p, self.BASE_PATH)
                        # print(self.name)
                    else:
                        raise ProtocalError("Invalid path")
                    self.__send(self.__pack())
                    continue
                except Exception:
                    self.content = b'Invalid path'
                    self.request = self.TRANS_ERROR
                    self.__send(self.__pack())
                    continue

            if self.request == self.MAKE_DIR:
                self.path = self.__recv(self.path_len)
                self.content = self.__recv(self.package_len - self.HEADER_LEN - self.path_len)
                try:
                    p = self.__os_check_path(self.path)
                    if os.path.exists(p):
                        raise ProtocalError("Invalid path")
                    os.makedirs(p)
                    self.content = b'Done'
                    self.__send(self.__pack())
                    continue
                except Exception:
                        self.content = b'Invalid path'
                        self.request = self.TRANS_ERROR
                        self.__send(self.__pack())
                        continue
            
            if self.request == self.DEL_FILE:
                self.path = self.__recv(self.path_len)
                self.content = self.__recv(self.package_len - self.HEADER_LEN - self.path_len)

                p = self.__os_check_path(self.path)
                if not os.path.exists(p):
                    raise ProtocalError("Invalid path")
                if os.path.isdir(p):
                    shutil.rmtree(p)
                elif os.path.isfile(p):
                    os.remove(p)
                self.content = b'Done'
                self.__send(self.__pack())
                continue

 
            
        

    def __os_check_path(self, path):
        p = os.path.normpath(path)
        if p.decode('utf-8').startswith('..') or p.decode('utf-8').startswith('/'):
            ProtocalError('Invalid path')
        print(self.BASE_PATH, self.root, p)
        p1 = os.path.join(self.BASE_PATH, self.root, p)
        print(p1)
        return p1


                
    def __check_format(self, pack):
        version = pack[0] & 7
        hb = (pack[0] >> 3) & 1
        request = pack[0] >> 4
        path_len = pack[2] + (pack[3] << 8)
        package_len = pack[4] + (pack[5] << 8) + (pack[6] << 16) + (pack[7] << 24) + (pack[8] << 32) + (pack[9] << 40) + (pack[10] << 48) + (pack[11] << 56)
        if version != 1:
            raise ProtocalError("Version error")
        if request not in range(1, 9):
            # print(request)
            raise ProtocalError("Request error")
        if path_len < 0:
            raise ProtocalError("Path error")
        if package_len < 0:
            raise ProtocalError("Package error")
        return version, hb, request, path_len, package_len


    def __pack(self, check_single=True):
        if check_single:
            self.path_len = len(self.path)
            self.package_len = self.HEADER_LEN + self.path_len + len(self.content)
        p = bytes([(self.version & 7) | (self.hb << 3) | (self.request << 4), 0, 
                   self.path_len & 0xff, (self.path_len >> 8) & 0xff,
                   self.package_len & 0xff, (self.package_len >> 8) & 0xff,
                   (self.package_len >> 16) & 0xff, (self.package_len >> 24) & 0xff,
                   (self.package_len >> 32) & 0xff, (self.package_len >> 40) & 0xff,
                   (self.package_len >> 48) & 0xff, (self.package_len >> 56) & 0xff,
                   0, 0, 0, 0])
        p += self.path
        p += self.content
        return p
           

    def __send(self, pack):
        self.ssock.send(pack)
        return 1
    
    def __recv(self, length):
        current_len = len(self.current_recv)
        while True:
            s = self.ssock.recv(length - current_len)
            # print(s, length, len(s))
            current_len += len(s)
            self.current_recv = self.current_recv + s
            # print(1)
            if current_len == length:
                current_len = 0
                ss = self.current_recv
                self.current_recv = b''
                # print(1)
                return ss
            if current_len > length:
                raise ProtocalError("Length error")




port__ = 5671

# client

cmds = ['help', 'cd', 'get', 'post', 'ls', 'pwd', 'rm', 'md', 'exit']

def usage():
    pass

def deal_client(ca, key, cert):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.check_hostname = False
    context.load_cert_chain(certfile=cert, keyfile=key)
    context.load_verify_locations(ca)
    context.verify_mode = ssl.CERT_REQUIRED

    with open(cert, 'rb') as f:
        cert_text = f.read()
        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_text)
        cn = cert.get_subject().get_components()[4][1]
        issue_cn = cert.get_issuer().get_components()[4][1]

    print('Welcome, %s@%s!' % (cn.decode(), issue_cn.decode()))
    cmd = input("connect: (Format IP_ADDR/HOST_NAME PORT, eg 127.0.0.1 23333) ").split()
    remote_host = cmd[0]
    remote_port = int(cmd[1])

    with socket.socket() as sock:
        with context.wrap_socket(sock, server_side=False) as ssock:
            ssock.connect((remote_host, remote_port))
            ftp = FtpProtocol(ssock, is_server=False)

            cwd = ftp.get_cwd()
            while True:
                cmd = input("%s@%s:%s$ " % (cn.decode(), issue_cn.decode(), cwd.decode())).split()
                if cmd[0] not in cmds:
                    print("Command %s not found" % cmd[0])
                    usage()
                    return
                if cmd[0] == 'help':
                    usage()
                    return
                if cmd[0] == 'cd':
                    pass

                

def client():
    CA_FILE = "CA.crt"
    KEY_FILE = "Client.key"
    CERT_FILE = "Client.crt"

    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.check_hostname = False
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    context.load_verify_locations(CA_FILE)
    context.verify_mode = ssl.CERT_REQUIRED

    with socket.socket() as sock:
        with context.wrap_socket(sock, server_side=False) as ssock:
            ssock.connect(('127.0.0.1', port__))
            ftp = FtpProtocol(ssock, is_server=False)
            ftp.get_file_list(b'.')
            ftp.post_file(b'new_new_ca.crt', file_path=b'CA.crt')
            ftp.get_file(b'new_new_ca.crt', local_path='geted_file')
            ftp.get_cwd()
            ftp.change_cwd(b'abc')
            ftp.get_cwd()
            ftp.post_file(b'new_new_ca.crt', file_path=b'CA.crt')
            ftp.make_dir(b'fff')
            ftp.del_file(b'new_new_ca.crt')
            # ftp.del_file(b'flag.txt')
            ssock.close()

def server_deal(ftp):
    try:
        ftp.server_deal()
    except Exception:
        import traceback
        print(traceback.format_exc())


def server():
    CA_FILE = "CA.crt"
    KEY_FILE = "Server.key"
    CERT_FILE = "Server.crt"
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    context.load_verify_locations(CA_FILE)
    context.verify_mode = ssl.CERT_REQUIRED

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        with context.wrap_socket(sock, server_side=True) as ssock:
            ssock.bind(('127.0.0.1', port__))
            ssock.setblocking(False)
            ssock.listen(20)

            inputs = [ssock,]
            while True:
                r_list, _, _ = select.select(inputs, [], [])
                for event in r_list:
                    if event == ssock:
                        client_socket, addr = ssock.accept()
                        inputs.append(client_socket)
                    else:
                        # print(event)
                        inputs.remove(event)
                        ftp = FtpProtocol(event, is_server=True)
                        # print(ftp.ssock)
                        threading.Thread(target=server_deal, args=(ftp,)).start()
                        # event.close()

                """
                client_socket, addr = ssock.accept()
                ftp = FtpProtocol(client_socket, is_server=True)
                ftp.server_deal()
                # msg = f"yes , you have client_socketect with server.\r\n".encode("utf-8")
                client_socket.close()
                """

if __name__ == "__main__":
    if sys.argv[1] == "server":
        server()
    if sys.argv[1] == "client":
        deal_client('CA.crt', 'Client.key', 'Client.crt')