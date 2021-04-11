import socket, ssl, os

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
    CONTENT_MAX_LENGTH = 0xfffff0
    HEADER_LEN = 0x10

    BASE_PATH = '/FILES'

    def __init__(self, ssock, version=1):
        if version != 1:
            raise ProtocalError("Version error")

        # if not isinstance(ssock, ssl.SSLSocket):
            # raise ProtocalError("Socket type error")

        self.version = version
        self.ssock = ssock
        self.request = 0
        self.hb = False
        self.root = b''

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

    def get_file(self, path):
        assert(isinstance(path, bytes))
        self.request = self.GET_FILE
        self.path = path
        self.path_len = len(path)
        self.content = b''
        self.package_len = self.HEADER_LEN + self.path_len
        if self.path_len <= 0 or self.path_len >= 0x10000:
            raise ProtocalError("Path length error")
        self.__send(self.__pack())

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
            with open(file_path, 'rb') as f:
                self.__send(self.__pack())
                while True:
                    s = f.read(self.CONTENT_MAX_LENGTH)
                    if not s:
                        break
                    self.__send(s)

        if file_content:
            self.package_len = self.HEADER_LEN + self.path_len + len(file_content)
            self.content = file_content
            self.__send(self.__pack())

        
    def get_cwd(self):
        self.request = self.GET_CWD
        self.path = b''
        self.path_len = 0
        self.content = b''
        self.package_len = self.HEADER_LEN + self.path_len
        self.__send(self.__pack())

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

    
    def server_deal(self):
        while True:
            header = self.__recv(self.HEADER_LEN)
            self.version , self.hb, self.request, self.path_len, self.package_len = self.__check_format(header)
            if self.hb:
                self.path_len = 0
                self.package_len = self.HEADER_LEN
                self.path = b''
                self.content = b''
                # return self.__send(self.__pack())
                return 0

            if self.request == self.GET_FILE_LIST:
                self.path = self.__recv(self.path_len) 
                self.content = self.__recv(self.package_len - self.HEADER_LEN - self.path_len)
                try:
                    p = self.__os_check_path(self.path)
                    ls = '\n'.join(os.listdir(p))
                    self.content = ls
                    return self.__send(self.__pack())
                except Exception:
                    self.content = 'Invalid path'
                    self.request = self.TRANS_ERROR
                    return self.__send(self.__pack())

            if self.request == self.GET_FILE:
                self.path = self.__recv(self.path_len)
                self.content = self.__recv(self.package_len - self.HEADER_LEN - self.path_len)
                try:
                    p = self.__os_check_path(self.path)
                    with open(p, 'rb') as f:
                        while True:
                            s = f.read(self.CONTENT_MAX_LENGTH)
                            if not s:
                                break
                            self.content = s
                            self.__send(self.__pack())
                except Exception:
                    self.content = 'Invalid path'
                    self.request = self.TRANS_ERROR
                    return self.__send(self.__pack())
        

    def __os_check_path(self, path):
        p = os.path.normpath(path)
        if p.startswith('..'):
            ProtocalError('Invalid path')
        return os.path.join(self.BASE_PATH, self.root, p)


                
    def __check_format(self, pack):
        version = pack[0] & 7
        hb = (pack[0] >> 3) & 1
        request = pack[0] >> 4
        path_len = pack[2] + (pack[3] << 8)
        package_len = pack[4] + (pack[5] << 8) + (pack[6] << 16) + (pack[7] << 24) + (pack[8] << 32) + (pack[9] << 40) + (pack[10] << 48) + (pack[11] << 56)
        if version != 1:
            raise ProtocalError("Version error")
        if request not in range(1, 8):
            raise ProtocalError("Request error")
        if path_len < 0:
            raise ProtocalError("Path error")
        if package_len < 0:
            raise ProtocalError("Package error")
        return version, hb, request, path_len, package_len


    def __pack(self):
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
        print(pack)
        path_len = pack[2] + (pack[3] << 8)
        package_len = pack[4] + (pack[5] << 8) + (pack[6] << 16) + (pack[7] << 24) + (pack[8] << 32) + (pack[9] << 40) + (pack[10] << 48) + (pack[11] << 56)
        request = pack[0] >> 4
        print("package_len: ", package_len)
        print("path_len: ", path_len)
        print("content_len: ", package_len - path_len - self.HEADER_LEN)
        print("path: ", pack[self.HEADER_LEN: self.HEADER_LEN + path_len])
        print("content: ", pack[self.HEADER_LEN + path_len:])
    
    def __recv(self, length):
        s = b''
        return s



FtpProtocol(0).post_file(b'/root/admin/user/pwn', b'CA.key')
