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

    def __init__(self, ssock, version=1):
        if version != 1:
            raise ProtocalError("Version error")

        # if not isinstance(ssock, ssl.SSLSocket):
            # raise ProtocalError("Socket type error")

        self.version = version
        self.ssock = ssock
        self.request = 0
        self.hb = False

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

                
        


    def __pack(self):
        p = bytes([(self.version & 7) | (self.hb << 3) | (self.request << 4), 0, 
                   self.path_len & 0xff, (self.path_len >> 8) & 0xff,
                   self.package_len & 0xff, (self.package_len >> 8) & 0xff,
                   (self.package_len >> 16) & 0xff, (self.package_len >> 24) & 0xff,
                   (self.package_len >> 32) & 0xff, (self.package_len >> 40) & 0xff,
                   (self.package_len >> 48) & 0xff, (self.package_len >> 56) & 0xff,
                   0, 0])
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
        print("enable_fragment: ", bool(fragment))
        print("is_last_fragment: ", bool(last_fragment))
        print("fragment_id: ", fragment_id)



FtpProtocol(0).post_file(b'/root/admin/user/pwn', b'CA.key')
