import socket, ssl

"""
        00  01  02  03  04  05  06  07  08  09  0a  0b  0c  0d  0e  0f  10  11  12  13  14  15  16  17  18  19  1a  1b  1c  1d  1e  1f 
0x00   | version  | hb |    request    |       package length (1)     |                        package length (2)                     |
0x04   |                      fragmentation ID (1)                    |                     fragmentation ID (2)              | l | f |
0x08                     
0x10   
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

    # fragmentation
    ENABLE_FRAGMENT = 1
    DISABLE_FRAGMENT = 0
    
    # TODO

    # Max length of single content is 16M
    CONTENT_MAX_LENGTH = 0xfffff0
    HEADER_LEN = 0x8

    def __init__(self, ssock, version=1):
        if (version != 1):
            raise ProtocalError("Version error")

        if (not isinstance(ssock, ssl.SSLSocket))
            raise ProtocalError("Socket type error")

        self.version = version
        self.ssock = ssock
        self.request = 0

    def feed(self):
        last_content = b''
        cur_content_len = b''
        while True:
            content ,is_last = yield
            content_len = len(content)
            while (self.cur_content_len + content_len > self.CONTENT_MAX_LENGTH):
                self.__send(self.__pack())
            

    def __pack(self, content, hb, request, fragment=False, fragment_id=0, last_fragment=False):
        if hb == True:
            p = bytes([(self.version & 7) | (1 << 3) | (self.request << 4), self.HEADER_LEN & 0xff, (self.HEADER_LEN >> 8) & 0xff, self.HEADER_LEN >> 16, 0, 0, 0, 0])
            return p
            
        package_len = len(content) + self.HEADER_LEN
        p = bytes([(self.version & 7) | (0 << 3) | (self.request << 4), package_len & 0xff, 
                   (package_len >> 8) & 0xff, package_len >> 16, fragment_id & 0xff, 
                   (fragment_id >> 8) & 0xff, (fragment_id >> 16) & 0xff, (fragment_id >> 24) & 0x3f] | (last_fragment << 6) | (fragment << 7))
        p += content
        return p
            
            

    def __send(self, pack):
        pass



print(FtpProtocol(FtpProtocol.GET_FILE, "123123123123").request)
