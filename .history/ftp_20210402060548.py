import socket, ssl

"""
        0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
0x00   | version  |  request  |    package length (1) 
0x02   | package length
0x04
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

    # fragmentation
    ENABLE_FRAGMENT = 1
    DISABLE_FRAGMENT = 0
    
    # TODO

    # Max length of single content is 16M
    CONTENT_MAX_LENGTH = 0xfffff0

    def __init__(self, request, main_content, version=1):
        if (version != 1):
            raise ProtocalError("Version error")

        if (request not in range(1, 8)):
            raise ProtocalError("Request type error")

        if (not isinstance(main_content), bytes):
            raise ProtocalError("Content type error")

        self.content_len = len(main_content)

        if (self.content_len > self.CONTENT_MAX_LENGTH):
            self.enable_fragment = self.ENABLE_FRAGMENT
        else:
            self.enable_fragment = self.DISABLE_FRAGMENT

        self.version = version
        self.request = request
        self.main_content = main_content

    def pack(self):
        pack_list = []
        if self.enable_fragment:
            contents_list = []
            i = 0
            while 



print(FtpProtocol(FtpProtocol.GET_FILE, "123123123123").request)
