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
    # CONTENT_MAX_LENGTH = 0xfffff0
    CONTENT_MAX_LENGTH = 0x4
    HEADER_LEN = 0x8

    def __init__(self, ssock, version=1):
        if version != 1:
            raise ProtocalError("Version error")

        # if not isinstance(ssock, ssl.SSLSocket):
            # raise ProtocalError("Socket type error")

        self.version = version
        self.ssock = ssock
        self.request = 0

    def __feed(self):
        f = self.__feed_gen()
        f.send(None)
        return f

    def __feed_gen(self):
        last_content = b''
        last_content_len = 0
        fragment_id = 0
        while True:
            content ,is_last = yield
            print(content, is_last)
            content_len = len(content)
            content = last_content + content
            content_len = content_len + last_content_len
            while (content_len > self.CONTENT_MAX_LENGTH):
                self.__send(self.__pack(content[:self.CONTENT_MAX_LENGTH], False, self.request, True, fragment_id, False))
                content = content[self.CONTENT_MAX_LENGTH:]
                content_len -= self.CONTENT_MAX_LENGTH
                fragment_id += 1
            if(is_last):
                self.__send(self.__pack(content, False, self.request, True, fragment_id, True))
            else:
                last_content = content
                last_content_len = content_len
            
    
    def get_file_list(self):
        self.request = self.GET_FILE_LIST
        return self.__feed()


            

    def __pack(self, content, hb, request, fragment=False, fragment_id=0, last_fragment=False):
        if hb == True:
            p = bytes([(self.version & 7) | (1 << 3) | (self.request << 4), self.HEADER_LEN & 0xff, (self.HEADER_LEN >> 8) & 0xff, self.HEADER_LEN >> 16, 0, 0, 0, 0])
            return p
            
        package_len = len(content) + self.HEADER_LEN
        p = bytes([(self.version & 7) | (0 << 3) | (self.request << 4), package_len & 0xff, 
                   (package_len >> 8) & 0xff, package_len >> 16, fragment_id & 0xff, 
                   (fragment_id >> 8) & 0xff, (fragment_id >> 16) & 0xff, (fragment_id >> 24) & 0x3f | (last_fragment << 6) | (fragment << 7)])
        print(p)
        p += content
        return p
            

    def __recv(self):
        pass
            

    def __send(self, pack):
        print(pack)
        package_len = pack[1] + (pack[2] << 8) + (pack[3] << 16)
        request = pack[0] >> 4
        fragment = pack[7] >> 7
        last_fragment = (pack[7] >> 6) & 1
        fragment_id = pack[4] + (pack[5] << 8) + (pack[6] << 16) + ((pack[7] & 0x3f) << 24)
        print("package_len: ", package_len)
        print("request: ", request)
        print("enable_fragment: ", bool(fragment))
        print("last_fragment: ", last_fragment)
        print("fragment_id: ", fragment_id)



f = FtpProtocol(0).get_file_list()
f.send((b"/root/admin/user/pwn",1))
