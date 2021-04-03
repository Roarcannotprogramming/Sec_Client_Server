class ProtocalError(Exception):
    pass

class FtpProtocol:
    MAGIC = b'v1me'

    GET_FILE_LIST = 1
    GET_FILE = 2
    POST_FILE = 3
    GET_CWD = 4
    CHANGE_CWD = 5
    MAKE_DIR = 6
    DEL_FILE = 7

    # Max length of single content is 4G
    CONTENT_MAX_LENGTH = 0x100000000

    def __init__(self, request, main_content, version=1):
        if (version != 1):
            raise ProtocalError("Version error")

        if (request not in range(1, 8)):
            raise ProtocalError("Request type error")

        if (not isinstance(main_content), bytes):
            raise ProtocalError("Content type error")

        self.content_len = len(main_content)

        if (self.content_len > self.CONTENT_MAX_LENGTH):
            raise ProtocalError("Content too large")

        self.version = version
        self.request = request
        self.main_content = main_content

    def pack(self):
        p = self.version


print(FtpProtocol(FtpProtocol.GET_FILE, "123123123123").request)
