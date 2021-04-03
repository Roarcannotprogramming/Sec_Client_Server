class ProtocalError(Exception):
    pass

class FtpProtocol:
    magic = b'v1me'

    GET_FILE_LIST = 1
    GET_FILE = 2
    POST_FILE = 3
    GET_CWD = 4
    CHANGE_CWD = 5
    MAKE_DIR = 6
    DEL_FILE = 7

    def __init__(self, request, main_context, version=1):
        if (version != 1):
            raise ProtocalError("Version error")

        if (request not in range(1, 8)):
            raise ProtocalError("Request type error")

        if (not isinstance(main_context), bytes):
            raise ProtocalError()

        self.version = version
        self.request = request
        self.main_context = main_context

    def pack(self):
        p = self.version


print(FtpProtocol(FtpProtocol.GET_FILE, "123123123123").request)