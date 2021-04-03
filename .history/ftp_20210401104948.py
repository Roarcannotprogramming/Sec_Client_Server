class FtpProtocol:
    magic = b'v1me'

    GET_FILE_LIST = 1
    GET_FILE = 2
    POST_FILE = 3
    GET_CWD = 4
    CHANGE_CWD = 5
    MAKE_DIR = 6
    DEL_FILE = 7

    def __init__(self, version = 1, request, main_context):
        self.version = version
        self.request = request
        self.main_context = main_context


print(FtpProtocol())