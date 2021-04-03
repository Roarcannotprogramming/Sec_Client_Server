class FtpProtocol:
    magic = b'v1me'

    GET_FILE_LIST = 0
    GET_FILE = 1
    POST_FILE = 2

    def __init__(self, version, ):
        self.version = 1
        self.request = 