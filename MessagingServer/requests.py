import struct

REQUEST_HEADER_LEN = 23
CLIENT_ID_SIZE = 16
VERSION_INDEX = 16
CODE_START_INDEX = 17
CODE_END_INDEX = 19
PAYLOAD_SIZE_START_INDEX = 19
PAYLOAD_SIZE_END_INDEX = 23

USER_NAME_END_INDEX = 255
SERVER_ID_END_INDEX = 16

AUTHENTICATOR_END_INDEX = 64

MSG_END_INDEX = 4
MSG_IV_END_INDEX = 4+16


class Request:
    def __init__(self, data: bytes) -> None:
        self.header: bytes = data[:REQUEST_HEADER_LEN]
        self.payload: bytes = data[REQUEST_HEADER_LEN:]
        self.client_id: bytes = self.header[:CLIENT_ID_SIZE]
        self.version: int = self.header[VERSION_INDEX]
        self.code: int = struct.unpack('h', self.header[CODE_START_INDEX:CODE_END_INDEX])[0]
        self.payload_size: int = struct.unpack('I', self.header[PAYLOAD_SIZE_START_INDEX:PAYLOAD_SIZE_END_INDEX])[0]


def create_request_from_data(data: bytes) -> Request:
    if len(data) < REQUEST_HEADER_LEN:
        raise Exception(f"Data too short to be a response")

    code = struct.unpack('h', data[CODE_START_INDEX:CODE_END_INDEX])[0]
    if code == 1028:
        return SendSymmetricKeyRequest(data)
    elif code == 1029:
        return SendMessageRequest(data)
    else:
        return Request(data)


class SendSymmetricKeyRequest(Request):
    def __init__(self, data: bytes) -> None:
        super().__init__(data=data)
        self.authenticator = self.payload[:AUTHENTICATOR_END_INDEX]
        self.ticket = self.payload[AUTHENTICATOR_END_INDEX:]


class SendMessageRequest(Request):
    def __init__(self, data: bytes) -> None:
        super().__init__(data=data)
        self.msg_size = self.payload[:MSG_END_INDEX]
        self.msg_iv = self.payload[MSG_END_INDEX:MSG_IV_END_INDEX]
        self.msg_content = self.payload[MSG_IV_END_INDEX:]
