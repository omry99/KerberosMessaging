import struct

REQUEST_HEADER_LEN = 23
CLIENT_ID_SIZE = 16
VERSION_INDEX = 16
CODE_START_INDEX = 17
CODE_END_INDEX = 19
PAYLOAD_SIZE_START_INDEX = 19
PAYLOAD_SIZE_END_INDEX = 23


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
    if code == 1025:
        return RegisterRequest(data)
    elif code == 1026:
        return KeyRequest(data)
    elif code == 1027:
        return ReconnectRequest(data)
    elif code == 1028:
        return FileRequest(data)
    elif code == 1029:
        return ValidCrcRequest(data)
    elif code == 1030:
        return InvalidCrcRequest(data)
    elif code == 1031:
        return LastInvalidCrcRequest(data)
    else:
        return Request(data)


class RegisterRequest(Request):
    def __init__(self, data: bytes) -> None:
        super().__init__(data=data)
        self.name = self.payload.decode()


class KeyRequest(Request):
    def __init__(self, data: bytes) -> None:
        super().__init__(data=data)
        self.name = self.payload[:255].decode()
        self.public_key = self.payload[255:]


class ReconnectRequest(Request):
    def __init__(self, data: bytes) -> None:
        super().__init__(data=data)
        self.name = self.payload[:255].decode()


class FileRequest(Request):
    def __init__(self, data: bytes) -> None:
        super().__init__(data=data)
        self.content_size: int = struct.unpack('I', self.payload[:4])[0]
        self.file_name = self.payload[4:4 + 255].decode()
        self.message_content = self.payload[4 + 255:]


class CrcRequest(Request):
    def __init__(self, data: bytes) -> None:
        super().__init__(data=data)
        self.file_name = self.payload.decode()


class ValidCrcRequest(CrcRequest):
    pass


class InvalidCrcRequest(CrcRequest):
    pass


class LastInvalidCrcRequest(CrcRequest):
    pass
