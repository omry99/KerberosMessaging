import struct

from server_version import SERVER_VERSION


class Response:
    def __init__(self, code: int, payload: bytes) -> None:
        self.version = SERVER_VERSION
        self.code = code
        self.payload_size = len(payload)
        self.payload = payload

    def pack(self) -> bytes:
        # The format string for packing the data
        format_string = "=BHI{}s".format(self.payload_size)

        # Pack the data into a binary buffer
        packed_data = struct.pack(
            format_string,
            self.version,
            self.code,
            self.payload_size,
            self.payload
        )

        return packed_data


class ReceivedSymmetricKeyResponse(Response):
    def __init__(self) -> None:
        super().__init__(code=1604, payload=b'')


class ReceivedMessageResponse(Response):
    def __init__(self) -> None:
        super().__init__(code=1605, payload=b'')


class GeneralFailureResponse(Response):
    def __init__(self) -> None:
        super().__init__(code=1609, payload=b'')
