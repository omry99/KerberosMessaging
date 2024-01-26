import struct

SERVER_VERSION = 3


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


class RegistrationSuccessResponse(Response):
    def __init__(self, client_id) -> None:
        super().__init__(code=2100, payload=client_id)


class RegistrationFailedResponse(Response):
    def __init__(self) -> None:
        super().__init__(code=2101, payload=b'')


class KeyResponse(Response):
    def __init__(self, client_id: bytes, enc_aes_key: bytes) -> None:
        super().__init__(code=2102, payload=client_id + enc_aes_key)


class ReceivedFileResponse(Response):
    def __init__(self, client_id: bytes, content_size: int, file_name: str, checksum: int) -> None:
        content_size_bytes = struct.pack('I', content_size)
        checksum_bytes = struct.pack('I', checksum)

        padded_file_name_requird_len = 255
        encoded_string = file_name.encode('utf-8')
        padded_file_name = encoded_string.ljust(padded_file_name_requird_len, b'\x00')

        super().__init__(code=2103, payload=client_id + content_size_bytes + padded_file_name + checksum_bytes)


class RequestReceivedResponse(Response):
    def __init__(self, client_id) -> None:
        super().__init__(code=2104, payload=client_id)


class AcceptedReconnectResponse(Response):
    def __init__(self, client_id: bytes, enc_aes_key: bytes) -> None:
        super().__init__(code=2105, payload=client_id + enc_aes_key)


class RejectedReconnectResponse(Response):
    def __init__(self, client_id: bytes) -> None:
        super().__init__(code=2106, payload=client_id)


class GeneralFailureResponse(Response):
    def __init__(self) -> None:
        super().__init__(code=2107, payload=b'')
