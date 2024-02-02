import struct

from encrypted_key import EncryptedKey
from ticket import Ticket
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


class RegistrationSuccessResponse(Response):
    def __init__(self, client_id: bytes) -> None:
        super().__init__(code=1600, payload=client_id)


class RegistrationFailedResponse(Response):
    def __init__(self) -> None:
        super().__init__(code=1601, payload=b'')


class SymmetricKeyResponse(Response):
    def __init__(self, client_id: bytes, enc_aes_key: EncryptedKey, ticket: Ticket) -> None:
        super().__init__(code=1603, payload=client_id + enc_aes_key.pack() + ticket.pack())


class GeneralFailureResponse(Response):
    def __init__(self) -> None:
        super().__init__(code=1609, payload=b'')
