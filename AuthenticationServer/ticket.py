import time
import struct

from server_version import SERVER_VERSION


class Ticket:
    def __init__(self, client_id: bytes, server_id: bytes, iv: bytes, enc_aes_key: bytes, enc_expiration_time: bytes) -> None:
        self.version = SERVER_VERSION
        self.client_id = client_id
        self.server_id = server_id
        self.creation_time = time.time()
        self.ticket_iv = iv
        self.aes_key = enc_aes_key
        self.enc_expiration_time = enc_expiration_time

    def pack(self) -> bytes:
        # The format string for packing the data
        format_string = "=B16s16sd16s48s16s"

        # Pack the data into a binary buffer
        packed_data = struct.pack(
            format_string,
            self.version,
            self.client_id,
            self.server_id,
            self.creation_time,
            self.ticket_iv,
            self.aes_key,
            self.enc_expiration_time
        )

        return packed_data
