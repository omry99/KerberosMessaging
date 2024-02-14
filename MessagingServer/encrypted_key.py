import struct


class EncryptedKey:
    def __init__(self, enc_key_iv: bytes, encrypted_nonce: bytes, encrpted_aes_key: bytes) -> None:
        self.enc_key_iv = enc_key_iv
        self.encrypted_nonce = encrypted_nonce
        self.encrpted_aes_key = encrpted_aes_key

    def pack(self) -> bytes:
        # The format string for packing the data
        format_string = "=16s16s48s"

        # Pack the data into a binary buffer
        packed_data = struct.pack(
            format_string,
            self.enc_key_iv,
            self.encrypted_nonce,
            self.encrpted_aes_key
        )

        return packed_data
