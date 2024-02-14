
class Authenticator:
    def __init__(self, data: bytes) -> None:
        # TODO: magic
        self.authenticator_iv = data[:16]
        self.version = data[16:33]
        self.client_id = data[33:33+32]
        self.server_id = data[33+32:33+32+32]
        self.creation_time = data[33+32+32:]
