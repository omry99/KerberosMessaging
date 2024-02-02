
class UserClient:
    # TODO: password_hash typing
    def __init__(self, client_id: bytes, user_name: str, password_hash, last_seen: str) -> None:
        self.client_id = client_id
        self.user_name = user_name
        self.password_hash = password_hash
        self.last_seen = last_seen
