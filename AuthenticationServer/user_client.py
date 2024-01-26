
class UserClient:
    def __init__(self, client_id, user_name, public_key, last_seen, aes_key):
        self.client_id = client_id
        self.user_name = user_name
        self.public_key = public_key
        self.last_seen = last_seen
        self.aes_key = aes_key
