import base64
import logging
import uuid
import time

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Hash import SHA256

from requests import *
from responses import *
from responses import Response
from user_client import UserClient

logger = logging.getLogger(__name__)

AES_KEY_LENGTH_IN_BYTES = 32
BUFFER_SIZE = 1024
TEN_MIN_IN_SEC = 600
EXPIRE_TIME_LEN = 8

CLIENTS_DATA_FILE_NAME = "clients"
MSG_SERVER_INFO_FILE_NAME = "msg.info"

MSG_SERVER_ID_LINE_NUM = 2
MSG_SERVER_KEY_LINE_NUM = 3

UUID_FIELD_INDEX = 0
LAST_SEEN_FIELD_INDEX = -1


# TODO: move this?
def encrypt_aes_cbc(data: bytes, key: bytes) -> (bytes, bytes):
    cipher = AES.new(key, AES.MODE_CBC)
    padded_data = pad(data, AES.block_size)
    ciphertext = cipher.encrypt(padded_data)

    return cipher.iv, ciphertext


class RequestHandler:
    def __init__(self, auth_server) -> None:
        self.users_data = auth_server.users_data

    def handle_request(self, request: Request) -> Response | None:
        if isinstance(request, RegisterRequest):
            response = self._handle_register_request(request)
        elif isinstance(request, SymmetricKeyRequest):
            response = self._handle_symmetric_key_request(request)
        else:
            response = GeneralFailureResponse()
        return response

    def _handle_register_request(self, request: RegisterRequest) -> Response:
        user_name = request.name[:request.name.find('\x00')]

        # Check if the user already exists in the records
        for client in self.users_data.values():
            if client.user_name == user_name:
                logger.error(f"User {user_name} already exists in DB")
                return RegistrationFailedResponse()

        # Create a UUID for the user and hash its password
        client_id = uuid.uuid4()
        pass_hash = SHA256.new(request.password.encode()).digest()

        # Add the user to the disk records
        client_entry = f"{client_id.hex}:{user_name}:{pass_hash}:{time.ctime()}\n"
        with open(CLIENTS_DATA_FILE_NAME, 'a') as f:
            f.write(client_entry)

        # Add the user to RAM records
        user_client = UserClient(client_id.bytes, user_name, pass_hash, time.ctime())
        self.users_data[client_id.bytes] = user_client

        logger.info(f"User {user_name} added to the disk and RAM records")

        return RegistrationSuccessResponse(client_id.bytes)

    def _handle_symmetric_key_request(self, request: SymmetricKeyRequest) -> Response:
        # Update the client's LastSeen in the disk records
        with open(CLIENTS_DATA_FILE_NAME, 'r') as file:
            lines = file.readlines()
        for line_num, line in enumerate(lines):
            parts = line.strip().split(':')
            if parts[UUID_FIELD_INDEX] == uuid.UUID(bytes=request.client_id).hex:
                parts[LAST_SEEN_FIELD_INDEX] = time.ctime()
                lines[line_num] = ':'.join(parts) + '\n'
                break

        # Update the client's LastSeen in the RAM records
        self.users_data[request.client_id].last_seen = time.ctime()

        user_name = self.users_data[request.client_id].user_name
        logger.info(f"Updated LastSeen for {user_name} in disk and RAM records")

        # Create an AES key for the client and message server
        aes_key = get_random_bytes(AES_KEY_LENGTH_IN_BYTES)
        # Encrypt the AES key with the client's password hash
        pass_hash = self.users_data[request.client_id].password_hash
        _, nonce_encrypted_with_client_key = encrypt_aes_cbc(data=request.nonce, key=pass_hash)
        encrypted_key_iv, aes_key_encrypted_with_client_key = encrypt_aes_cbc(data=aes_key, key=pass_hash)
        encrypted_aes_key_obj = EncryptedKey(encrypted_key_iv, nonce_encrypted_with_client_key,
                                             aes_key_encrypted_with_client_key)

        with open(MSG_SERVER_INFO_FILE_NAME, 'r') as f:
            lines = f.readlines()
            msg_server_id = uuid.UUID(hex=lines[MSG_SERVER_ID_LINE_NUM].strip())
            b64_enc_msg_server_key = lines[MSG_SERVER_KEY_LINE_NUM]
        msg_server_key = base64.b64decode(b64_enc_msg_server_key)
        # TODO: rename iv. is this even the right iv?
        iv, aes_key_enc_with_msg_server_key = encrypt_aes_cbc(data=aes_key, key=msg_server_key)
        exp_time = int(time.time()) + TEN_MIN_IN_SEC
        _, enc_exp_time = encrypt_aes_cbc(data=exp_time.to_bytes(EXPIRE_TIME_LEN, 'little'), key=msg_server_key)

        ticket_obj = Ticket(request.client_id, msg_server_id.bytes, iv, aes_key_enc_with_msg_server_key,
                            enc_exp_time)

        return SymmetricKeyResponse(request.client_id, encrypted_aes_key_obj, ticket_obj)
