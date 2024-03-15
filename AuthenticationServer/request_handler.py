import logging
import uuid
import time
import struct

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Hash import SHA256

from requests import *
from responses import *
from responses import Response
from user_client import UserClient
from server_version import SERVER_VERSION_BYTES

logger = logging.getLogger(__name__)

AES_KEY_LENGTH_IN_BYTES = 32
TEN_MIN_IN_SEC = 600

CLIENTS_DATA_FILE_NAME = "clients"

UUID_FIELD_INDEX = 0
LAST_SEEN_FIELD_INDEX = -1


class AuthRequestHandler:
    def __init__(self, auth_server) -> None:
        self.users_data = auth_server.users_data
        self.msg_server_id = auth_server.msg_server_id
        self.msg_server_key = auth_server.msg_server_key

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
        logger.info(f"Got a registeration request from {user_name}")

        # Check if the user already exists in the records
        for client in self.users_data.values():
            if client.user_name == user_name:
                logger.error(f"User {user_name} already exists in DB")
                self._update_client_last_seen(client.client_id)
                return RegistrationFailedResponse()

        # Create a UUID for the user and hash its password
        client_id = uuid.uuid4()
        pass_hash = SHA256.new(request.password.encode()).digest()

        # Add the user to the disk records
        client_entry = f"{client_id.hex}:{user_name}:{pass_hash.hex()}:{time.time()}\n"
        with open(CLIENTS_DATA_FILE_NAME, 'a') as f:
            f.write(client_entry)

        # Add the user to RAM records
        user_client = UserClient(client_id.bytes, user_name, pass_hash.hex(), time.time())
        self.users_data[client_id.bytes] = user_client

        logger.info(f"User {user_name} added to the disk and RAM records")

        return RegistrationSuccessResponse(client_id.bytes)

    def _handle_symmetric_key_request(self, request: SymmetricKeyRequest) -> Response:
        user_name = self.users_data[request.client_id].user_name
        logger.info(f"Got a symmetric key request from {user_name}")

        self._update_client_last_seen(request.client_id)

        # Create an AES key for the client and message server
        aes_key = get_random_bytes(AES_KEY_LENGTH_IN_BYTES)

        # Encrypt the AES key with the client's password hash
        encrypted_key = self._encrypt_key(request.client_id, request.nonce, aes_key)

        ticket = self._generate_ticket(request.client_id, self.msg_server_id.bytes, aes_key)

        return SymmetricKeyResponse(request.client_id, encrypted_key, ticket)

    def _generate_ticket(self, client_id: bytes, server_id: bytes, aes_key: bytes) -> bytes:
        creation_time = int(time.time())
        creation_time_bytes = struct.pack("=d", creation_time)
        exp_time = creation_time + TEN_MIN_IN_SEC
        exp_time_bytes = struct.pack("=d", exp_time)

        ticket_data_to_encrypt = aes_key + exp_time_bytes
        ticket_iv, encrypted_ticket_data = self._encrypt_aes_cbc(data=ticket_data_to_encrypt, key=self.msg_server_key)

        ticket = SERVER_VERSION_BYTES + client_id + server_id + creation_time_bytes + ticket_iv + encrypted_ticket_data

        return ticket

    def _encrypt_key(self, client_id: bytes, nonce: bytes, aes_key: bytes) -> bytes:
        pass_hash = bytes.fromhex(self.users_data[client_id].password_hash)
        key_data_to_encrypt = nonce + aes_key
        encrypted_key_iv, encrypted_key_data = self._encrypt_aes_cbc(data=key_data_to_encrypt, key=pass_hash)
        encrypted_key = encrypted_key_iv + encrypted_key_data

        return encrypted_key

    def _update_client_last_seen(self, client_id: bytes):
        # Update the client's LastSeen in the disk records
        with open(CLIENTS_DATA_FILE_NAME, 'r') as file:
            lines = file.readlines()
        for line_num, line in enumerate(lines):
            parts = line.strip().split(':')
            if parts[UUID_FIELD_INDEX] == uuid.UUID(bytes=client_id).hex:
                parts[LAST_SEEN_FIELD_INDEX] = time.time()
                lines[line_num] = ':'.join(parts) + '\n'
                break
        with open(CLIENTS_DATA_FILE_NAME, 'w') as file:
            file.writelines(lines)

        # Update the client's LastSeen in the RAM records
        self.users_data[client_id].last_seen = time.time()

        user_name = self.users_data[client_id].user_name
        logger.info(f"Updated LastSeen for {user_name} in disk and RAM records")

    @staticmethod
    def _encrypt_aes_cbc(data: bytes, key: bytes) -> (bytes, bytes):
        cipher = AES.new(key, AES.MODE_CBC)
        padded_data = pad(data, AES.block_size)
        ciphertext = cipher.encrypt(padded_data)

        return cipher.iv, ciphertext
