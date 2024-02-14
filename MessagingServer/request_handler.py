import base64
import logging
import uuid
import time
import base64

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad
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
def decrypt_aes_cbc(iv: bytes, ciphertext: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(ciphertext)
    unpadded_data = unpad(decrypted_data, AES.block_size)

    return unpadded_data


# TODO: rename everything to differ between serers?
class RequestHandler:
    def __init__(self, auth_server) -> None:
        self.users_data = auth_server.users_data

    def handle_request(self, request: Request) -> Response | None:
        if isinstance(request, SendSymmetricKeyRequest):
            response = self._handle_send_symmetric_key_request(request)
        elif isinstance(request, SendMessageRequest):
            response = self._handle_send_msg_request(request)
        else:
            response = GeneralFailureResponse()
        return response

    def _handle_send_symmetric_key_request(self, request: SendSymmetricKeyRequest) -> Response:
        authenticator = request.authenticator
        ticket = request.ticket

        # TODO: move this + consts
        with open("msg.info", 'r') as f:
            msg_server_key = base64.b64decode(f.readlines()[3])

        iv = ticket[41:57]
        encrypted_aes_key = ticket[57:57+48]
        encrypted_exp_timestamp = ticket[41+48:]
        self.aes_key = decrypt_aes_cbc(iv, encrypted_aes_key, msg_server_key)
        #exp_timestamp = decrypt_aes_cbc(iv, encrypted_exp_timestamp, msg_server_key)

        return ReceivedSymmetricKeyResponse()

    def _handle_send_msg_request(self, request: SendMessageRequest) -> Response:
        encrypted_msg = request.msg_content
        msg = decrypt_aes_cbc(request.msg_iv, encrypted_msg, self.aes_key)
        #msg = decrypt_aes_cbc(b"\x00" * 16, encrypted_msg, self.aes_key)
        print(msg.decode())

        return ReceivedMessageResponse()
