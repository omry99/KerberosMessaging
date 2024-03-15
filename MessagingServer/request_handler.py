import logging
import time

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from requests import *
from responses import *
from responses import Response

logger = logging.getLogger(__name__)

BUFFER_SIZE = 1024
TEN_MIN_IN_SEC = 600
EXPIRE_TIME_LEN = 8

CLIENTS_DATA_FILE_NAME = "clients"
MSG_SERVER_INFO_FILE_NAME = "msg.info"

UUID_FIELD_INDEX = 0
LAST_SEEN_FIELD_INDEX = -1

CLIENT_ID_START_INDEX = 1
CLIENT_ID_END_INDEX = 17
TICKET_IV_START_INDEX = 41
TICKET_IV_END_INDEX = 57
AUTHENTICATOR_CREATION_TIME_START_INDEX = 33
AUTHENTICATOR_IV_SIZE = 16
AES_KEY_LEN = 32


class MsgRequestHandler:
    def __init__(self, msg_server) -> None:
        self.users_data = msg_server.users_data
        self.msg_server_key = msg_server.msg_server_key

    def handle_request(self, request: Request) -> Response | None:
        if isinstance(request, SendSymmetricKeyRequest):
            response = self._handle_send_symmetric_key_request(request)
        elif isinstance(request, SendMessageRequest):
            response = self._handle_send_msg_request(request)
        else:
            response = GeneralFailureResponse()
        return response

    def _handle_send_symmetric_key_request(self, request: SendSymmetricKeyRequest) -> Response:
        logger.info(f"Got a send symmetric key request from")

        ticket = request.ticket
        ticket_client_id = ticket[CLIENT_ID_START_INDEX:CLIENT_ID_END_INDEX]
        ticket_iv = ticket[TICKET_IV_START_INDEX:TICKET_IV_END_INDEX]
        encrypted_ticket_data = ticket[TICKET_IV_END_INDEX:]
        decrypted_ticket_data = self._decrypt_aes_cbc(ticket_iv, encrypted_ticket_data, self.msg_server_key)
        exp_time = decrypted_ticket_data[AES_KEY_LEN:]
        unpacked_exp_time = struct.unpack("=d", exp_time)[0]

        if unpacked_exp_time < time.time():
            logger.error("Received expired ticket")
            return GeneralFailureResponse()

        self.aes_key = decrypted_ticket_data[:AES_KEY_LEN]

        authenticator = request.authenticator
        authenticator_iv = authenticator[:AUTHENTICATOR_IV_SIZE]
        encrypted_authenticator_data = authenticator[AUTHENTICATOR_IV_SIZE:]
        decrypted_authenticator_data = self._decrypt_aes_cbc(authenticator_iv, encrypted_authenticator_data,
                                                             self.aes_key)
        authenticator_client_id = decrypted_authenticator_data[CLIENT_ID_START_INDEX:CLIENT_ID_END_INDEX]
        authenticator_creation_time = decrypted_authenticator_data[AUTHENTICATOR_CREATION_TIME_START_INDEX:]
        unpacked_authenticator_creation_time = struct.unpack("=d", authenticator_creation_time)[0]

        if authenticator_client_id != ticket_client_id:
            logger.error("Authenticator client ID is different from ticket client ID")
            return GeneralFailureResponse()
        if unpacked_authenticator_creation_time > time.time():
            logger.error("Invalid authenticator creation time")
            return GeneralFailureResponse()

        return ReceivedSymmetricKeyResponse()

    def _handle_send_msg_request(self, request: SendMessageRequest) -> Response:
        encrypted_msg = request.msg_content
        msg = self._decrypt_aes_cbc(request.msg_iv, encrypted_msg, self.aes_key)
        logger.info(f"Received message: {msg.decode()}")

        return ReceivedMessageResponse()

    @staticmethod
    def _decrypt_aes_cbc(iv: bytes, ciphertext: bytes, key: bytes) -> bytes:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(ciphertext)
        unpadded_data = unpad(decrypted_data, AES.block_size)

        return unpadded_data
