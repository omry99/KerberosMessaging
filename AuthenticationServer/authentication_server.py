import logging
import socket
from pathlib import Path
import threading
import base64
import uuid

from requests import create_request_from_data
from request_handler import AuthRequestHandler
from user_client import UserClient

logger = logging.getLogger(__name__)

CONFIG_FILE_NAME = "port.info"
DEFAULT_PORT = 1256
MIN_PORT = 1025
MAX_PORT = 65535
LOCALHOST = '127.0.0.1'
CLIENTS_DATA_FILE_NAME = "clients"
MSG_SERVER_INFO_FILE_NAME = "msg.info"
MSG_SERVER_ID_LINE_NUM = 2
MSG_SERVER_KEY_LINE_NUM = 3
BUFFER_SIZE = 1024

CLIENT_ENTRY_CLIENT_ID_INDEX = 0
CLIENT_ENTRY_USER_NAME_INDEX = 1
CLIENT_ENTRY_PASS_HASH_INDEX = 2
CLIENT_ENTRY_LAST_SEEN_INDEX = 3


class AuthenticationServer:
    def __init__(self) -> None:
        logger.info('Setting up authentication server...')

        if Path(CONFIG_FILE_NAME).is_file():
            with open(CONFIG_FILE_NAME, 'r') as config_file:
                port = config_file.read()
            if not (port.isdigit() and MIN_PORT <= int(port) <= MAX_PORT):
                logger.warning(f"{CONFIG_FILE_NAME} is invalid, using default port {DEFAULT_PORT}")
                self.port = DEFAULT_PORT
            else:
                self.port = int(port)
        else:
            logger.warning(f"{CONFIG_FILE_NAME} does not exist, using default port {DEFAULT_PORT}")
            self.port = DEFAULT_PORT

        if Path(MSG_SERVER_INFO_FILE_NAME).is_file():
            with open(MSG_SERVER_INFO_FILE_NAME, 'r') as f:
                lines = f.readlines()
                self.msg_server_id = uuid.UUID(hex=lines[MSG_SERVER_ID_LINE_NUM].strip())
                b64_enc_msg_server_key = lines[MSG_SERVER_KEY_LINE_NUM]
                self.msg_server_key = base64.b64decode(b64_enc_msg_server_key)
        else:
            raise Exception(f"{MSG_SERVER_INFO_FILE_NAME} does not exist, aborting")

        self.users_data = {}
        self._init_ram_records()
        self.request_handler = AuthRequestHandler(self)

    def serve(self) -> None:
        logger.info(f'Listening for clients on port {self.port}...')
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind((LOCALHOST, self.port))
            server_socket.listen()

            while True:
                conn, address = server_socket.accept()
                logger.info("Got a connection from: " + str(address))
                client_thread = threading.Thread(target=self._handle_client, args=(conn,))
                client_thread.start()

    def _handle_client(self, conn) -> None:
        with conn:
            while True:
                data = self._recv_all_data(conn)

                if not data:
                    break

                request = create_request_from_data(data)
                response = self.request_handler.handle_request(request)
                if response:
                    conn.sendall(response.pack())

    def _init_ram_records(self) -> None:
        if Path(CLIENTS_DATA_FILE_NAME).is_file():
            logger.info('Loading disk records into RAM...')
            with open(CLIENTS_DATA_FILE_NAME, 'r') as f:
                client_entries = f.readlines()
            for client_entry in client_entries:
                split_client_entry = client_entry.split(':')
                client_id = bytes.fromhex(split_client_entry[CLIENT_ENTRY_CLIENT_ID_INDEX])
                user_name = split_client_entry[CLIENT_ENTRY_USER_NAME_INDEX]
                pass_hash = split_client_entry[CLIENT_ENTRY_PASS_HASH_INDEX]
                last_seen = split_client_entry[CLIENT_ENTRY_LAST_SEEN_INDEX]
                user_client = UserClient(client_id, user_name, pass_hash, last_seen)
                self.users_data[client_id] = user_client

    def _recv_all_data(self, conn: socket) -> bytes:
        data = b""
        while True:
            try:
                data_part = conn.recv(BUFFER_SIZE)
            except Exception:
                break

            data += data_part
            if len(data_part) < BUFFER_SIZE:
                break

        return data
