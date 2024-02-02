import logging
import socket
from pathlib import Path
import threading

from requests import create_request_from_data
from request_handler import RequestHandler
from user_client import UserClient

logger = logging.getLogger(__name__)

CONFIG_FILE_NAME = "port.info"
DEFAULT_PORT = 1256
MIN_PORT = 1025
MAX_PORT = 65535
LOCALHOST = '127.0.0.1'
CLIENTS_DATA_FILE_NAME = "clients"
BUFFER_SIZE = 1024

CLIENT_ID_FIELD_END_INDEX = 16
USER_NAME_FIELD_SIZE = 255
USER_NAME_FIELD_START_INDEX = CLIENT_ID_FIELD_END_INDEX
USER_NAME_FIELD_END_INDEX = USER_NAME_FIELD_START_INDEX + USER_NAME_FIELD_SIZE
PASS_HASH_FIELD_SIZE = 32
PASS_HASH_FIELD_START_INDEX = USER_NAME_FIELD_END_INDEX
PASS_HASH_FIELD_END_INDEX = PASS_HASH_FIELD_START_INDEX + PASS_HASH_FIELD_SIZE
LAST_SEEN_FIELD_START_INDEX = PASS_HASH_FIELD_END_INDEX


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

        self.users_data = {}
        self._init_ram_records()
        self.request_handler = RequestHandler(self)

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
                client_id = client_entry[:CLIENT_ID_FIELD_END_INDEX].encode()
                user_name = client_entry[USER_NAME_FIELD_START_INDEX:USER_NAME_FIELD_END_INDEX]
                pass_hash = client_entry[PASS_HASH_FIELD_START_INDEX:PASS_HASH_FIELD_END_INDEX]
                last_seen = client_entry[LAST_SEEN_FIELD_START_INDEX:]
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