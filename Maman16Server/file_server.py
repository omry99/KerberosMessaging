import logging
import socket
import sqlite3
import os
from pathlib import Path
import threading

from requests import create_request_from_data
from request_handler import RequestHandler

logger = logging.getLogger(__name__)

CONFIG_FILE_NAME = "port.info"
DEFAULT_PORT = 1357
MIN_PORT = 1025
MAX_PORT = 65535
LOCALHOST = '127.0.0.1'
DATABASE_NAME = r"defensive.db"
BUFFER_SIZE = 1024
RECEIVED_FILES_FOLDER_NAME = "ReceivedFiles"


class FileServer:
    def __init__(self) -> None:
        logger.info('Setting up server...')

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

        if not Path(RECEIVED_FILES_FOLDER_NAME).exists():
            os.mkdir(RECEIVED_FILES_FOLDER_NAME)

        logger.info('Connecting to DB...')
        self.db_conn = sqlite3.connect(DATABASE_NAME, check_same_thread=False)
        self._init_db()
        self.request_handler = RequestHandler(self.db_conn, RECEIVED_FILES_FOLDER_NAME)

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

    def _handle_client(self, conn):
        with conn:
            while True:
                data = self._recv_all_data(conn)

                if not data:
                    break

                request = create_request_from_data(data)
                response = self.request_handler.handle_request(request)
                if response:
                    conn.sendall(response.pack())

    def _init_db(self) -> None:
        cursor = self.db_conn.cursor()
        # Create the tables if they don't exist
        clients_table_schema = '''
            CREATE TABLE IF NOT EXISTS clients (
                ID BLOB(16) NOT NULL,
                Name TEXT(255),
                PublicKey BLOB(160),
                LastSeen DATETIME,
                AesKey BLOB(128),
                PRIMARY KEY (ID)
            )
        '''
        cursor.execute(clients_table_schema)
        files_table_schema = '''
                CREATE TABLE IF NOT EXISTS files (
                    ID BLOB(16) NOT NULL,
                    FileName TEXT(255),
                    PathName TEXT(255),
                    Verified BOOLEAN
                )
            '''
        cursor.execute(files_table_schema)
        self.db_conn.commit()

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
