import logging
import socket
import threading
import base64

from requests import create_request_from_data
from request_handler import MsgRequestHandler

logger = logging.getLogger(__name__)

MSG_SERVER_INFO_FILE_NAME = "msg.info"
MSG_SERVER_ADDR_LINE_NUM = 0
MSG_SERVER_KEY_LINE_NUM = 3
MIN_PORT = 1025
MAX_PORT = 65535
LOCALHOST = '127.0.0.1'
BUFFER_SIZE = 1024


class MessagingServer:
    def __init__(self) -> None:
        logger.info('Setting up messaging server...')

        with open(MSG_SERVER_INFO_FILE_NAME, 'r') as msg_server_info_file:
            msg_server_info_lines = msg_server_info_file.readlines()
            msg_server_addr = msg_server_info_lines[MSG_SERVER_ADDR_LINE_NUM].strip()
            port = msg_server_addr[msg_server_addr.find(':') + 1:]
            self.msg_server_key = base64.b64decode(msg_server_info_lines[MSG_SERVER_KEY_LINE_NUM])
        if not (port.isdigit() and MIN_PORT <= int(port) <= MAX_PORT):
            raise Exception(f"{MSG_SERVER_INFO_FILE_NAME} is invalid")
        else:
            self.port = int(port)

        self.users_data = {}
        self.request_handler = MsgRequestHandler(self)

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
