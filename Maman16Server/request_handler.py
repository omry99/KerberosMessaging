import logging
import uuid
import time
import os

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import unpad

import cksum
from requests import *
from responses import *
from responses import Response
from user_client import UserClient
from client_file import ClientFile

logger = logging.getLogger(__name__)

AES_KEY_LENGTH_IN_BYTES = 16
BUFFER_SIZE = 1024


class RequestHandler:
    def __init__(self, db_conn, files_folder) -> None:
        self.db_conn = db_conn
        self.cursor = db_conn.cursor()
        self.users_data = {}
        self.files_data = {}
        self.files_folder = files_folder

    def handle_request(self, request: Request) -> Response | None:
        if isinstance(request, RegisterRequest):
            response = self._handle_register_request(request)
        elif isinstance(request, KeyRequest):
            response = self._handle_key_request(request)
        elif isinstance(request, ReconnectRequest):
            response = self._handle_reconnect_request(request)
        elif isinstance(request, FileRequest):
            response = self._handle_file_request(request)
        elif isinstance(request, ValidCrcRequest):
            response = self._handle_valid_crc_request(request)
        elif isinstance(request, InvalidCrcRequest):
            return None
        elif isinstance(request, LastInvalidCrcRequest):
            return None
        else:
            response = GeneralFailureResponse()
        return response

    def _handle_register_request(self, request: RegisterRequest) -> Response:
        user_name = request.name[:request.name.find('\x00')]

        # Check if the user already exists in the DB
        select_query = "SELECT * FROM clients WHERE NAME = ?"
        self.cursor.execute(select_query, (user_name,))
        # Fetch the first matching record (if any)
        existing_entry = self.cursor.fetchone()
        if existing_entry:
            logger.error(f"User {user_name} already exists in DB")
            return RegistrationFailedResponse()

        # Add the user to the DB
        client_id = uuid.uuid4().bytes
        new_entry = (client_id, user_name, None, time.ctime(), None)
        insert_query = "INSERT INTO clients (ID, Name, PublicKey, LastSeen, AesKey) VALUES (?, ?, ?, ?, ?)"
        self.cursor.execute(insert_query, new_entry)
        self.db_conn.commit()

        # Add the user to RAM records
        user_client = UserClient(client_id, user_name, None, time.ctime(), None)
        self.users_data[client_id] = user_client

        logger.info(f"User {user_name} added to the DB and RAM")

        return RegistrationSuccessResponse(client_id)

    def _handle_key_request(self, request: KeyRequest) -> Response:
        # Create an AES key for the client
        aes_key = os.urandom(AES_KEY_LENGTH_IN_BYTES)

        # Insert the client's public key and AES key into the DB
        update_query = "UPDATE clients SET PublicKey = ?, AesKey = ? WHERE id = ?"
        self.cursor.execute(update_query, (request.public_key, aes_key, request.client_id))
        self.db_conn.commit()

        # Update the key in the RAM records
        self.users_data[request.client_id].public_key = request.public_key

        user_name = request.name[:request.name.find('\x00')]
        logger.info(f"Set public key and AES key for {user_name} in DB and RAM")

        # Encrypt the AES key with the client's public RSA key and sent it to the client
        client_pub_key = RSA.importKey(request.public_key)

        cipher = PKCS1_OAEP.new(client_pub_key)
        encrypted_aes_key = cipher.encrypt(aes_key)
        return KeyResponse(request.client_id, encrypted_aes_key)

    def _handle_reconnect_request(self, request: ReconnectRequest) -> Response:
        user_name = request.name[:request.name.find('\x00')]
        logger.info(f"Got a reconnect request from {user_name}")

        # Get the client's public key from the DB
        query = "SELECT PublicKey FROM clients WHERE id = ?"
        self.cursor.execute(query, (request.client_id,))
        public_key = self.cursor.fetchone()
        if public_key:
            public_key = public_key[0]
        else:
            return RejectedReconnectResponse(request.client_id)

        # Get the client's AES key from the DB
        query = "SELECT AesKey FROM clients WHERE id = ?"
        self.cursor.execute(query, (request.client_id,))
        aes_key = self.cursor.fetchone()
        if aes_key:
            aes_key = aes_key[0]
        else:
            return RejectedReconnectResponse(request.client_id)

        # Encrypt the AES key with the client's public RSA key and sent it to the client
        client_pub_key = RSA.importKey(public_key)

        cipher = PKCS1_OAEP.new(client_pub_key)
        encrypted_aes_key = cipher.encrypt(aes_key)

        return AcceptedReconnectResponse(request.client_id, encrypted_aes_key)

    def _handle_file_request(self, request: FileRequest) -> Response:
        encrypted_file = request.message_content

        # Get the client's AES key from the DB
        query = "SELECT AesKey FROM clients WHERE id = ?"
        self.cursor.execute(query, (request.client_id,))
        aes_key = self.cursor.fetchone()
        if aes_key:
            aes_key = aes_key[0]
        else:
            return GeneralFailureResponse()

        DUMMY_IV = b"\x00" * 16
        cipher = AES.new(aes_key, AES.MODE_CBC, iv=DUMMY_IV)
        cleartext_file = unpad(cipher.decrypt(encrypted_file), AES.block_size)
        cleartext_file_crc = cksum.memcrc(cleartext_file)

        # Add the file to the DB
        file_path = os.path.join(self.files_folder, request.file_name)[:255]
        new_entry = (request.client_id, request.file_name, file_path, False)
        insert_query = "INSERT INTO files (ID, FileName, PathName, Verified) VALUES (?, ?, ?, ?)"
        self.cursor.execute(insert_query, new_entry)
        self.db_conn.commit()

        # Add the file to RAM records
        file_name_unpadded = request.file_name[:request.file_name.find('\x00')]
        file_path_unpadded = os.path.join(self.files_folder, file_name_unpadded)
        client_file = ClientFile(request.client_id, file_name_unpadded, file_path_unpadded, False)
        if request.client_id in self.files_data.keys():
            self.files_data[request.client_id][file_name_unpadded] = client_file
        else:
            self.files_data[request.client_id] = {file_name_unpadded : client_file}

        # Write the file to the local folder
        with open(file_path_unpadded, 'wb') as f:
            f.write(cleartext_file)

        logger.info(f"File {file_name_unpadded} added to DB, RAM and local files folder")

        return ReceivedFileResponse(request.client_id, request.content_size, request.file_name, cleartext_file_crc)

    def _handle_valid_crc_request(self, request: ValidCrcRequest) -> Response:
        # Update the file record in the DB to be verified
        update_query = "UPDATE files SET Verified = TRUE WHERE id = ? AND FileName = ?"
        self.cursor.execute(update_query, (request.client_id, request.file_name))
        self.db_conn.commit()

        # Update the file record in the RAM to be verified
        file_name_unpadded = request.file_name[:request.file_name.find('\x00')]
        self.files_data[request.client_id][file_name_unpadded].verified = True

        logger.info(f"File {file_name_unpadded} verified and updated in DB and RAM")

        return RequestReceivedResponse(request.client_id)
