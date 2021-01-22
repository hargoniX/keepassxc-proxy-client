# Refer to https://github.com/keepassxreboot/keepassxc-browser/blob/develop/keepassxc-protocol.md
import base64
import socket
import json
import platform
import os

import nacl.utils
from nacl.public import PrivateKey, Box, PublicKey


class ResponseUnsuccesfulException(Exception):
    pass


class Connection:

    def __init__(self):
        self.private_key = PrivateKey.generate()
        self.public_key = self.private_key.public_key
        self.nonce = nacl.utils.random(24)
        self.client_id = base64.b64encode(nacl.utils.random(24)).decode("utf-8")
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

    def connect(self, path=None):
        if path is None:
            path = Connection.get_socket_path()

        self.socket.connect(path)
        message = json.dumps(self.change_public_keys())
        self.socket.sendall(message.encode("utf-8"))
        response = self.get_unencrypted_response()
        if not response["success"]:
            raise ResponseUnsuccesfulException
        self.box = Box(self.private_key, PublicKey(base64.b64decode(response["publicKey"])))
        self.nonce = (int.from_bytes(self.nonce, "big") + 1).to_bytes(24, "big")

    @staticmethod
    def get_socket_path():
        server_name = "org.keepassxc.KeePassXC.BrowserServer"
        system = platform.system()
        if system == "Linux" and "XDG_RUNTIME_DIR" in os.environ:
            return os.path.join(os.environ["XDG_RUNTIME_DIR"], server_name)
        elif system == "Darwin" and "TMPDIR" in os.environ:
            return os.path.join(os.getenv("TMPDIR"), server_name)
        else:
            return os.path.join("/tmp", server_name)

    def change_public_keys(self):
        return {
            "action": "change-public-keys",
            "publicKey": base64.b64encode(self.public_key._public_key).decode("utf-8"),
            "nonce": base64.b64encode(self.nonce).decode("utf-8"),
            "clientID": self.client_id
        }

    def get_databasehash(self):
        msg = {
            "action": "get-databasehash"
        }
        self.send_encrypted_message(msg)
        response = self.get_encrypted_response()
        return response["hash"]

    def associate(self):
        self.id_public_key = PrivateKey.generate().public_key
        msg = {
            "action": "associate",
            "key": base64.b64encode(self.public_key._public_key).decode("utf-8"),
            "idKey": base64.b64encode(self.id_public_key._public_key).decode("utf-8")
        }

        self.send_encrypted_message(msg)
        response = self.get_encrypted_response()
        self.associate_id = response["id"]
        return True

    def load_associate(self, name, public_key):
        self.associate_id = name
        self.id_public_key = PublicKey(public_key)

    def dump_associate(self):
        return (self.associate_id, self.id_public_key._public_key)

    def test_associate(self):
        msg = {
            "action": "test-associate",
            "id": self.associate_id,
            "key": base64.b64encode(self.id_public_key._public_key).decode("utf-8")
        }

        self.send_encrypted_message(msg)
        self.get_encrypted_response()
        return True

    def get_logins(self, url):
        msg = {
            "action": "get-logins",
            "url": url,
            "keys": [
                {
                    "id": self.associate_id,
                    "key": base64.b64encode(self.id_public_key._public_key).decode("utf-8")
                }
            ]
        }

        self.send_encrypted_message(msg)
        response = self.get_encrypted_response()
        if not response["count"]:
            return False
        else:
            return response["entries"]

    def get_unencrypted_response(self):
        return json.loads(self.socket.recv(4096).decode("utf-8"))

    def get_encrypted_response(self):
        raw_response = self.get_unencrypted_response()
        if "error" in raw_response:
            raise ResponseUnsuccesfulException(raw_response)
        server_nonce = base64.b64decode(raw_response["nonce"])
        decrypted = self.box.decrypt(base64.b64decode(raw_response["message"]), server_nonce)
        response = json.loads(decrypted)
        if not response["success"]:
            raise ResponseUnsuccesfulException(raw_response)
        return response

    def send_encrypted_message(self, msg):
        encrypted = base64.b64encode(self.box.encrypt(json.dumps(msg).encode("utf-8"), nonce=self.nonce).ciphertext)
        msg = {
            "action": msg["action"],
            "message": encrypted.decode("utf-8"),
            "nonce": base64.b64encode(self.nonce).decode("utf-8"),
            "clientID": self.client_id
        }
        self.socket.sendall(json.dumps(msg).encode("utf-8"))
        self.nonce = (int.from_bytes(self.nonce, "big") + 1).to_bytes(24, "big")
