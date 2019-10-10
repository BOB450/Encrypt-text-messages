from cryptography.fernet import Fernet


import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

password_provided = input("Type in the password for incripting and decrypting:  ")

#password_provided = "Rowika" # This is input in the form of a string
password = password_provided.encode() # Convert to type bytes
salt = b'salt_' # CHANGE THIS - recommend using a key from os.urandom(16), must be of type bytes
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = base64.urlsafe_b64encode(kdf.derive(password)) # Can only use kdf once







#key = Fernet.generate_key()
#print(key)
message = input("Type in message that you want encrypted")
enmessage = message.encode()


f = Fernet(key)
encrypted = f.encrypt(enmessage)


nencrypted = encrypted.decode()
print(nencrypted)

q = input("Quit")
if q == "y":
    quit()

