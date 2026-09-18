import hashlib
import base64
import os

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# Get message from user
message = input("Enter a message: ")

# SHA-256 hash
original_hash = hashlib.sha256(message.encode()).hexdigest()

print("\nSHA-256 Hash:")
print(original_hash)


# AES encryption
key = AESGCM.generate_key(bit_length=256)
aes = AESGCM(key)

nonce = os.urandom(12)
encrypted = aes.encrypt(nonce, message.encode(), None)

print("\nEncrypted Message:")
print(base64.b64encode(encrypted).decode())


# AES decryption
decrypted = aes.decrypt(nonce, encrypted, None)
decrypted_message = decrypted.decode()

print("\nDecrypted Message:")
print(decrypted_message)


# Check the hash again
new_hash = hashlib.sha256(decrypted_message.encode()).hexdigest()

print("\nChecking Integrity...")

if original_hash == new_hash:
    print("Integrity check passed. The message was not changed.")
else:
    print("Integrity check failed. The message was changed.")


# RSA private and public keys
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

public_key = private_key.public_key()


# Create digital signature
signature = private_key.sign(
    message.encode(),
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

print("\nDigital Signature Created.")


# Verify digital signature
try:
    public_key.verify(
        signature,
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    print("Digital signature is valid.")
except:
    print("Digital signature is not valid.")