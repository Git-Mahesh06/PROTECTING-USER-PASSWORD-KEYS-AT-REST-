import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from getpass import getpass

backend = default_backend()

def encrypt_file(file_path, passphrase):
    # Generate a random File Encryption Key (FEK)
    fek = os.urandom(32)  # AES-256 requires a 32-byte key

    # Read the file content
    with open(file_path, 'rb') as f:
        plaintext = f.read()

    # Pad plaintext to be multiple of block size
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    # Encrypt the file content using AES-256
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(fek), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Overwrite the original file with the encrypted content
    with open(file_path, 'wb') as f:
        f.write(iv + ciphertext)

    # Derive a key from the passphrase using PBKDF2
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key = kdf.derive(passphrase.encode())

    # Encrypt the FEK using the derived key
    iv_fek = os.urandom(16)
    cipher_fek = Cipher(algorithms.AES(key), modes.CBC(iv_fek), backend=backend)
    encryptor_fek = cipher_fek.encryptor()
    
    # Pad the FEK before encryption
    padder_fek = padding.PKCS7(128).padder()
    padded_fek = padder_fek.update(fek) + padder_fek.finalize()
    
    enc_fek = encryptor_fek.update(padded_fek) + encryptor_fek.finalize()

    # Save the encrypted FEK and salt
    with open(file_path + '.key', 'wb') as f:
        f.write(salt + iv_fek + enc_fek)

def decrypt_file(file_path, passphrase):
    # Read the encrypted FEK and salt
    with open(file_path + '.key', 'rb') as f:
        salt = f.read(16)
        iv_fek = f.read(16)
        enc_fek = f.read()

    # Derive the key from the passphrase using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key = kdf.derive(passphrase.encode())

    # Decrypt the FEK using the derived key
    cipher_fek = Cipher(algorithms.AES(key), modes.CBC(iv_fek), backend=backend)
    decryptor_fek = cipher_fek.decryptor()
    padded_fek = decryptor_fek.update(enc_fek) + decryptor_fek.finalize()

    unpadder_fek = padding.PKCS7(128).unpadder()
    fek = unpadder_fek.update(padded_fek) + unpadder_fek.finalize()

    # Read the encrypted file content
    with open(file_path, 'rb') as f:
        iv = f.read(16)
        ciphertext = f.read()

    # Decrypt the file content using the FEK
    cipher = Cipher(algorithms.AES(fek), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    # Overwrite the original file with the decrypted content
    with open(file_path, 'wb') as f:
        f.write(plaintext)

if _name_ == '_main_':
    action = input("Do you want to (e)ncrypt or (d)ecrypt a file? ")
    file_path = input("Enter the path of the file: ")
    passphrase = getpass("Enter the passphrase: ")

    if action == 'e':
        encrypt_file(file_path, passphrase)
        print("File encrypted successfully.")
    elif action == 'd':
        decrypt_file(file_path, passphrase)
        print("File decrypted successfully.")
    else:
        print("Invalid action.")