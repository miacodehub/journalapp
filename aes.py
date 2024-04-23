from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os


def encrypt_message(key, message):
    #generate a random initialization vector (??)
    iv = os.urandom(16)

    #create an aes cipher object
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend = default_backend())
    #?!?!?
    #create a padder
    padder = padding.PKCS7(128).padder()

    #pad the message 
    padded_data = padder.update(message) + padder.finalize()

    #encrypt the padded data

    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return iv + ciphertext


def decrypt_message(key, iv_cyphertext):
    #extract the iv from the ciphertext
    iv = iv_ciphertext[:16]
    ciphertext = iv_ciphertext[16:]

    #create an aes cipher object
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    #decrypt the ciphertext
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    #unpad the decrypted data
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    return data

key = b'thisISASecretKey' # 16, 24, or 32 bytes long
message = b'hello world!'

iv_ciphertext = encrypt_message(key, message)
print("encrypted message:", iv_ciphertext)

decrypted_message = decrypt_message(key, iv_ciphertext)
print("decrypted message", decrypted_message.decode())



