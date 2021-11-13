import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding as pad
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key


def generate_symmetric_key(key_size=16):
    _encSymKey = os.urandom(key_size)
    return _encSymKey


def serialize_symmetric_key(key, path='symmetric_key.txt'):
    with open(path, 'wb') as key_file:
        key_file.write(key)


def deserialize_symmetric_key(path):
    with open(path, 'rb') as key_file:
        key = key_file.read()
        return key


def padding_text(text: str):
    _padder = pad.ANSIX923(128).padder()
    _text = bytes(text, 'UTF-8')

    _padded_text = _padder.update(_text) + _padder.finalize()

    return _padded_text


def encrypt_text_with_symmetric_algorithm(key, text: str):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.Camellia(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    e_text = encryptor.update(padding_text(text)) + encryptor.finalize()

    set_for_decryption = {'ciphrotext': e_text, 'iv': iv}

    return set_for_decryption


def decrypt_text_symmetric_algorithm(encrypted_text, key, iv):
    cipher = Cipher(algorithms.Camellia(key), modes.CBC(iv))

    decryptor = cipher.decryptor()
    decrypted_text = decryptor.update(encrypted_text) + decryptor.finalize()

    unpadder = pad.ANSIX923(128).unpadder()
    unpadded_decrypted_text = unpadder.update(decrypted_text) + unpadder.finalize()

    return unpadded_decrypted_text


def generate_asymmetric_keys():
    keys = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    return keys


def deserialize_public_key(path='public_key.pem'):
    with open(path, 'rb') as pem_in:
        public_bytes = pem_in.read()
        deserialized_public_key = load_pem_public_key(public_bytes)

    return deserialized_public_key


def deserialize_private_key(path='private_key.pem'):
    with open(path, 'rb') as pem_in:
        private_bytes = pem_in.read()
        deserialized_private_key = load_pem_private_key(private_bytes, password=None)

    return deserialized_private_key


def encrypt_symmetric_key(key, public_key):
    encrypted_key = public_key.encrypt(key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                             algorithm=hashes.SHA256(), label=None))
    return encrypted_key


def decrypt_symmetric_key(encrypted_key, private_key):
    decrypted_key = private_key.decrypt(encrypted_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                        algorithm=hashes.SHA256(), label=None))
    return decrypted_key
