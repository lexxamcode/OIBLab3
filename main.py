import pickle
import cryptosystem

settings = {
    'initial_file': 'initial_file.txt',
    'encrypted_file': 'encrypted_file.txt',
    'decrypted_file': 'decrypted_file.txt',
    'symmetric_key': 'symmetric_key.txt',
    'public_key': 'public_key.pem',
    'secret_key': 'secret_key.pem',
}


def keys_generator(block_size=128, path_public: str = 'public.pem', path_private: str = 'private.pem',
                   path_symm: str = 'symmetric_key.txt'):
    # Generating asymmetric keys:
    keys = cryptosystem.generate_asymmetric_keys()
    public_key = keys.public_key()
    private_key = keys
    # Generating and encrypting symmetric key:
    symmetric_key = cryptosystem.encrypt_symmetric_key(cryptosystem.generate_symmetric_key(block_size//8), public_key)

    # Serializing keys:
    cryptosystem.serialize_symmetric_key(symmetric_key, path_symm)

    with open(path_public, 'wb') as public_file:
        public_file.write(public_key.public_bytes(encoding=cryptosystem.serialization.Encoding.PEM,
                                                  format=cryptosystem.serialization.PublicFormat.SubjectPublicKeyInfo))

    with open(path_private, 'wb') as private_file:
        private_file.write(private_key.private_bytes(encoding=cryptosystem.serialization.Encoding.PEM,
                                                     format=cryptosystem.serialization.PrivateFormat.TraditionalOpenSSL,
                                                     encryption_algorithm=cryptosystem.serialization.NoEncryption()))


def encrypt_data(path_initial: str = 'initial_file.txt',
                 path_encrypted_text: str = 'encrypted.txt',
                 path_private: str = 'private.pem',
                 path_symm: str = 'symmetric_key.txt'):
    # Reading data from files:
    with open(path_symm, 'rb') as sym_file:
        symmetric_key = sym_file.read()
    with open(path_initial, 'rb') as text_file:
        initial_text = text_file.read()
    # Getting private key from file:
    private_key = cryptosystem.deserialize_private_key(path_private)

    # Decrypting symmetric key:
    symmetric_key = cryptosystem.decrypt_symmetric_key(symmetric_key, private_key)
    print(len(symmetric_key))
    # Encrypting text:
    encrypted_text = cryptosystem.encrypt_text_with_symmetric_algorithm(symmetric_key, initial_text.decode('UTF-8'))
    # Saving encrypted text and initial vector to file:
    with open('encrypted.txt', 'wb') as enc_file:
        pickle.dump(encrypted_text, enc_file)


def decrypt_data(path_encrypted_text: str = 'encrypted.txt', path_private: str = 'private.pem',
                 path_encrypted_key: str = 'symmetric_key.txt', path_decrypted: str = 'decrypted.txt'):
    # Getting symmetric key and private key:
    with open(path_encrypted_key, 'rb') as sym_key_file:
        symmetric_key = sym_key_file.read()
    with open(path_private, 'rb') as pem_in:
        private_bytes = pem_in.read()
    private_key = cryptosystem.load_pem_private_key(private_bytes, password=None,)

    # Decrypting encoded key
    symmetric_key = cryptosystem.decrypt_symmetric_key(symmetric_key, private_key)

    with open('encrypted.txt', 'rb') as encrypt_file:
        encoded_text = pickle.load(encrypt_file)

    decrypted_text = cryptosystem.decrypt_text_symmetric_algorithm(encoded_text['ciphrotext'], symmetric_key, encoded_text['iv'])
    with open(path_decrypted, 'w') as dec:
        dec.write(decrypted_text.decode('UTF-8'))


if __name__ == '__main__':
    keys_generator(128)
    encrypt_data()
    decrypt_data()
