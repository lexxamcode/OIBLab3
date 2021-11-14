import pickle
import cryptosystem
import argparse


def keys_generator(block_size=128, path_public: str = 'public.pem', path_private: str = 'private.pem',
                   path_symm: str = 'symmetric_key.txt') -> None:
    # Generating asymmetric keys:
    keys = cryptosystem.generate_asymmetric_keys()
    public_key = keys.public_key()
    private_key = keys
    # Generating and encrypting symmetric key:
    symmetric_key = cryptosystem.encrypt_symmetric_key(cryptosystem.generate_symmetric_key(block_size // 8), public_key)

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
                 path_symm: str = 'symmetric_key.txt') -> None:
    # Reading data from files:
    with open(path_symm, 'rb') as sym_file:
        symmetric_key = sym_file.read()
    with open(path_initial, 'rb') as text_file:
        initial_text = text_file.read()
    # Getting private key from file:
    private_key = cryptosystem.deserialize_private_key(path_private)

    # Decrypting symmetric key:
    symmetric_key = cryptosystem.decrypt_symmetric_key(symmetric_key, private_key)
    # Encrypting text:
    encrypted_text = cryptosystem.encrypt_text_with_symmetric_algorithm(symmetric_key, initial_text.decode('UTF-8'))
    # Saving encrypted text and initial vector to file:
    with open(path_encrypted_text, 'wb') as enc_file:
        pickle.dump(encrypted_text, enc_file)


def decrypt_data(path_encrypted_text: str = 'encrypted.txt', path_private: str = 'private.pem',
                 path_encrypted_key: str = 'symmetric_key.txt', path_decrypted: str = 'decrypted.txt') -> None:
    # Getting symmetric key and private key:
    with open(path_encrypted_key, 'rb') as sym_key_file:
        symmetric_key = sym_key_file.read()
    with open(path_private, 'rb') as pem_in:
        private_bytes = pem_in.read()
    private_key = cryptosystem.load_pem_private_key(private_bytes, password=None, )

    # Decrypting encoded key
    symmetric_key = cryptosystem.decrypt_symmetric_key(symmetric_key, private_key)

    with open(path_encrypted_text, 'rb') as encrypt_file:
        encoded_text = pickle.load(encrypt_file)

    decrypted_text = cryptosystem.decrypt_text_symmetric_algorithm(encoded_text['ciphrotext'],
                                                                   symmetric_key, encoded_text['iv'])
    with open(path_decrypted, 'w') as dec:
        dec.write(decrypted_text.decode('UTF-8'))


settings = {
    'key_size': 128,
    'initial_file': 'work_files/data/text_for_test.txt',
    'encrypted_file': 'work_files/data/encrypted_file.txt',
    'decrypted_file': 'work_files/data/decrypted_file.txt',
    'symmetric_key': 'work_files/keys/symmetric_key.txt',
    'public_key': 'work_files/keys/public_key.pem',
    'secret_key': 'work_files/keys/secret_key.pem',
}


cryptosystem_parser = argparse.ArgumentParser(description="Camelia hybrid cryptosystem")
cryptosystem_parser.add_argument('-s', '--settings', type=str, help="Path to the settings of cryptosystem. Check "
                                                                    "settings.txt in project directory for changing "
                                                                    "parameters.")
# arg_group = cryptosystem_parser.add_mutually_exclusive_group(required=True)
cryptosystem_parser.add_argument('-gen', '--generation', type=str, help='type \'do\' to start keys generation mode '
                                                                        'and null not to start')
cryptosystem_parser.add_argument('-enc', '--encryption', type=str, help='type \'do\' to start encryption mode'
                                                                        ' and null not to start')
cryptosystem_parser.add_argument('-dec', '--decryption', type=str, help='type \'do\' to start decryption mode'
                                                                        'and null not to start')

if __name__ == '__main__':
    args = cryptosystem_parser.parse_args()
    # Settings
    if args.settings is not None:
        with open(args.settings, 'r') as settings_file:
            for line in settings_file:
                key, value = line.split(': ')
                settings[key] = value
    else:
        with open('work_files/settings.txt', 'r') as settings_file:
            for line in settings_file:
                key, value = line.split(': ')
                settings[key] = value
    # Key generation
    if (int(settings['key_size']) == 128) or (int(settings['key_size']) == 192) or (int(settings['key_size']) == 256):
        if args.generation is not None:
            if args.generation == 'do':
                keys_generator(settings['key_size'], settings['public_key'], settings['secret_key'],
                               settings['symmetric_key'])
            elif args.generation == 'null':
                print('Key generation - skipped...')
            else:
                print('Incorrect command at pos2')
    else:
        print('Incorrect key size')
    # Encryption
    if args.encryption is not None:
        if args.encryption == 'do':
            encrypt_data(settings['initial_file'], settings['encrypted_file'], settings['secret_key'],
                         settings['symmetric_key'])
        elif args.encryption == 'null':
            print('Text encryption - skipped...')
        else:
            print('Incorrect command at pos3')

    # Decryption
    if args.decryption is not None:
        if args.decryption == 'do':
            decrypt_data(settings['encrypted_file'], settings['secret_key'], settings['symmetric_key'],
                         settings['decrypted_file'])
        elif args.decryption == 'null':
            print('Text decryption - skipped...')
        else:
            print('Incorrect command at pos4')

    print('Done')
