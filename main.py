import cryptosystem

settings = {
    'initial_file': 'initial_file.txt',
    'encrypted_file': 'encrypted_file.txt',
    'decrypted_file': 'decrypted_file.txt',
    'symmetric_key': 'symmetric_key.txt',
    'public_key': 'public_key.pem',
    'secret_key': 'secret_key.pem',
}


if __name__ == '__main__':
    s_key = cryptosystem.generate_symmetric_key(16)
    cryptosystem.serialize_symmetric_key(s_key, settings['symmetric_key'])

    with open(settings['initial_file'], 'r') as file:
        text = file.read()

    padded_text = cryptosystem.padding_text(text)
    encrypted_text_set = cryptosystem.encrypt_text_with_symmetric_algorithm(s_key, padded_text)
    decrypted_text = cryptosystem.decrypt_text_symmetric_algorithm(s_key, encrypted_text_set['encrypted'],
                                                                   encrypted_text_set['iv'],
                                                                   encrypted_text_set['cipher'],)
    # print(text)
    # print(padded_text)
    print(encrypted_text_set['encrypted'])
    print(decrypted_text.decode('utf-8'))
