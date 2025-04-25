import pickle
import socket
import ciphers.aes as aes
import ciphers.rsa as rsa


def decrypt_message_from_server(data: str, key: str, initialization_vector: str):
    data = [ord(i) for i in data]
    key = [ord(i) for i in key]
    initialization_vector = [ord(i) for i in initialization_vector]
    if len(initialization_vector) < 16:  # заполнение до 16 байт
        empty_spaces = 16 - len(initialization_vector)
        for i in range(empty_spaces):
            initialization_vector.append(1)
    decrypted_data = aes.CBC_decrypt(data, key, initialization_vector)
    decrypted_data = ''.join(chr(i) for i in decrypted_data if i >= 32)
    return decrypted_data

def encrypt_message_to_server(text: str, key: str, initialization_vector: str):
    text = [ord(i) for i in text]
    key = [ord(i) for i in key]
    initialization_vector = [ord(i) for i in initialization_vector]
    if len(initialization_vector) < 16:  # заполнение до 16 байт
        empty_spaces = 16 - len(initialization_vector)
        for i in range(empty_spaces):
            initialization_vector.append(1)
    encrypted_data = aes.CBC_encrypt(text, key, initialization_vector)
    encrypted_data = ''.join(chr(i) for i in encrypted_data)
    return encrypted_data


def main():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = '127.0.0.1'
    port = 8888
    client.connect((host, port))

    open_key, clode_key = rsa.generate_keys()
    buf_size = 1024
    key = input('Enter key: ')
    bytes_key = key.encode('utf-8')
    number_key = int.from_bytes(bytes_key, 'big')
    initialize_vector = 'aaa'
    bytes_initialize_vector = initialize_vector.encode('utf-8')
    number_initialize_vector = int.from_bytes(bytes_initialize_vector, 'big')

    server_open_key = client.recv(buf_size)
    deserialized_server_open_key = pickle.loads(server_open_key)

    encrypted_key = str(rsa.encrypt(number_key, deserialized_server_open_key))
    client.send(encrypted_key.encode('utf-8'))
    encrypted_initialize_vector = str(rsa.encrypt(number_initialize_vector, deserialized_server_open_key))
    client.send(encrypted_initialize_vector.encode('utf-8'))

    message = input('Enter message: ')
    encrypted_message = encrypt_message_to_server(message, key, initialize_vector)
    client.send(encrypted_message.encode('utf-8'))
    data = client.recv(buf_size)
    message = data.decode('utf-8')
    decrypted_message = decrypt_message_from_server(message, key, initialize_vector)
    print(f'Server sent "{decrypted_message}"')
    client.close()


if __name__ == '__main__':
    main()
