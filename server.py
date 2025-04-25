import pickle
import socket
import ciphers.aes as aes
import ciphers.rsa as rsa

def encrypt_message_to_client(text: str, key: str, initialization_vector: str):
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

def decrypt_message_from_client(data: str, key: str, initialization_vector: str):
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


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = '127.0.0.1'
    port = 8888
    server.bind((host, port))
    server.listen()
    print('Server Listening')

    open_key, close_key = rsa.generate_keys()
    buf_size = 1024

    connection, address = server.accept()
    serialized_open_key = pickle.dumps(open_key)
    connection.send(serialized_open_key)

    data = connection.recv(buf_size)
    message = int(data.decode('utf-8'))
    number_key = rsa.decrypt(message, close_key)
    bytes_key = number_key.to_bytes((number_key.bit_length() + 7) // 8, 'big')
    key = bytes_key.decode('utf-8')
    print(f'key: {key}')
    data = connection.recv(buf_size)
    message = int(data.decode('utf-8'))
    number_initialize_vector = rsa.decrypt(message, close_key)
    bytes_initialize_vector = number_initialize_vector.to_bytes((number_initialize_vector.bit_length() + 7) // 8, 'big')
    initialize_vector = bytes_initialize_vector.decode('utf-8')

    data = connection.recv(buf_size)
    message = data.decode('utf-8')
    decrypted_message = decrypt_message_from_client(message, key, initialize_vector)
    print(f'Client {address} sent "{decrypted_message}"')
    message = f'your message is "{decrypted_message}"'
    encrypted_message = encrypt_message_to_client(message, key, initialize_vector)
    connection.send(encrypted_message.encode('utf-8'))
    connection.close()

    server.close()


if __name__ == '__main__':
    main()
