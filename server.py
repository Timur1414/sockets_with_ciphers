import pickle
import socket
from ciphers.aes import AES
from ciphers.rsa import RSA


class Server:
    def __init__(self, host: str = '127.0.0.1', port: int = 8888, buf_size: int = 1024):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.host = host
        self.port = port
        self.server.bind((self.host, self.port))
        self.server.listen()
        self.buf_size = buf_size
        print('Server Listening')
        self.open_key = None
        self.close_key = None

        self.address = None
        self.connection = None
        self.client_key = None
        self.client_initialize_vector = None

    def generate_keys(self):
        self.open_key, self.close_key = RSA.generate_keys()

    def recv_bytes(self) -> int:
        data = self.connection.recv(self.buf_size)
        message = int(data.decode('utf-8'))
        return message

    def key_exchange(self):
        serialized_open_key = pickle.dumps(self.open_key)
        self.connection.send(serialized_open_key)

        message = self.recv_bytes()
        number_key = RSA.decrypt(message, self.close_key)
        bytes_key = number_key.to_bytes((number_key.bit_length() + 7) // 8, 'big')
        self.client_key = bytes_key.decode('utf-8')
        print(f'key: {self.client_key}')
        message = self.recv_bytes()
        number_initialize_vector = RSA.decrypt(message, self.close_key)
        bytes_initialize_vector = number_initialize_vector.to_bytes((number_initialize_vector.bit_length() + 7) // 8,
                                                                    'big')
        self.client_initialize_vector = bytes_initialize_vector.decode('utf-8')

    def get_message_from_client(self) -> str:
        self.connection, self.address = self.server.accept()
        self.key_exchange()
        data = self.connection.recv(self.buf_size)
        message = data.decode('utf-8')
        decrypted_message = AES.decrypt_message(message, self.client_key, self.client_initialize_vector)
        print(f'Client {self.address} sent "{decrypted_message}"')
        return decrypted_message


    def send_message_to_client(self, message: str):
        encrypted_message = AES.encrypy_message(message, self.client_key, self.client_initialize_vector)
        self.connection.send(encrypted_message.encode('utf-8'))
        self.connection.close()
        self.server.close()


def main():
    server = Server()
    server.generate_keys()

    message = server.get_message_from_client()
    message = f'your message is "{message}"'
    server.send_message_to_client(message)


if __name__ == '__main__':
    main()
