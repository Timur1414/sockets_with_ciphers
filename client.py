import pickle
import socket
from ciphers.aes import AES
from ciphers.rsa import RSA


class Client:
    def __init__(self, host: str = '127.0.0.1', port: int = 8888, buf_size: int = 1024):
        self.initialize_vector = None
        self.key = None
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.host = host
        self.port = port
        self.client.connect((self.host, self.port))
        self.buf_size = buf_size
        self.close_key = None
        self.open_key = None

        self.server_open_key = None

    def generate_keys(self):
        self.open_key, self.close_key = RSA.generate_keys()

    def key_exchange(self):
        server_open_key = self.client.recv(self.buf_size)
        self.server_open_key = pickle.loads(server_open_key)

        self.key = input('Enter key: ')
        bytes_key = self.key.encode('utf-8')
        number_key = int.from_bytes(bytes_key, 'big')
        self.initialize_vector = 'aaa'
        bytes_initialize_vector = self.initialize_vector.encode('utf-8')
        number_initialize_vector = int.from_bytes(bytes_initialize_vector, 'big')
        encrypted_key = str(RSA.encrypt(number_key, self.server_open_key))
        self.client.send(encrypted_key.encode('utf-8'))
        encrypted_initialize_vector = str(RSA.encrypt(number_initialize_vector, self.server_open_key))
        self.client.send(encrypted_initialize_vector.encode('utf-8'))

    def send_message_to_server(self):
        self.key_exchange()
        message = input('Enter message: ')
        encrypted_message = AES.encrypy_message(message, self.key, self.initialize_vector)
        self.client.send(encrypted_message.encode('utf-8'))

    def get_message_from_server(self) -> str:
        data = self.client.recv(self.buf_size)
        message = data.decode('utf-8')
        decrypted_message = AES.decrypt_message(message, self.key, self.initialize_vector)
        print(f'Server sent "{decrypted_message}"')
        self.client.close()
        return decrypted_message


def main():
    client = Client()

    client.send_message_to_server()
    message = client.get_message_from_server()


if __name__ == '__main__':
    main()
