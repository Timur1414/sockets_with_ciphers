import socket


def main():
    client = socket.socket()
    host = socket.gethostname()
    port = 8888
    buf_size = 1024
    client.connect((host, port))
    message = input('Enter message: ')
    client.send(message.encode('utf-8'))
    data = client.recv(buf_size)
    message = data.decode('utf-8')
    print(f'Server sent "{message}"')
    client.close()


if __name__ == '__main__':
    main()
