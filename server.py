import socket


def main():
    server = socket.socket()
    host = socket.gethostname()
    port = 8888
    server.bind((host, port))
    server.listen()
    print('Server Listening')

    buf_size = 1024

    connection, address = server.accept()
    data = connection.recv(buf_size)
    message = data.decode('utf-8')
    print(f'Client {address} sent "{message}"')
    message = 'some text'
    connection.send(message.encode('utf-8'))
    connection.close()

    server.close()


if __name__ == '__main__':
    main()
