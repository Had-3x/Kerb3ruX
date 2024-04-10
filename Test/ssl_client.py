import socket, ssl, sys

class SSLClient:
    def __init__(self, host='localhost', port=4433):
        self.host = host
        self.port = port
        self.context = ssl.create_default_context()
        self.context.load_verify_locations(cafile='E:/Projects/Kerb3ruX/Test/server.pem')

    def send_message(self, message):
        self.sock = socket.socket()
        self.sock.connect((self.host, self.port))
        self.wrapped_socket = self.context.wrap_socket(self.sock, server_hostname='server')

        self.wrapped_socket.sendall(message.encode('utf-8'))
        response = self.wrapped_socket.recv(1024)

        print(f"Received message from server: {response.decode('utf-8')}")

        self.wrapped_socket.close()
        self.sock.close()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        message = sys.argv[1]
    else:
        message = input("Enter a message to send to the server: ")

    SSLClient().send_message(message)