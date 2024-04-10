import socket, ssl, threading

class SSLServer:
    def __init__(self, host='localhost', port=4433):
        self.host = host
        self.port = port
        self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.context.load_cert_chain(certfile='E:/Projects/Kerb3ruX/Test/server.pem')

    def start(self):
        self.server_socket = socket.socket()
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen()
        print(f"Server listening on {self.host}:{self.port}")

        while True:
            client_socket, addr = self.server_socket.accept()
            thread = threading.Thread(target=self.handle_client, args=(client_socket, addr))
            thread.start()

    def handle_client(self, client_socket, addr):
        wrapped_socket = self.context.wrap_socket(client_socket, server_side=True)
        try:
            while True:
                data = wrapped_socket.recv(1024)
                if not data:
                    break
                print(f"Received message from {addr}: {data.decode('utf-8')}")
                wrapped_socket.sendall(data)
        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            wrapped_socket.close()

if __name__ == "__main__":
    SSLServer().start()