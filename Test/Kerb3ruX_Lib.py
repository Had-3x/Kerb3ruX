from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes, PrivateKeyTypes
import socket, hashlib, logging, datetime, re
from concurrent.futures import ThreadPoolExecutor
from requests import get
from sys import getsizeof

class Errors:
    class ResponseFormatError(Exception):
        ...
    class UnknowType(Exception):
        ...

def getCode(Data) -> str:
    ''' 
    Returns the transmission code based on the type of data provided. (see: Transmision Codes Table).
    '''
    if isinstance(Data, str):
        return "0x001"
    elif isinstance(Data, dict):
        return "0x002"
    else:
        raise Errors.UnknowType()

class Security:

    def __init__(self, keySize: int = 1024) -> None:
        self.privateKey = rsa.generate_private_key(65537, keySize)
        self.publicBytes = self.privateKey.public_key().public_bytes(encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        self.publicKey = serialization.load_pem_public_key(self.publicBytes)
    
    def Encrypt(self, Data: bytes, remoteKey: PublicKeyTypes) -> bytes:
        '''
        Is used to encrypt data using an RSA public key.
        Parameters:
        - Data(bytes): The text to be encrypted
        - remoteKey(RSAPublicKey): The public key with which the data is to be encrypted. This key needs to be loaded before use (See Load_PEM)
        Return:
        - Bytes -> Encrypted data
        '''
        if isinstance(remoteKey, rsa.RSAPublicKey):
            text = remoteKey.encrypt(
                Data,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                ))
            return text
        else:
            raise Exception("No RSA Key")

    def Decrypt(self, Data: bytes, Encode: str ='utf-8') -> str:
        '''
        Is used to decrypt data that has been encrypted with an RSA public key.
        Parameters:
        - Data(bytes): The set of bytes to be decrypted.
        - privateKey(RSAprivateKey): The private key with which the data is to be decrypted.
        - Encode(str): Decoding is performed using the encoding specified. By default is 'utf-8'.
        Return:
        - A text string with decrypted data.
        '''

        text = self.privateKey.decrypt(
            Data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            ))
        return text.decode(Encode)

    def Hash(self, Data: bytes) -> str:
        '''
        Calculate the Hash of the provided data.
        Parameters:
        - Data(Bytes): The data to be Hashed
        Return:
        - Str -> Hash
        '''
        digest = hashlib.sha256()
        digest.update(Data)
        return digest.hexdigest()

    def LoadKey(self, remoteKey: bytes) -> PublicKeyTypes:
        '''
        Loads the bytes of a remote public key for its use.
        Parameters:
        - remoteKey(bytes): Public key in bytes.
        Return:
        - PublicKeyTypes -> Public key for use.
        '''
        return serialization.load_pem_public_key(remoteKey)

class Server:
    def __init__(self):
        logging.basicConfig(filename=f'{datetime.date.today()}.log', filemode='a', level=logging.DEBUG,
                            format='> [%(threadName)s] [%(asctime)s] [%(levelname)s]\n \t%(message)s',
                            datefmt='%I:%M:%S %p') # Configure how logs will be stored 
        self.executor = ThreadPoolExecutor(max_workers=5) # Create a Thread Pool to manage processes
        self.clientAddrs = [] # List to storage slave's ip

    def Listen(self, host: str = 'localhost', port: int = 4433):
        '''
        Listen for incoming connections on the specified HOST and PORT (default localhost:4433).
        Parameters:
        - host(str): Ip or Domain to listen.
        - port(int): Port to listen.
        Return:
        - NULL
        '''
        listenerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Create Socket
        listenerSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listenerSocket.bind((host, port)) # Assign the socket to the host and port
        listenerSocket.listen() # Listen for connections
        logging.info(f"Server listening on {host}:{port}") # Log listening
        
        while True:
            remoteSocket, remoteAddr = listenerSocket.accept() # Accept Connections
            #client_sockets.append(remoteSocket) Save To DB
            #client_addresses.append(remoteAddr) Save To DB
            logging.info(f"New Conecction from {remoteAddr}") # Log new connection
            self.clientAddrs.append(remoteAddr) # Save connection address
            self.executor.submit(self.Handle_client, remoteSocket, remoteAddr) # Create thread for connection

    def Handle_client(self, client_socket: socket.SocketType, remoteAddr: str):
        try:
            while True:
                RawData = client_socket.recv(2048) # Receive data
                if not RawData:
                    break # If recieved data is empty, close the connection
                Data = re.findall(r'(?<!\\)<.*?(?<!\\)>', str(RawData)) # Divide data into fields separated by <>.
                if (Data[0] == "2x000"): # Data is a new connection request
                    if(Data[1] == remoteAddr): # check if the sender's ip matches the declared ip
                        ...
                logging.info(f"Recived Data From {remoteAddr}") # Log data
        except Exception as e:
            logging.warn(f"Error handling client: {e}")
        finally:
            client_socket.close()

    def Connect(self, remoteAddr: str, data: bytes):
        if remoteAddr in self.clientAddrs: # Check for known ip
            senderSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Create Socket
            senderSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                senderSocket.connect(remoteAddr) # Try connection
            except ConnectionRefusedError as exception:
                self.clientAddrs.remove(remoteAddr) # Remove dead slave
            else:
                self.executor.submit(senderSocket.sendall, data) # Create thread for connection
            finally:
                senderSocket.close()
        else:
            ...

class Client:
    def __init__(self, remoteInfo: tuple[str | None, int], localInfo: tuple[str, str, int, int]):
        self.remoteAddr = remoteInfo # Server data for sockets
        self.security = Security() # Create an instance of security class
        self.name = localInfo[0] # Program Name, Generated By Server
        self.passphrase = localInfo[1] # Generated by Server, NO CLIENT, ENCRYPTED
        self.bufSize = localInfo[2] # Buffer Size for sockets
        self.port = localInfo[3] # Local port to use
        self.ip = get('https://checkip.amazonaws.com').text.strip() # Public Ip for checks
        
    def Connect(self, Data):
        try:
            sock = socket.create_connection(self.remoteAddr, timeout=30) # Connect to server
        except ConnectionRefusedError as error:
            ...
        else:
            content = f"<{getCode(Data)}><{str(Data).encode()}>".encode() # Data to send
            header = f"<2x000><{self.ip}><{self.name}><{self.passphrase}><{getsizeof(content)}>".encode() # Header of connection
            tail = f"<0x005><{self.security.Hash(str(Data).encode())}>".encode() # Tail of connection
        finally:
            sock.close()

    def Listen(self):
        sock = socket.create_server(("localhost", 0))
        
#https://www.blackbox.ai/share/f5ed0ee8-3cbc-4a95-bb74-69b8628f9b74 - Exceptions and Types
#https://www.blackbox.ai/share/2f4e302f-535a-4833-801e-4d9e14db52dd
#(?<!\\)<.*?(?<!\\)> - Regex for data

