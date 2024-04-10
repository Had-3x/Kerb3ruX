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
        if isinstance(Data, str):
            return "0x001"
        elif isinstance(Data, dict):
            return "0x002"
        else:
            raise Errors.UnknowType()

class Security:

    def __init__(self, keySize: int = 1024) -> None:
        '''
        Is used to generate a public and private key pair for RSA cryptography.\n
        Parameters:
        - keySize(int): Is the size of the key in bits. By default, 2048.\n
        Return:
        - A dictionary containing both, the public key(publicKey) and the private key(privateKey).
        '''
        self.privateKey = rsa.generate_private_key(65537, keySize)
        self.publicBytes = self.privateKey.public_key().public_bytes(encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        self.publicKey = serialization.load_pem_public_key(self.publicBytes)
    
    def Encrypt(self, Data: bytes, remoteKey: PublicKeyTypes) -> bytes:
        '''
        Is used to encrypt data using an RSA public key.\n
        Parameters:
        - Data(bytes): The text to be encrypted\n
        - remoteKey(RSAPublicKey): The public key with which the data is to be encrypted. This key needs to be loaded before use (See Load_PEM)\n
        Return:
        - Encrypted data in bytes
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
        Is used to decrypt data that has been encrypted with an RSA public key.\n
        Parameters:
        - Data(bytes): The set of bytes to be decrypted.
        - privateKey(RSAprivateKey): The private key with which the data is to be decrypted.
        - Encode(str): Decoding is performed using the encoding specified. By default is 'utf-8'.\n
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
        digest = hashlib.sha256()
        digest.update(Data)
        return digest.hexdigest()

    def LoadKey(self, remoteKey: bytes) -> PublicKeyTypes:
        return serialization.load_pem_public_key(remoteKey)

class Server:
    def __init__(self):
        logging.basicConfig(filename=f'{datetime.date.today()}.log', filemode='a', level=logging.DEBUG,
                            format='> [%(threadName)s] [%(asctime)s] [%(levelname)s]\n \t%(message)s',
                            datefmt='%I:%M:%S %p')
        self.executor = ThreadPoolExecutor(max_workers=5)
        self.clientAddrs = []

    def Listen(self, host='localhost', port=4433):
        listenerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listenerSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listenerSocket.bind((host, port))
        listenerSocket.listen()
        logging.info(f"Server listening on {host}:{port}")
        
        while True:
            remoteSocket, remoteAddr = listenerSocket.accept()
            #client_sockets.append(remoteSocket) Save To DB
            #client_addresses.append(remoteAddr) Save To DB
            logging.info(f"New Conecction from {remoteAddr}")
            self.clientAddrs.append(remoteAddr)
            self.executor.submit(self.Handle_client, remoteSocket, remoteAddr)

    def Handle_client(self, client_socket: socket.SocketType, remoteAddr: str):
        try:
            while True:
                RawData = client_socket.recv(2048)
                if not RawData:
                    break
                #Enviar Datos
                Data = re.findall("<*>", str(RawData))
                if (Data[0] == "2x000"):
                    if(Data[1] == remoteAddr):
                        ...
                logging.info(f"Recived Data From {remoteAddr}")
        except Exception as e:
            logging.warn(f"Error handling client: {e}")
        finally:
            client_socket.close()

    def Send(self, remoteAddr: str, data: bytes):
        if remoteAddr in self.clientAddrs:
            senderSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            senderSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                senderSocket.connect(remoteAddr)
            except ConnectionRefusedError as exception:
                self.clientAddrs.remove(remoteAddr)
            else:
                self.executor.submit(senderSocket.sendall, data)
            finally:
                senderSocket.close()
        else:
            ...

class Client:
    def __init__(self, remoteInfo: tuple[str | None, int], localInfo: tuple[str, str, int, int]):
        self.remoteAddr = remoteInfo
        self.security = Security()
        self.name = localInfo[0] #Program Name, Generated By Server
        self.passphrase = localInfo[1] #Generated by Server, NO CLIENT, ENCRYPTED
        self.bufSize = localInfo[2]
        self.port = localInfo[3]
        self.ip = get('https://checkip.amazonaws.com').text.strip()
        
    def Connect(self, Data):
        try:
            sock = socket.create_connection(self.remoteAddr, timeout=30)
        except ConnectionRefusedError as error:
            ...
        else:
            content = f"<{getCode(Data)}><{str(Data).encode()}>".encode()
            header = f"<2x000><{self.ip}><{self.name}><{self.passphrase}><{getsizeof(content)}>".encode()
            tail = f"<0x005><{self.security.Hash(str(Data).encode())}>".encode()
            
            
        finally:
            sock.close()

    def Listen(self):
        sock = socket.create_server(("localhost", 0))
        
#https://www.blackbox.ai/share/f5ed0ee8-3cbc-4a95-bb74-69b8628f9b74 - Exceptions and Types
#https://www.blackbox.ai/share/2f4e302f-535a-4833-801e-4d9e14db52dd
#(?<!\\)<.*?(?<!\\)> - Regex for data

