from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import socket

def Crypt_Setup(keySize: int = 4096, ) -> dict:
    privateKey = rsa.generate_private_key(65537, keySize)
    publicKey = privateKey.public_key().public_bytes(encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    
    return {"publicKey": publicKey, "privateKey": privateKey}

def Crypt(data: bytes, remoteKey: rsa.RSAPublicKey) -> bytes:
    text = remoteKey.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ))
    return text

def Decrypt(data: bytes, privateKey: rsa.RSAPrivateKey, encode: str ='utf-8') -> str:
    text = privateKey.decrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ))
    return text.decode(encode)

