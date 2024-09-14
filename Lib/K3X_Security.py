from cryptography import x509, exceptions
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.x509.oid import NameOID

import datetime
import K3X_Exceptions

class Utils:
    
    ROOT_CERTIFICATE_PROFILE = x509.CertificateBuilder(
    ).add_extension(    
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ), critical=True
    ).add_extension(x509.BasicConstraints(ca=True, path_length=None), 
                    critical=True
    ).serial_number(x509.random_serial_number()
    ).not_valid_after(datetime.datetime.now() + datetime.timedelta(days = 365 * 10))
    
    INTERMEDIATE_CERTIFICATE_PROFILE = x509.CertificateBuilder(
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ), critical=True
    ).add_extension(x509.BasicConstraints(ca=False, path_length=None),
                    critical=True
    ).serial_number(x509.random_serial_number()
    ).not_valid_after(datetime.datetime.now() + datetime.timedelta(days = 365 * 5))

    ENDPOINT_CERTIFICATE_PROFILE = x509.CertificateBuilder(
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ), critical=True,
    ).add_extension(x509.BasicConstraints(ca=False, path_length=None),
                    critical=True,
    ).serial_number(x509.random_serial_number()
    ).not_valid_after(datetime.datetime.now() + datetime.timedelta(days = 365 * 1))

class Security:
    
    Private_Key: rsa.RSAPrivateKey
    Public_Key:  rsa.RSAPublicKey
    Certificate: x509.Certificate | None
    Certificate_Revokation_List: list[x509.RevokedCertificate]
    
    def __init__(self, Private_Key: rsa.RSAPrivateKey, Certificate: x509.Certificate | None = None):
        
        self.Private_Key = Private_Key
        self.Public_Key = Private_Key.public_key()
        self.Certificate = Certificate if (Certificate) else None
        
    def RevokeCRT(self, Cert: x509.Certificate, Reason: x509.ReasonFlags = x509.ReasonFlags.unspecified) -> x509.RevokedCertificate:
          
        revoked_cert = x509.RevokedCertificateBuilder(
            ).serial_number(
                Cert.serial_number
            ).revocation_date(
                datetime.datetime.today()
            ).add_extension(
                x509.CRLReason(Reason),
                critical=True
            ).build()

        return revoked_cert
    
    def GenCSR(self, DNS_Names: list[str], Common_Name: str, Filepath: str | None = None
               ) -> x509.CertificateSigningRequest:
        
        CSR = x509.CertificateSigningRequestBuilder()
        CSR = CSR.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, Common_Name),
        ]))

        DNS_List: list[x509.DNSName] = []
        for i in DNS_Names:
            DNS_List.append(x509.DNSName(i)) 

        CSR = CSR.add_extension(
            x509.SubjectAlternativeName(DNS_List),
            critical=False,
        )
        CSR = CSR.sign(self.Private_Key, hashes.SHA256())
        
        if(Filepath):
            with open(Filepath, "wb") as f:
                f.write(CSR.public_bytes(serialization.Encoding.PEM))
        
        return CSR
    
    def GenCRL(self, FilePath: str | None) -> x509.CertificateRevocationList:
        
        if(self.Certificate_Revokation_List):
            if (self.Certificate):
                CRL = x509.CertificateRevocationListBuilder(
                ).issuer_name(
                    self.Certificate.subject
                ).last_update(datetime.datetime.today()
                ).next_update(datetime.datetime.today() + datetime.timedelta(days = 1))
                
                for i in self.Certificate_Revokation_List:
                    CRL.add_revoked_certificate(i)
                
                CRL = CRL.sign(self.Private_Key, hashes.SHA256())
                
                if (FilePath):
                    with open(FilePath, "wb") as file:
                        file.write(CRL.public_bytes(encoding=serialization.Encoding.PEM))
                return CRL
            else:
                raise K3X_Exceptions.CertificateInicializationError
        else:
            raise K3X_Exceptions.CertificateRevokationListEmpty
    
    def GenCRT(self, Subject_CSR: x509.CertificateSigningRequest, 
               Profile: x509.CertificateBuilder, Filepath: str | None = None
            ) -> x509.Certificate:
        
        Cert = Profile.subject_name(
            Subject_CSR.subject
        ).issuer_name(
            self.Certificate.subject if (self.Certificate) else (Subject_CSR.subject)
        ).public_key(
            Subject_CSR.public_key()
        ).not_valid_before(
            datetime.datetime.today()
        ).add_extension(
            Subject_CSR.extensions.get_extension_for_class(x509.SubjectAlternativeName).value,
            critical=False
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(Subject_CSR.public_key()),
            critical=False
        )
        
        if (self.Certificate):
            Cert = Cert.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                    self.Certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value) ,
                critical=False
            )
        
        Cert = Cert.sign(self.Private_Key, hashes.SHA256())
        
        if (Filepath):
            with open(Filepath, "wb")as file:
                file.write(Cert.public_bytes(serialization.Encoding.PEM))
        
        return Cert

    @staticmethod
    def GenRSAPrivateKey(Key_Size: int, Filepath: str | None = None, Passphrase: bytes | None = None
                      ) -> rsa.RSAPrivateKey: 
        
        Private_Key = rsa.generate_private_key(65537, Key_Size)
        if(Filepath):
            if(Passphrase):
                with open(Filepath, "wb") as file:
                    file.write(Private_Key.private_bytes(
                        encoding = serialization.Encoding.PEM,
                        format = serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm = serialization.BestAvailableEncryption(Passphrase)
                    ))
            else:
                with open(Filepath, "wb") as file:
                    file.write(Private_Key.private_bytes(
                        encoding = serialization.Encoding.PEM,
                        format = serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm = serialization.NoEncryption()
                    ))
        
        return Private_Key
    
    def Hash(self, Data: bytes) -> bytes:
        
        digest = hashes.Hash(hashes.SHA256())
        List = [Data[i:i+1024] for i in range(0,len(Data)-1,1024)]
        for i in List:
            digest.update(i)
        
        return digest.finalize()
    
    def Sign(self, Data: bytes) -> bytes:
        
        Hash = self.Hash(Data)
        signature = self.Private_Key.sign(
            Hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(hashes.SHA256())
        )
        
        return signature
    
    def VerifySign(self, Signature: bytes, Data: bytes, Public_Key: rsa.RSAPublicKey):
        
        Hash = self.Hash(Data)
        try:
            Public_Key.verify(
                Signature,
                Hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                utils.Prehashed(hashes.SHA256())
            )
        except (exceptions.InvalidSignature): 
            return False
        else:
            return True
    
    def Encrypt(self, Data: bytes):
        
        Result = self.Public_Key.encrypt(
            Data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return Result
    
    def Decrypt(self, Data: bytes):
        
        Result = self.Private_Key.decrypt(
            Data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return Result