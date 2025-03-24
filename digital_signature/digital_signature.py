from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key, Encoding, PublicFormat, PrivateFormat, NoEncryption

class DigitalSignature:
    def __init__(self, security_parameter=256):
        self.security_parameter = security_parameter
        self.private_key = None
        self.public_key = None

    def key_generation(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
        return self.private_key, self.public_key

    def sign(self, message: bytes):
        if self.private_key is None:
            raise ValueError("Private key not generated. Run key_generation() first.")
        signature = self.private_key.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )
        return signature

    def verify(self, message: bytes, signature: bytes):
        if self.public_key is None:
            raise ValueError("Public key not generated. Run key_generation() first.")
        try:
            self.public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False

    def serialize_keys(self):
        private_pem = self.private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        )
        public_pem = self.public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        )
        return private_pem, public_pem

    def load_keys(self, private_pem: bytes, public_pem: bytes):
        # self.private_key = load_pem_private_key(private_pem, password=None)
        self.public_key = load_pem_public_key(public_pem)
