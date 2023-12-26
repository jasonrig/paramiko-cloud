from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, ECDSA
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from paramiko_cloud.base import BaseKeyECDSA, CloudSigningKey


class _LocalSigningKey(CloudSigningKey):
    """
    A dummy signing key
    """
    def __init__(self, key: EllipticCurvePrivateKey):
        super().__init__(key.curve)
        self.key = key

    def sign(self, data: bytes, signature_algorithm: ECDSA) -> bytes:
        return self.key.sign(data, signature_algorithm)


class ECDSAKey(BaseKeyECDSA):
    """
    A dummy key that demonstrates the abstraction, but just loads they key from file.

    Args:
        pem_private_key: A PEM-formatted private key
        password: An optional password to decrypt the private key
    """
    def __init__(self, pem_private_key: bytes, password: Optional[bytes] = None):
        private_key: EllipticCurvePrivateKey = load_pem_private_key(pem_private_key, password)
        public_key = private_key.public_key()
        super().__init__((_LocalSigningKey(private_key), public_key))
