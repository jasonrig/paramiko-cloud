from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
    EllipticCurveSignatureAlgorithm,
)
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.utils import Buffer

from paramiko_cloud.base import BaseKeyECDSA, CloudSigningKey


class _LocalSigningKey(CloudSigningKey):
    """
    A dummy signing key
    """

    def __init__(
        self,
        key: EllipticCurvePrivateKey,
        public_key: EllipticCurvePublicKey,
    ):
        super().__init__(public_key)
        self.key = key

    def sign(
        self,
        data: Buffer,
        signature_algorithm: EllipticCurveSignatureAlgorithm,
    ) -> bytes:
        return self.key.sign(data, signature_algorithm)


class ECDSAKey(BaseKeyECDSA):
    """
    A dummy key that demonstrates the abstraction, but just loads they key from file.

    Args:
        pem_private_key: A PEM-formatted private key
        password: An optional password to decrypt the private key
    """

    def __init__(self, pem_private_key: bytes, password: bytes | None = None):
        private_key = load_pem_private_key(pem_private_key, password)
        if not isinstance(private_key, EllipticCurvePrivateKey):
            raise TypeError("PEM private key is not an elliptic curve key")
        public_key = private_key.public_key()
        super().__init__((_LocalSigningKey(private_key, public_key), public_key))
