import abc
import base64
import hashlib
from datetime import datetime
from typing import Tuple, Optional, IO, Callable, Any

from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePublicKey, EllipticCurve
from paramiko import ECDSAKey, Message

from paramiko_cloud.pki import CertificateSigningKeyMixin


class CloudSigningKey(abc.ABC):
    """
    Base class for all cloud KMS-backed signing keys
    """

    def __init__(self, curve: EllipticCurve):
        """
        Constructor

        Args:
            curve: the elliptic curve used for this key
        """

        self.curve = curve

    @staticmethod
    def digest(data: bytes, ec: ECDSA) -> bytes:
        """
        Calculates the hash of the given data according to the given elliptic curve key

        Args:
            data: the data for which to calculate the hash
            ec: the elliptic curve key that will use the hash

        Returns:
            The hash of the data
        """
        return getattr(hashlib, ec.algorithm.name)(data).digest()

    def sign(self, data, signature_algorithm: ECDSA) -> bytes:
        """
        Calculate the signature for the given data

        Args:
            data: data for which to calculate a signature
            signature_algorithm: the curve used for this signature

        Returns:
            The DER formatted signature
        """

        raise NotImplementedError()


class BaseKeyECDSA(ECDSAKey, CertificateSigningKeyMixin):
    """
    Base class for all cloud-backed ECDSA keys
    """

    def __init__(self, vals: Tuple[CloudSigningKey, EllipticCurvePublicKey]):
        """
        Constructor

        Args:
            vals: tuple of signing key and verifying key
        """
        super().__init__(vals=vals)

    def write_private_key_file(self, filename: str, password: Optional[str] = ...):
        raise RuntimeError("Private key managed externally, cannot export")

    def write_private_key(self, file_obj: IO[str], password: Optional[str] = ...):
        raise RuntimeError("Private key managed externally, cannot export")

    @classmethod
    def generate(
            cls, curve: EllipticCurve = ..., progress_func: Optional[Callable[..., Any]] = ...,
            bits: Optional[int] = ...
    ):
        raise RuntimeError("Create new signing keys using the KMS client for your cloud provider")

    def pubkey_string(self, comment=None) -> str:
        """
        Render a string suitable for OpenSSH authorized_keys files

        Args:
            comment: an optional comment, defaulting to the current date and time in ISO format

        Returns:
            The public key string
        """
        key_bytes = self.asbytes()
        m = Message(self.asbytes())
        key_type = m.get_text()
        return "{key_type} {pubkey_string} {comment}".format(
            key_type=key_type,
            pubkey_string=base64.standard_b64encode(key_bytes).decode(),
            comment=comment or datetime.now().isoformat()
        )
