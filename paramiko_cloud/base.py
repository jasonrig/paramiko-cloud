import abc
import base64
import hashlib
from collections.abc import Callable
from datetime import datetime, timezone
from typing import IO, Any

from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA,
    EllipticCurve,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
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
    def digest(data: bytes, signature_algorithm: ECDSA) -> bytes:
        """
        Calculates the hash of the given data according to the given elliptic curve key

        Args:
            data: the data for which to calculate the hash
            signature_algorithm: the elliptic curve signature algorithm

        Returns:
            The hash of the data
        """
        algorithm = signature_algorithm.algorithm
        if isinstance(algorithm, Prehashed):
            algorithm = algorithm._algorithm
        return getattr(hashlib, algorithm.name)(data).digest()

    def sign(self, data: bytes, signature_algorithm: ECDSA) -> bytes:
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

    def __init__(self, vals: tuple[CloudSigningKey, EllipticCurvePublicKey]):
        """
        Constructor

        Args:
            vals: tuple of signing key and verifying key
        """
        super().__init__(vals=vals)

    def write_private_key_file(
        self, filename: str, password: str | None = None
    ) -> None:
        raise RuntimeError("Private key managed externally, cannot export")

    def write_private_key(self, file_obj: IO[str], password: str | None = None) -> None:
        raise RuntimeError("Private key managed externally, cannot export")

    @classmethod
    def generate(
        cls,
        curve: EllipticCurve | None = None,
        progress_func: Callable[..., Any] | None = None,
        bits: int | None = None,
    ) -> "BaseKeyECDSA":
        raise RuntimeError(
            "Create new signing keys using the KMS client for your cloud provider"
        )

    def pubkey_string(self, comment: str | None = None) -> str:
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
        return f"{key_type} {base64.standard_b64encode(key_bytes).decode()} {comment or datetime.now(timezone.utc).isoformat()}"
