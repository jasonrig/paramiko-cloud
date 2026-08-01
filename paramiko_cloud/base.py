import base64
import hashlib
import os
from abc import abstractmethod
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any, Protocol

from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH,
    ECDSA,
    EllipticCurve,
    EllipticCurvePrivateKey,
    EllipticCurvePrivateNumbers,
    EllipticCurvePublicKey,
    EllipticCurveSignatureAlgorithm,
)
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    KeySerializationEncryption,
    PrivateFormat,
)
from cryptography.utils import Buffer
from paramiko import ECDSAKey, Message
from paramiko.pkey import PEM, FileFormat

from paramiko_cloud.pki import CertificateSigningKeyMixin


class _SupportsWrite(Protocol):
    def write(self, data: str) -> object: ...


class CloudSigningKey(EllipticCurvePrivateKey):
    """
    Base class for all cloud KMS-backed signing keys
    """

    def __init__(self, public_key: EllipticCurvePublicKey):
        """
        Constructor

        Args:
            public_key: the public key corresponding to the cloud-managed key
        """

        self._public_key = public_key

    @property
    def curve(self) -> EllipticCurve:
        return self._public_key.curve

    @property
    def key_size(self) -> int:
        return self.curve.key_size

    def public_key(self) -> EllipticCurvePublicKey:
        return self._public_key

    def __copy__(self) -> "CloudSigningKey":
        return self

    def __deepcopy__(self, memo: dict[object, object]) -> "CloudSigningKey":
        return self

    def exchange(
        self, algorithm: ECDH, peer_public_key: EllipticCurvePublicKey
    ) -> bytes:
        raise RuntimeError("Key exchange is unavailable for cloud-managed keys")

    def private_numbers(self) -> EllipticCurvePrivateNumbers:
        raise RuntimeError("Private key material is managed externally")

    def private_bytes(
        self,
        encoding: Encoding,
        format: PrivateFormat,
        encryption_algorithm: KeySerializationEncryption,
    ) -> bytes:
        raise RuntimeError("Private key material is managed externally")

    @staticmethod
    def digest(
        data: Buffer,
        signature_algorithm: EllipticCurveSignatureAlgorithm,
    ) -> bytes:
        """
        Calculates the hash of the given data according to the given elliptic curve key

        Args:
            data: the data for which to calculate the hash
            signature_algorithm: the elliptic curve signature algorithm

        Returns:
            The hash of the data
        """
        if not isinstance(signature_algorithm, ECDSA):
            raise TypeError("Cloud-managed keys require an ECDSA signature algorithm")
        algorithm = signature_algorithm.algorithm
        if isinstance(algorithm, Prehashed):
            algorithm = algorithm._algorithm
        return getattr(hashlib, algorithm.name)(data).digest()

    @abstractmethod
    def sign(
        self,
        data: Buffer,
        signature_algorithm: EllipticCurveSignatureAlgorithm,
    ) -> bytes:
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
        self,
        filename: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        password: str | None = None,
        file_format: FileFormat = PEM,
    ) -> None:
        raise RuntimeError("Private key managed externally, cannot export")

    def write_private_key(
        self,
        file_obj: _SupportsWrite,
        password: str | None = None,
        file_format: FileFormat = PEM,
    ) -> None:
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
