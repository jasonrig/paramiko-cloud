from typing import cast

from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurve
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.hashes import HashAlgorithm
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from google.cloud import kms
from google.cloud.kms_v1 import Digest

from paramiko_cloud.base import BaseKeyECDSA, CloudSigningKey


class _GCPSigningKey(CloudSigningKey):
    """
    Provides signing operations to Paramiko for the Google Cloud Platform KMS-backed key
    Args:
        kms_client: a KMS client that can access the selected key
        key_name: the name of the key
        curve: the elliptic curve used for this key
    """

    def __init__(
        self,
        kms_client: kms.KeyManagementServiceClient,
        key_name: str,
        curve: EllipticCurve,
    ):
        super().__init__(curve)
        self.client = kms_client
        self.key_name = key_name

    def sign(self, data: bytes, signature_algorithm: ECDSA) -> bytes:
        """
        Calculate the signature for the given data

        Args:
            data: data for which to calculate a signature
            signature_algorithm: the curve used for this signature

        Returns:
            The DER formatted signature
        """
        if isinstance(signature_algorithm.algorithm, Prehashed):
            algorithm: HashAlgorithm = signature_algorithm.algorithm._algorithm
        else:
            algorithm = signature_algorithm.algorithm
        digest = Digest(
            mapping={algorithm.name: self.digest(data, signature_algorithm)}
        )
        signing_response = self.client.asymmetric_sign(
            name=self.key_name, digest=digest
        )
        return signing_response.signature


class ECDSAKey(BaseKeyECDSA):
    """
    A Google Cloud Platform KMS-based ECDSA key

    Args:
        kms_client: a `KMS client`_ that can access the selected key
        key_name: the name of the key

    .. _KMS client:
       https://googleapis.dev/python/cloudkms/latest/kms_v1/key_management_service.html#google.cloud.kms_v1.services.key_management_service.KeyManagementServiceClient
    """

    _ALLOWED_ALGOS = (
        "EC_SIGN_P256_SHA256",
        "EC_SIGN_P384_SHA384",
    )

    def __init__(self, kms_client: kms.KeyManagementServiceClient, key_name: str):
        pub_key = kms_client.get_public_key(name=key_name)
        assert pub_key.algorithm.name in self._ALLOWED_ALGOS, (
            "Unsupported signing algorithm: {}".format(pub_key.algorithm.name)
        )
        verifying_key = cast(
            EllipticCurvePublicKey, load_pem_public_key(pub_key.pem.encode())
        )
        super().__init__(
            (
                _GCPSigningKey(kms_client, pub_key.name, verifying_key.curve),
                verifying_key,
            )
        )
