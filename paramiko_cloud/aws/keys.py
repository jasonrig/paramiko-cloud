from typing import Set

import boto3
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurve
from cryptography.hazmat.primitives.serialization import load_der_public_key

from paramiko_cloud.base import BaseKeyECDSA, CloudSigningKey


class _AWSSigningKey(CloudSigningKey):
    """
    Provides signing operations to Paramiko for the AWS KMS-backed key
    """

    def __init__(self, client, key_id: str, signing_algo: str, curve: EllipticCurve):
        """
        Constructor

        Args:
            client: the AWS KMS client from boto3
            key_id: the AWS KMS key id
            signing_algo: the signing algorithm to use
            curve: the elliptic curve used for this key
        """

        super().__init__(curve)
        self.client = client
        self.key_id = key_id
        self.signing_algo = signing_algo

    def sign(self, data: bytes, signature_algorithm: ECDSA) -> bytes:
        """
        Calculate the signature for the given data

        Args:
            data: data for which to calculate a signature
            signature_algorithm: the curve used for this signature

        Returns:
            The DER formatted signature
        """

        hash_ = self.digest(data, signature_algorithm)
        signing_response = self.client.sign(
            KeyId=self.key_id,
            Message=hash_,
            MessageType="DIGEST",
            GrantTokens=[
                'string',
            ],
            SigningAlgorithm=self.signing_algo
        )
        return signing_response["Signature"]


class ECDSAKey(BaseKeyECDSA):
    """
    An AWS KMS-based ECDSA key

    Args:
        key_id: the AWS KMS key id
        **kwargs: extra parameters passed to the Boto3 kms client, see the `Boto3 documentation`_.

    .. _Boto3 documentation:
       https://boto3.amazonaws.com/v1/documentation/api/latest/reference/core/session.html#boto3.session.Session.client
    """

    _ALLOWED_ALGOS = (
        ("ECC_NIST_P256", "ECDSA_SHA_256"),
        ("ECC_NIST_P384", "ECDSA_SHA_384"),
        ("ECC_NIST_P521", "ECDSA_SHA_512"),
    )

    def __init__(self, key_id: str, **kwargs):
        client = boto3.client('kms', **kwargs)
        pub_key = client.get_public_key(
            KeyId=key_id,
            GrantTokens=[
                'string',
            ]
        )

        assert any(
            signing_algo in pub_key["SigningAlgorithms"] and
            key_spec == pub_key["CustomerMasterKeySpec"]
            for key_spec, signing_algo in self._ALLOWED_ALGOS), \
            "No supported key/algorithm pair found."
        assert pub_key["KeyUsage"] == "SIGN_VERIFY", "Key does not support signing."

        verifying_key = load_der_public_key(pub_key["PublicKey"])

        super().__init__(
            (
                _AWSSigningKey(
                    client,
                    key_id,
                    self._choose_signing_algo(set(pub_key["SigningAlgorithms"])), verifying_key.curve),
                verifying_key
            )
        )

    def _choose_signing_algo(self, supported_algos: Set[str]) -> str:
        """
        Selects the appropriate signing algorithm based on the supported and offered signing algorithms

        Args:
            supported_algos: the list of supported algorithms provided by AWS

        Returns:
            The selected signing algorithm
        """

        return set([algo for _, algo in self._ALLOWED_ALGOS]).intersection(supported_algos).pop()
