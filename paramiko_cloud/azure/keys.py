from typing import Union

from azure.identity import DefaultAzureCredential, AzurePowerShellCredential, InteractiveBrowserCredential, \
    ChainedTokenCredential, EnvironmentCredential, ManagedIdentityCredential, SharedTokenCacheCredential, \
    AzureCliCredential, VisualStudioCodeCredential
from azure.keyvault.keys import KeyClient
from azure.keyvault.keys.crypto import CryptographyClient, SignatureAlgorithm
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePublicNumbers, SECP256R1, \
    SECP384R1, SECP521R1, SECP224R1, SECP192R1, EllipticCurve
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from paramiko_cloud.base import BaseKeyECDSA, CloudSigningKey

_CURVES = {
    "P-256": SECP256R1,
    "P-384": SECP384R1,
    "P-521": SECP521R1,
    "P-224": SECP224R1,
    "P-192": SECP192R1,
}


class _AzureSigningKey(CloudSigningKey):
    """
    Provides signing operations to Paramiko for the Azure Key Vault-backed key

    Args:
        crypto_client: the Key Vault Cryptography Client authenticated to access the selected key
        curve: the elliptic curve used for this key
    """

    def __init__(self, crypto_client: CryptographyClient, curve: EllipticCurve):
        super().__init__(curve)
        self.crypto_client = crypto_client

    def _signaure_algorithm(self) -> SignatureAlgorithm:
        """
        Selects the appropriate signature algorithm given the curve

        Returns:
            A suitable signature algorithm
        """

        if isinstance(self.curve, SECP256R1):
            return SignatureAlgorithm.es256
        elif isinstance(self.curve, SECP384R1):
            return SignatureAlgorithm.es384
        elif isinstance(self.curve, SECP521R1):
            return SignatureAlgorithm.es512
        else:
            raise NotImplementedError("Unsupported EC signature algorithm")

    def sign(self, data: bytes, signature_algorithm: ECDSA) -> bytes:
        """
        Calculate the signature for the given data

        Args:
            data: data for which to calculate a signature
            signature_algorithm: the curve used for this signature

        Returns:
            The DER formatted signature
        """

        digest = self.digest(data, signature_algorithm)
        signing_response = self.crypto_client.sign(self._signaure_algorithm(), digest)
        raw_signature = signing_response.signature
        r = int.from_bytes(raw_signature[:len(raw_signature) // 2], "big")
        s = int.from_bytes(raw_signature[len(raw_signature) // 2:], "big")
        return encode_dss_signature(r, s)


class ECDSAKey(BaseKeyECDSA):
    """
    An Azure Key Vault-backed ECDSA key

    Args:
        credential: an `Azure credential`_ suitable for accessing the key in Key Vault
        vault_url: the vault URL
        key_name: the name of the key in the vault

    .. _Azure credential:
       https://docs.microsoft.com/en-us/azure/developer/python/azure-sdk-authenticate
    """

    _ALLOWED_ALGOS = (
        "EC",
    )

    def __init__(self, credential: Union[DefaultAzureCredential, AzurePowerShellCredential,
                                         InteractiveBrowserCredential, ChainedTokenCredential, EnvironmentCredential,
                                         ManagedIdentityCredential, SharedTokenCacheCredential, AzureCliCredential,
                                         VisualStudioCodeCredential],
                 vault_url: str, key_name: str):
        vault_client = KeyClient(vault_url, credential=credential)
        pub_key = vault_client.get_key(key_name)
        assert pub_key.key_type in self._ALLOWED_ALGOS, "Unsupported signing algorithm: {}".format(pub_key.key_type)

        assert pub_key.key.crv in _CURVES, "Unsupported curve: {}".format(pub_key.key.crv)

        curve = _CURVES[pub_key.key.crv]()

        verifying_key = EllipticCurvePublicNumbers(
            int.from_bytes(pub_key.key.x, "big"),
            int.from_bytes(pub_key.key.y, "big"),
            curve
        ).public_key()

        super().__init__(
            (
                _AzureSigningKey(CryptographyClient(pub_key, credential), verifying_key.curve),
                verifying_key
            )
        )
