from typing import Tuple
from unittest import TestCase
from unittest.mock import patch, Mock

from azure.keyvault.keys import KeyVaultKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurve
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature
from cryptography.hazmat.primitives.hashes import HashAlgorithm
from paramiko.rsakey import RSAKey

from paramiko_cloud.test_helpers import parse_certificate, sha256_fingerprint


class _SigningResponse:
    def __init__(self, signature):
        self.signature = signature


def set_up_mocks(key_client_mock: Mock, crypto_client_mock: Mock, curve: EllipticCurve, hash_algo: HashAlgorithm,
                 key_name: str):
    priv_key = ec.generate_private_key(curve)
    pub_key = priv_key.public_key().public_numbers()

    crypto_client_instance = crypto_client_mock.return_value

    def sign(_, digest):
        signature = priv_key.sign(
            digest,
            ec.ECDSA(Prehashed(hash_algo))
        )
        r, s = decode_dss_signature(signature)
        return _SigningResponse(r.to_bytes(128, "big") + s.to_bytes(128, "big"))

    crypto_client_instance.sign.side_effect = sign
    key_client_instance = key_client_mock.return_value
    key_client_instance.get_key.return_value = KeyVaultKey(key_name, jwk={
        "kty": "EC",
        "crv": "P-{}".format(curve.key_size),
        "x": int.to_bytes(pub_key.x, 128, "big"),
        "y": int.to_bytes(pub_key.y, 128, "big")
    })


class TestECDSAKey(TestCase):
    ALL_SUPPORTED_ALGOS: Tuple[Tuple[EllipticCurve, HashAlgorithm]] = (
        (ec.SECP256R1(), hashes.SHA256()),
        (ec.SECP384R1(), hashes.SHA384()),
        (ec.SECP521R1(), hashes.SHA512())
    )

    TEST_KEY_NAME = "https://test-vault.vault.azure.net/keys/abc/1"

    @patch("azure.keyvault.keys.crypto.CryptographyClient")
    @patch("azure.keyvault.keys.KeyClient")
    def test_key_from_cloud_can_sign(self, key_client_mock: Mock, crypto_client_mock: Mock):
        from paramiko_cloud.azure.keys import ECDSAKey
        for curve, hash_ in self.ALL_SUPPORTED_ALGOS:
            with self.subTest("Using curve {} and hash {}".format(curve.name, hash_.name)):
                set_up_mocks(key_client_mock, crypto_client_mock, curve, hash_, self.TEST_KEY_NAME)
                key = ECDSAKey(None, None, "test_key")
                signature = key.sign_ssh_data(b"hello world")
                signature.rewind()
                self.assertTrue(key.verify_ssh_sig(b"hello world", signature), "Signature is invalid")

    @patch("azure.keyvault.keys.crypto.CryptographyClient")
    @patch("azure.keyvault.keys.KeyClient")
    def test_key_from_cloud_can_produce_valid_certificate(self, key_client_mock: Mock, crypto_client_mock: Mock):
        from paramiko_cloud.azure.keys import ECDSAKey
        for curve, hash_ in self.ALL_SUPPORTED_ALGOS:
            with self.subTest("Using curve {} and hash {}".format(curve.name, hash_.name)):
                set_up_mocks(key_client_mock, crypto_client_mock, curve, hash_, self.TEST_KEY_NAME)
                ca_key = ECDSAKey(None, None, "test_key")
                client_key = RSAKey.generate(1024)
                cert_string = ca_key.sign_certificate(client_key, ["test.user"]).cert_string()
                exit_code, cert_details = parse_certificate(cert_string)
                self.assertEqual(
                    cert_details.public_key,
                    "RSA-CERT SHA256:{}".format(sha256_fingerprint(client_key))
                )
                self.assertEqual(
                    cert_details.signing_ca,
                    "ECDSA SHA256:{} (using ecdsa-sha2-nistp{})".format(
                        sha256_fingerprint(ca_key),
                        ca_key.ecdsa_curve.key_length
                    )
                )
                self.assertEqual(
                    exit_code, 0,
                    "Could not parse generated certificate with ssh-keygen, exit code {}".format(
                        exit_code
                    )
                )
