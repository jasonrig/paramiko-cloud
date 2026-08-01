from unittest import TestCase

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from google.cloud.kms_v1 import AsymmetricSignResponse, Digest
from google.cloud.kms_v1.types.resources import CryptoKeyVersion, PublicKey

from paramiko_cloud.gcp.keys import ECDSAKey
from tests.helpers import assert_valid_certificate


class MockKeyManagementServiceClient:
    def __init__(self, expected_key_name: str, algo: int):
        self.expected_key_name = expected_key_name
        self.algo = algo
        if algo == CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_P256_SHA256:
            self.private_key = ec.generate_private_key(ec.SECP256R1())
        elif algo == CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_P384_SHA384:
            self.private_key = ec.generate_private_key(ec.SECP384R1())
        else:
            raise NotImplementedError()

    def get_public_key(self, name) -> PublicKey:
        assert name == self.expected_key_name
        pem_key = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return PublicKey(pem=pem_key, algorithm=self.algo, name=name)

    def asymmetric_sign(self, name, digest: Digest) -> AsymmetricSignResponse:
        assert name == self.expected_key_name
        digest_algo_pairs = (
            (digest.sha256, ec.ECDSA(Prehashed(hashes.SHA256()))),
            (digest.sha384, ec.ECDSA(Prehashed(hashes.SHA384()))),
            (digest.sha512, ec.ECDSA(Prehashed(hashes.SHA512()))),
        )
        hash_ = next(filter(lambda d: bool(d[0]), digest_algo_pairs))
        return AsymmetricSignResponse(signature=self.private_key.sign(*hash_))


class TestECDSAKey(TestCase):
    ALL_SUPPORTED_ALGOS: tuple[int, ...] = (
        CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_P256_SHA256,
        CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_P384_SHA384,
    )

    TEST_KEY_NAME = "test_key"

    def test_key_from_cloud_can_sign(self):
        for algo in self.ALL_SUPPORTED_ALGOS:
            with self.subTest(f"Using {algo.name}"):
                key = ECDSAKey(
                    MockKeyManagementServiceClient(self.TEST_KEY_NAME, algo), "test_key"
                )
                signature = key.sign_ssh_data(b"hello world")
                signature.rewind()
                self.assertTrue(
                    key.verify_ssh_sig(b"hello world", signature),
                    "Signature is invalid",
                )

    def test_key_from_cloud_can_produce_valid_certificate(self):
        for algo in self.ALL_SUPPORTED_ALGOS:
            with self.subTest(f"Using {algo.name}"):
                ca_key = ECDSAKey(
                    MockKeyManagementServiceClient(self.TEST_KEY_NAME, algo), "test_key"
                )
                assert_valid_certificate(self, ca_key)
