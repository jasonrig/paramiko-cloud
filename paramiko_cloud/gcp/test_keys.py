from typing import Tuple
from unittest import TestCase

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from google.cloud.kms_v1 import AsymmetricSignResponse, Digest
from google.cloud.kms_v1.types.resources import PublicKey, CryptoKeyVersion
from paramiko.rsakey import RSAKey

from paramiko_cloud.gcp.keys import ECDSAKey
from paramiko_cloud.test_helpers import parse_certificate, sha256_fingerprint


class MockKeyManagementServiceClient:
    def __init__(self, expected_key_name, algo: CryptoKeyVersion.CryptoKeyVersionAlgorithm):
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
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return PublicKey(
            pem=pem_key,
            algorithm=self.algo,
            name=name
        )

    def asymmetric_sign(self, name, digest: Digest) -> AsymmetricSignResponse:
        assert name == self.expected_key_name
        digest_algo_pairs = (
            (digest.sha256, ec.ECDSA(Prehashed(hashes.SHA256()))),
            (digest.sha384, ec.ECDSA(Prehashed(hashes.SHA384()))),
            (digest.sha512, ec.ECDSA(Prehashed(hashes.SHA512()))),
        )
        hash_ = next(filter(lambda d: bool(d[0]), digest_algo_pairs))
        return AsymmetricSignResponse(
            signature=self.private_key.sign(*hash_)
        )


class TestECDSAKey(TestCase):
    ALL_SUPPORTED_ALGOS: Tuple[CryptoKeyVersion.CryptoKeyVersionAlgorithm] = (
        CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_P256_SHA256,
        CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_P384_SHA384
    )

    TEST_KEY_NAME = "test_key"

    def test_key_from_cloud_can_sign(self):
        for algo in self.ALL_SUPPORTED_ALGOS:
            with self.subTest("Using {}".format(algo.name)):
                key = ECDSAKey(MockKeyManagementServiceClient(self.TEST_KEY_NAME, algo), "test_key")
                signature = key.sign_ssh_data(b"hello world")
                signature.rewind()
                self.assertTrue(key.verify_ssh_sig(b"hello world", signature), "Signature is invalid")

    def test_key_from_cloud_can_produce_valid_certificate(self):
        for algo in self.ALL_SUPPORTED_ALGOS:
            with self.subTest("Using {}".format(algo.name)):
                ca_key = ECDSAKey(MockKeyManagementServiceClient(self.TEST_KEY_NAME, algo), "test_key")
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
