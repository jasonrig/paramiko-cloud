from typing import Tuple
from unittest import TestCase
from unittest.mock import patch, Mock

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurve
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.hashes import HashAlgorithm
from paramiko.rsakey import RSAKey

from paramiko_cloud.test_helpers import parse_certificate, sha256_fingerprint


def set_up_mocks(boto3_mock: Mock, curve: EllipticCurve, hash_algo: HashAlgorithm):
    priv_key = ec.generate_private_key(curve)
    pem_key = priv_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    signing_algorithm_name = "ECDSA_SHA_{}".format(hash_algo.name[-3:])
    key_spec_name = "ECC_NIST_P{}".format(curve.key_size)

    boto3_instance = boto3_mock.return_value
    boto3_instance.get_public_key.return_value = {
        "SigningAlgorithms": [signing_algorithm_name],
        "CustomerMasterKeySpec": key_spec_name,
        "KeyUsage": "SIGN_VERIFY",
        "PublicKey": pem_key
    }

    def sign(KeyId, Message, MessageType, GrantTokens, SigningAlgorithm):
        assert SigningAlgorithm == signing_algorithm_name
        return {
            "Signature": priv_key.sign(
                Message,
                ec.ECDSA(Prehashed(hash_algo))
            )
        }

    boto3_instance.sign.side_effect = sign


class TestECDSAKey(TestCase):
    ALL_SUPPORTED_ALGOS: Tuple[Tuple[EllipticCurve, HashAlgorithm]] = (
        (ec.SECP256R1(), hashes.SHA256()),
        (ec.SECP384R1(), hashes.SHA384()),
        (ec.SECP521R1(), hashes.SHA512())
    )

    @patch("boto3.client")
    def test_key_from_cloud_can_sign(self, boto3_mock: Mock):
        from paramiko_cloud.aws.keys import ECDSAKey
        for curve, hash_ in self.ALL_SUPPORTED_ALGOS:
            with self.subTest("Using curve {} and hash {}".format(curve.name, hash_.name)):
                set_up_mocks(boto3_mock, curve, hash_)
                key = ECDSAKey("test_key", region_name="ap-northeast-1")
                signature = key.sign_ssh_data(b"hello world")
                signature.rewind()
                self.assertTrue(key.verify_ssh_sig(b"hello world", signature), "Signature is invalid")

    @patch("boto3.client")
    def test_key_from_cloud_can_produce_valid_certificate(self, boto3_mock: Mock):
        from paramiko_cloud.aws.keys import ECDSAKey
        for curve, hash_ in self.ALL_SUPPORTED_ALGOS:
            with self.subTest("Using curve {} and hash {}".format(curve.name, hash_.name)):
                set_up_mocks(boto3_mock, curve, hash_)
                ca_key = ECDSAKey("test_key", region_name="ap-northeast-1")
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
