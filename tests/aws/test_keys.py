from unittest import TestCase
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurve
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.hashes import HashAlgorithm

from tests.helpers import assert_valid_certificate


def set_up_mocks(boto3_mock: Mock, curve: EllipticCurve, hash_algo: HashAlgorithm):
    priv_key = ec.generate_private_key(curve)
    pem_key = priv_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    signing_algorithm_name = f"ECDSA_SHA_{hash_algo.name[-3:]}"
    key_spec_name = f"ECC_NIST_P{curve.key_size}"

    boto3_instance = boto3_mock.return_value
    boto3_instance.get_public_key.return_value = {
        "SigningAlgorithms": [signing_algorithm_name],
        "CustomerMasterKeySpec": key_spec_name,
        "KeyUsage": "SIGN_VERIFY",
        "PublicKey": pem_key,
    }

    def sign(KeyId, Message, MessageType, GrantTokens, SigningAlgorithm):
        assert SigningAlgorithm == signing_algorithm_name
        return {"Signature": priv_key.sign(Message, ec.ECDSA(Prehashed(hash_algo)))}

    boto3_instance.sign.side_effect = sign


class TestECDSAKey(TestCase):
    ALL_SUPPORTED_ALGOS: tuple[tuple[EllipticCurve, HashAlgorithm], ...] = (
        (ec.SECP256R1(), hashes.SHA256()),
        (ec.SECP384R1(), hashes.SHA384()),
        (ec.SECP521R1(), hashes.SHA512()),
    )

    @patch("boto3.client")
    def test_key_from_cloud_can_sign(self, boto3_mock: Mock):
        from paramiko_cloud.aws.keys import ECDSAKey

        for curve, hash_ in self.ALL_SUPPORTED_ALGOS:
            with self.subTest(f"Using curve {curve.name} and hash {hash_.name}"):
                set_up_mocks(boto3_mock, curve, hash_)
                key = ECDSAKey("test_key", region_name="ap-northeast-1")
                signature = key.sign_ssh_data(b"hello world")
                signature.rewind()
                self.assertTrue(
                    key.verify_ssh_sig(b"hello world", signature),
                    "Signature is invalid",
                )

    @patch("boto3.client")
    def test_key_from_cloud_can_produce_valid_certificate(self, boto3_mock: Mock):
        from paramiko_cloud.aws.keys import ECDSAKey

        for curve, hash_ in self.ALL_SUPPORTED_ALGOS:
            with self.subTest(f"Using curve {curve.name} and hash {hash_.name}"):
                set_up_mocks(boto3_mock, curve, hash_)
                ca_key = ECDSAKey("test_key", region_name="ap-northeast-1")
                assert_valid_certificate(self, ca_key)
