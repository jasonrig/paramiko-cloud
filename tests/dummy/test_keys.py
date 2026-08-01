import copy
from unittest import TestCase

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from paramiko_cloud.dummy.keys import ECDSAKey
from tests.helpers import assert_valid_certificate

private_key = ec.generate_private_key(ec.SECP256R1()).private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)


class TestECDSAKey(TestCase):
    def test_key_from_cloud_can_sign(self):
        key = ECDSAKey(private_key)
        signature = key.sign_ssh_data(b"hello world")
        signature.rewind()
        self.assertTrue(
            key.verify_ssh_sig(b"hello world", signature), "Signature is invalid"
        )

    def test_cloud_private_key_adapter(self):
        key = ECDSAKey(private_key)
        signing_key = key.signing_key

        self.assertIs(signing_key.public_key(), key.verifying_key)
        self.assertEqual(signing_key.curve, key.verifying_key.curve)
        self.assertEqual(signing_key.key_size, key.verifying_key.key_size)
        self.assertIs(copy.copy(signing_key), signing_key)
        self.assertIs(copy.deepcopy(signing_key), signing_key)

        exchange_algorithm = ec.ECDH()
        peer_public_key = signing_key.public_key()
        with self.assertRaises(RuntimeError):
            signing_key.exchange(exchange_algorithm, peer_public_key)
        with self.assertRaises(RuntimeError):
            signing_key.private_numbers()
        encoding = serialization.Encoding.PEM
        private_format = serialization.PrivateFormat.PKCS8
        encryption = serialization.NoEncryption()
        with self.assertRaises(RuntimeError):
            signing_key.private_bytes(encoding, private_format, encryption)

    def test_key_from_cloud_can_produce_valid_certificate(self):
        ca_key = ECDSAKey(private_key)
        assert_valid_certificate(self, ca_key)
