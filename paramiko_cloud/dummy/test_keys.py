from unittest import TestCase

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from paramiko.rsakey import RSAKey

from paramiko_cloud.dummy.keys import ECDSAKey
from paramiko_cloud.test_helpers import parse_certificate, sha256_fingerprint

private_key = ec.generate_private_key(ec.SECP256R1()).private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)


class TestECDSAKey(TestCase):
    def test_key_from_cloud_can_sign(self):
        key = ECDSAKey(private_key)
        signature = key.sign_ssh_data(b"hello world")
        signature.rewind()
        self.assertTrue(key.verify_ssh_sig(b"hello world", signature), "Signature is invalid")

    def test_key_from_cloud_can_produce_valid_certificate(self):
        ca_key = ECDSAKey(private_key)
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
