from unittest import TestCase

from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1
from paramiko.dsskey import DSSKey
from paramiko.ecdsakey import ECDSAKey
from paramiko.rsakey import RSAKey

from paramiko_cloud.pki import CertificateSigningRequest, CertificateParameters

rsa_key = RSAKey.generate(1024)
dss_key = DSSKey.generate(1024)
ecdsa_key = ECDSAKey.generate(SECP256R1())


class PKITest(TestCase):
    def test_certificate_signing_request_serializable(self):
        for key in (rsa_key, dss_key, ecdsa_key):
            with self.subTest("CSR from {} key can be serialized and deserialized".format(key.get_name())):
                csr = CertificateSigningRequest(key, CertificateParameters())
                csr_reconstructed = CertificateSigningRequest.from_proto(csr.to_proto())
                self.assertEqual(key.get_fingerprint(), csr_reconstructed.public_key.get_fingerprint())
                for attr in dir(csr.cert_params):
                    if not attr.startswith("_"):
                        self.assertEqual(getattr(csr.cert_params, attr), getattr(csr_reconstructed.cert_params, attr))
