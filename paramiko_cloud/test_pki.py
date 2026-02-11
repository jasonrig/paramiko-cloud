from unittest import TestCase

from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1
from paramiko import ECDSAKey, RSAKey

from paramiko_cloud.pki import CertificateSigningRequest, CertificateParameters, DSSKey

rsa_key = RSAKey.generate(1024)
ecdsa_key = ECDSAKey.generate(SECP256R1())
dss_key = DSSKey.generate(1024) if DSSKey is not None else None


class PKITest(TestCase):
    def test_certificate_signing_request_serializable(self):
        keys = [rsa_key, ecdsa_key]
        if dss_key is not None:
            keys.append(dss_key)

        for key in keys:
            with self.subTest(
                "CSR from {} key can be serialized and deserialized".format(
                    key.get_name()
                )
            ):
                csr = CertificateSigningRequest(key, CertificateParameters())
                csr_reconstructed = CertificateSigningRequest.from_proto(csr.to_proto())
                self.assertEqual(
                    key.get_fingerprint(),
                    csr_reconstructed.public_key.get_fingerprint(),
                )
                for attr in dir(csr.cert_params):
                    if not attr.startswith("_"):
                        self.assertEqual(
                            getattr(csr.cert_params, attr),
                            getattr(csr_reconstructed.cert_params, attr),
                        )

    def test_dss_key_type_handling(self):
        csr = CertificateSigningRequest(rsa_key, CertificateParameters()).to_proto()
        csr.publicKeyType = "ssh-dss"
        if DSSKey is None:
            with self.assertRaises(NotImplementedError):
                CertificateSigningRequest.from_proto(csr)
        else:
            CertificateSigningRequest.from_proto(csr)
