from unittest import TestCase

from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1
from paramiko import ECDSAKey, RSAKey

from paramiko_cloud.pki import (
    CertificateExtensions,
    CertificateParameters,
    CertificateSigningRequest,
    DSSKey,
    _optional_pkey_type,
)
from paramiko_cloud.protobuf.csr_pb2 import CSR

rsa_key = RSAKey.generate(1024)
ecdsa_key = ECDSAKey.generate(SECP256R1())


class PKITest(TestCase):
    def test_certificate_signing_request_serializable(self):
        keys = [rsa_key, ecdsa_key]
        for key in keys:
            with self.subTest(
                f"CSR from {key.get_name()} key can be serialized and deserialized"
            ):
                csr = CertificateSigningRequest(
                    key,
                    CertificateParameters(principals=["test.user"]),
                )
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
        csr = CertificateSigningRequest(
            rsa_key,
            CertificateParameters(principals=["test.user"]),
        ).to_proto()
        csr.publicKeyType = "ssh-dss"
        if DSSKey is None:
            with self.assertRaises(NotImplementedError):
                CertificateSigningRequest.from_proto(csr)
        else:
            CertificateSigningRequest.from_proto(csr)

    def test_optional_pkey_type_discovery(self):
        self.assertIs(_optional_pkey_type({"DSSKey": RSAKey}, "DSSKey"), RSAKey)
        self.assertIsNone(_optional_pkey_type({}, "DSSKey"))
        self.assertIsNone(_optional_pkey_type({"DSSKey": object}, "DSSKey"))

    def test_certificate_extensions_serialize_to_proto(self):
        csr = CertificateSigningRequest(
            rsa_key,
            CertificateParameters(
                principals=["test.user"],
                extensions={CertificateExtensions.NO_TOUCH_REQUIRED: ""},
            ),
        ).to_proto()

        self.assertEqual(CSR.Extension.NO_TOUCH_REQUIRED, csr.extensions[0].type)
