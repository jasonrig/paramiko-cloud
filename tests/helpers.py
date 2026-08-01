import base64
import hashlib
import subprocess
import tempfile
from unittest import TestCase

from paramiko.pkey import PKey
from paramiko.rsakey import RSAKey

from paramiko_cloud.base import BaseKeyECDSA


class ParsedCertificateResponse:
    def __init__(self, raw_output: str):
        self._parameters: dict[str, str | list[str]] = {}
        last_list_key = None
        last_list = []
        for line in raw_output.splitlines(keepends=False)[1:]:
            line_parts = line.strip().split(":", maxsplit=1)
            try:
                key, value = line_parts
                if last_list_key is not None:
                    self._parameters[last_list_key] = last_list
                    last_list_key = None
                    last_list = []
                if len(value) > 0:
                    self._parameters[key] = value.strip()
                else:
                    last_list_key = key
            except ValueError:
                last_list.append(line_parts[0].strip())
        if last_list_key is not None:
            self._parameters[last_list_key] = last_list

    @property
    def type(self):
        return self._parameters["Type"]

    @property
    def public_key(self):
        return self._parameters["Public key"]

    @property
    def signing_ca(self):
        return self._parameters["Signing CA"]

    @property
    def key_id(self):
        return self._parameters["Key ID"]

    @property
    def serial(self):
        return self._parameters["Serial"]

    @property
    def valid(self):
        return self._parameters["Valid"]

    @property
    def principals(self):
        return self._parameters["Principals"]

    @property
    def critical_options(self):
        return self._parameters["Critical Options"]

    @property
    def extensions(self):
        return self._parameters["Extensions"]


def parse_certificate(cert_string: str) -> tuple[int, ParsedCertificateResponse]:
    with tempfile.NamedTemporaryFile() as f:
        f.write(cert_string.encode())
        f.flush()
        try:
            # Python 3.7+
            result = subprocess.run(
                ["ssh-keygen", "-L", "-f", f.name],
                capture_output=True,
                check=False,
            )
        except TypeError:
            # Python 3.6
            result = subprocess.run(
                ["ssh-keygen", "-L", "-f", f.name],
                stdout=subprocess.PIPE,
                check=False,
            )
        return result.returncode, ParsedCertificateResponse(result.stdout.decode())


def sha256_fingerprint(key: PKey) -> str:
    return base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


def assert_valid_certificate(test_case: TestCase, ca_key: BaseKeyECDSA) -> None:
    client_key = RSAKey.generate(1024)
    cert_string = ca_key.sign_certificate(client_key, ["test.user"]).cert_string()
    exit_code, cert_details = parse_certificate(cert_string)

    test_case.assertEqual(
        cert_details.public_key,
        f"RSA-CERT SHA256:{sha256_fingerprint(client_key)}",
    )
    assert ca_key.ecdsa_curve is not None
    test_case.assertEqual(
        cert_details.signing_ca,
        f"ECDSA SHA256:{sha256_fingerprint(ca_key)} "
        f"(using ecdsa-sha2-nistp{ca_key.ecdsa_curve.key_length})",
    )
    test_case.assertEqual(
        exit_code,
        0,
        f"Could not parse generated certificate with ssh-keygen, exit code {exit_code}",
    )
