import base64
import hashlib
import subprocess
import tempfile
from typing import Tuple

from paramiko.pkey import PKey


class ParsedCertificateResponse:
    def __init__(self, raw_output: str):
        self._parameters = dict()
        last_list_key = None
        last_list = list()
        for line in raw_output.splitlines(keepends=False)[1:]:
            line_parts = line.strip().split(":", maxsplit=1)
            try:
                key, value = line_parts
                if last_list_key is not None:
                    self._parameters[last_list_key] = last_list
                    last_list_key = None
                    last_list = list()
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


def parse_certificate(cert_string: str) -> Tuple[int, ParsedCertificateResponse]:
    with tempfile.NamedTemporaryFile() as f:
        f.write(cert_string.encode())
        f.flush()
        try:
            # Python 3.7+
            result = subprocess.run(["ssh-keygen", "-L", "-f", f.name], capture_output=True)
        except TypeError:
            # Python 3.6
            result = subprocess.run(["ssh-keygen", "-L", "-f", f.name], stdout=subprocess.PIPE)
        return result.returncode, ParsedCertificateResponse(result.stdout.decode())


def sha256_fingerprint(key: PKey) -> str:
    return base64.b64encode(
        hashlib.sha256(key.asbytes()).digest()
    ).decode().rstrip("=")
