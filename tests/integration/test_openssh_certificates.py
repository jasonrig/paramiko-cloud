import os
import subprocess
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1
from paramiko import ECDSAKey, RSAKey
from paramiko.pkey import PKey

from paramiko_cloud.pki import (
    CertificateCriticalOptions,
    CertificateExtensions,
    CertificateParameters,
    CertificateType,
)
from tests.helpers import write_openssh_public_blob

from .conftest import (
    INTEGRATION_ENV,
    SSH_USER,
    DummySigner,
    OpenSSHServer,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get(INTEGRATION_ENV) != "1",
        reason=f"set {INTEGRATION_ENV}=1 to run Docker integration tests",
    ),
]


def _write_identity(key: PKey, directory: Path, name: str) -> Path:
    identity_file = directory / name
    key.write_private_key_file(str(identity_file))
    identity_file.chmod(0o600)
    return identity_file


def _write_certificate(
    certificate_type: str,
    certificate: bytes,
    identity_file: Path,
) -> Path:
    certificate_file = identity_file.with_name(identity_file.name + "-cert.pub")
    write_openssh_public_blob(
        certificate_file,
        certificate_type,
        certificate,
        "integration-test-certificate",
    )
    return certificate_file


def _issue_user_certificate(
    signer: DummySigner,
    public_key: PKey,
    identity_file: Path,
    *,
    principals: list[str] | None = None,
    valid_after: int | None = None,
    valid_before: int | None = None,
    critical_options: dict[CertificateCriticalOptions, str] | None = None,
) -> Path:
    now = int(time.time())
    parameters = CertificateParameters(
        type=CertificateType.USER,
        key_id="protobuf-integration-test",
        serial=42,
        principals=[SSH_USER] if principals is None else principals,
        valid_after=valid_after if valid_after is not None else now - 30,
        valid_before=valid_before if valid_before is not None else now + 300,
        critical_options=critical_options or {},
        extensions={CertificateExtensions.PERMIT_PTY: ""},
    )
    response = signer.issue(public_key, parameters)
    return _write_certificate(
        response.certificateType,
        response.certificate,
        identity_file,
    )


def _assert_authentication_succeeds(
    signer: DummySigner,
    server: OpenSSHServer,
    key: PKey,
    tmp_path: Path,
    identity_name: str,
) -> None:
    identity_file = _write_identity(key, tmp_path, identity_name)
    certificate_file = _issue_user_certificate(
        signer,
        key,
        identity_file,
    )

    result = server.authenticate(identity_file, certificate_file)

    assert result.returncode == 0, result.stderr + "\n" + server.logs()
    assert result.stdout.strip() == SSH_USER
    signing_request = signer.servicer.last_signing_request
    assert signing_request is not None
    assert signing_request.kmsKeyId == "integration-test-ca"
    assert signing_request.signingRequestPayload.keyId == "protobuf-integration-test"
    assert signing_request.signingRequestPayload.serial == 42
    assert list(signing_request.signingRequestPayload.principals) == [SSH_USER]
    assert signing_request.signingRequestPayload.publicKeyType == key.get_name()


def _assert_authentication_rejected(
    result: subprocess.CompletedProcess[str],
) -> None:
    assert result.returncode != 0
    assert "Permission denied" in result.stderr


def test_server_runs_modern_openssh(openssh_server: OpenSSHServer) -> None:
    major, minor, version = openssh_server.version()

    assert (major, minor) >= (10, 0), version


def test_rsa_certificate_from_protobuf_csr_is_accepted(
    dummy_signer: DummySigner,
    openssh_server: OpenSSHServer,
    tmp_path: Path,
) -> None:
    _assert_authentication_succeeds(
        dummy_signer,
        openssh_server,
        RSAKey.generate(2048),
        tmp_path,
        "id_rsa",
    )


def test_ecdsa_certificate_from_protobuf_csr_is_accepted(
    dummy_signer: DummySigner,
    openssh_server: OpenSSHServer,
    tmp_path: Path,
) -> None:
    _assert_authentication_succeeds(
        dummy_signer,
        openssh_server,
        ECDSAKey.generate(SECP256R1()),
        tmp_path,
        "id_ecdsa",
    )


def test_certificate_for_another_principal_is_rejected(
    dummy_signer: DummySigner,
    openssh_server: OpenSSHServer,
    tmp_path: Path,
) -> None:
    key = RSAKey.generate(2048)
    identity_file = _write_identity(key, tmp_path, "wrong_principal")
    certificate_file = _issue_user_certificate(
        dummy_signer,
        key,
        identity_file,
        principals=["another-user"],
    )

    result = openssh_server.authenticate(identity_file, certificate_file)

    _assert_authentication_rejected(result)


@pytest.mark.standards
def test_text_critical_option_certificate_is_accepted(
    dummy_signer: DummySigner,
    openssh_server: OpenSSHServer,
    tmp_path: Path,
) -> None:
    key = RSAKey.generate(2048)
    identity_file = _write_identity(key, tmp_path, "source_address")
    certificate_file = _issue_user_certificate(
        dummy_signer,
        key,
        identity_file,
        critical_options={CertificateCriticalOptions.SOURCE_ADDRESS: "0.0.0.0/0"},
    )

    result = openssh_server.authenticate(identity_file, certificate_file)

    assert result.returncode == 0, result.stderr + "\n" + openssh_server.logs()
    assert result.stdout.strip() == SSH_USER


def test_expired_certificate_is_rejected(
    dummy_signer: DummySigner,
    openssh_server: OpenSSHServer,
    tmp_path: Path,
) -> None:
    key = RSAKey.generate(2048)
    identity_file = _write_identity(key, tmp_path, "expired")
    now = int(time.time())
    certificate_file = _issue_user_certificate(
        dummy_signer,
        key,
        identity_file,
        valid_after=now - 600,
        valid_before=now - 300,
    )

    result = openssh_server.authenticate(identity_file, certificate_file)

    _assert_authentication_rejected(result)
