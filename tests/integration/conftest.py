import logging
import os
import re
import shutil
import subprocess
import uuid
from collections.abc import Iterator
from concurrent import futures
from dataclasses import dataclass
from pathlib import Path

import grpc
import pytest
from paramiko.pkey import PKey

from paramiko_cloud.dummy.keys import ECDSAKey as DummyECDSAKey
from paramiko_cloud.pki import CertificateParameters, CertificateSigningRequest
from paramiko_cloud.protobuf import rpc_pb2, rpc_pb2_grpc
from tests.helpers import dummy_ecdsa_ca, write_openssh_public_blob

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILE = Path(__file__).parent / "openssh" / "compose.yaml"
INTEGRATION_ENV = "RUN_OPENSSH_INTEGRATION"
SSH_USER = "certuser"
LOGGER = logging.getLogger(__name__)


class DummySignerServicer(rpc_pb2_grpc.SignerServicer):
    """A local gRPC signing service backed by paramiko-cloud's dummy key."""

    def __init__(self, ca_key: DummyECDSAKey):
        self.ca_key = ca_key
        self.last_signing_request: rpc_pb2.CloudCertificateSigningRequest | None = None

    def SignCertificate(
        self,
        request: rpc_pb2.CloudCertificateSigningRequest,
        context: grpc.ServicerContext,
    ) -> rpc_pb2.CloudCertificateSigningResponse:
        self.last_signing_request = request
        signing_request = CertificateSigningRequest.from_proto(
            request.signingRequestPayload
        )
        certificate = signing_request.sign(self.ca_key)

        response = rpc_pb2.CloudCertificateSigningResponse()
        response.certificateType = certificate.key_type
        response.certificate = certificate.key_blob
        return response

    def GetCertificateAuthority(
        self,
        request: rpc_pb2.GetCertificateAuthorityRequest,
        context: grpc.ServicerContext,
    ) -> rpc_pb2.GetCertificateAuthorityResponse:
        response = rpc_pb2.GetCertificateAuthorityResponse()
        response.keyType = self.ca_key.get_name()
        response.publicKey = self.ca_key.asbytes()
        return response


@dataclass(frozen=True)
class DummySigner:
    stub: rpc_pb2_grpc.SignerStub
    servicer: DummySignerServicer

    def issue(
        self,
        public_key: PKey,
        parameters: CertificateParameters,
    ) -> rpc_pb2.CloudCertificateSigningResponse:
        request = rpc_pb2.CloudCertificateSigningRequest()
        request.provider = rpc_pb2.CloudProvider.AWS
        request.kmsKeyId = "integration-test-ca"
        request.signingRequestPayload.CopyFrom(
            CertificateSigningRequest(public_key, parameters).to_proto()
        )
        return self.stub.SignCertificate(request)

    def get_ca(self) -> rpc_pb2.GetCertificateAuthorityResponse:
        request = rpc_pb2.GetCertificateAuthorityRequest()
        request.provider = rpc_pb2.CloudProvider.AWS
        request.kmsKeyId = "integration-test-ca"
        return self.stub.GetCertificateAuthority(request)


@dataclass(frozen=True)
class OpenSSHServer:
    port: int
    project_name: str
    compose_environment: dict[str, str]

    def compose(
        self,
        *arguments: str,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "docker",
                "compose",
                "--file",
                str(COMPOSE_FILE),
                "--project-name",
                self.project_name,
                *arguments,
            ],
            cwd=REPOSITORY_ROOT,
            env=self.compose_environment,
            check=check,
            capture_output=True,
            text=True,
        )

    def authenticate(
        self,
        identity_file: Path,
        certificate_file: Path,
        command: str = "id -un",
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "ssh",
                "-F",
                os.devnull,
                "-p",
                str(self.port),
                "-o",
                "BatchMode=yes",
                "-o",
                "CertificateFile=" + str(certificate_file),
                "-o",
                "ConnectTimeout=10",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "IdentityAgent=none",
                "-o",
                "LogLevel=ERROR",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=" + os.devnull,
                "-i",
                str(identity_file),
                f"{SSH_USER}@127.0.0.1",
                command,
            ],
            cwd=REPOSITORY_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )

    def version(self) -> tuple[int, int, str]:
        result = self.compose("exec", "-T", "openssh", "sshd", "-V")
        output = result.stdout + result.stderr
        match = re.search(r"(OpenSSH_(\d+)\.(\d+)[^\r\n]*)", output)
        if match is None:
            raise AssertionError(f"Unable to parse OpenSSH version from: {output}")
        return int(match.group(2)), int(match.group(3)), match.group(1)

    def alpine_version(self) -> str:
        result = self.compose(
            "exec",
            "-T",
            "openssh",
            "cat",
            "/etc/alpine-release",
        )
        return result.stdout.strip()

    def logs(self) -> str:
        result = self.compose("logs", "--no-color", check=False)
        return result.stdout + result.stderr


def _require_integration_prerequisites() -> None:
    missing = [
        command for command in ("docker", "ssh") if shutil.which(command) is None
    ]
    if missing:
        pytest.fail("Missing OpenSSH integration prerequisites: " + ", ".join(missing))

    result = subprocess.run(
        ["docker", "info"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.fail("Docker daemon is unavailable:\n" + result.stderr)


@pytest.fixture(scope="session")
def dummy_signer() -> Iterator[DummySigner]:
    ca_key = dummy_ecdsa_ca()
    servicer = DummySignerServicer(ca_key)

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))
    rpc_pb2_grpc.add_SignerServicer_to_server(servicer, server)
    port = server.add_insecure_port("127.0.0.1:0")
    server.start()

    channel = grpc.insecure_channel(f"127.0.0.1:{port}")
    grpc.channel_ready_future(channel).result(timeout=10)
    try:
        yield DummySigner(rpc_pb2_grpc.SignerStub(channel), servicer)
    finally:
        channel.close()
        server.stop(0).wait()


@pytest.fixture(scope="session")
def openssh_server(
    dummy_signer: DummySigner,
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[OpenSSHServer]:
    _require_integration_prerequisites()

    ca_response = dummy_signer.get_ca()
    ca_file = tmp_path_factory.mktemp("openssh-ca") / "trusted_user_ca_keys"
    write_openssh_public_blob(
        ca_file,
        ca_response.keyType,
        ca_response.publicKey,
        "integration-test-ca",
    )
    ca_file.chmod(0o644)

    project_name = "paramiko-cloud-openssh-" + uuid.uuid4().hex[:12]
    compose_environment = {
        **os.environ,
        "OPENSSH_TEST_CA_PUBLIC_KEY": str(ca_file),
    }
    server = OpenSSHServer(0, project_name, compose_environment)

    try:
        up_result = server.compose(
            "up",
            "--detach",
            "--build",
            "--wait",
            "--wait-timeout",
            "90",
            check=False,
        )
        if up_result.returncode != 0:
            pytest.fail(
                "Unable to start the OpenSSH integration container:\n"
                + up_result.stdout
                + up_result.stderr
                + server.logs()
            )

        port_result = server.compose("port", "openssh", "22")
        port = int(port_result.stdout.strip().rsplit(":", maxsplit=1)[1])
        running_server = OpenSSHServer(port, project_name, compose_environment)
        container_id = running_server.compose(
            "ps",
            "--quiet",
            "openssh",
        ).stdout.strip()
        if not container_id:
            pytest.fail("OpenSSH integration container is not running")
        LOGGER.info(
            "OpenSSH container %s is ready on 127.0.0.1:%d",
            container_id,
            port,
        )
        yield running_server
    finally:
        server.compose(
            "down",
            "--volumes",
            "--remove-orphans",
            check=False,
        )
