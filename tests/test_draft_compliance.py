import pytest
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)
from paramiko import RSAKey
from paramiko.pkey import PKey

from paramiko_cloud.pki import (
    CertificateCriticalOptions,
    CertificateExtensions,
    CertificateKeyTypeFormat,
    CertificateParameters,
    CertificateSigningRequest,
    CertificateType,
    Ed448Key,
)
from paramiko_cloud.protobuf.csr_pb2 import CSR
from tests.helpers import ParsedCertificateResponse, dummy_ecdsa_ca, parse_certificate

pytestmark = pytest.mark.standards


def _inspect_certificate(
    certificate_signing_request: CertificateSigningRequest,
    signing_key: PKey,
) -> ParsedCertificateResponse:
    certificate = certificate_signing_request.sign(signing_key)
    exit_code, details = parse_certificate(certificate.cert_string())
    assert exit_code == 0
    return details


def test_text_critical_option_is_a_single_nested_string() -> None:
    signing_request = CertificateSigningRequest(
        RSAKey.generate(2048),
        CertificateParameters(
            principals=["certuser"],
            critical_options={CertificateCriticalOptions.SOURCE_ADDRESS: "0.0.0.0/0"},
        ),
    )

    details = _inspect_certificate(signing_request, dummy_ecdsa_ca())

    assert details.critical_options == ["source-address 0.0.0.0/0"]


def test_verify_required_is_available_in_public_api() -> None:
    option = CertificateCriticalOptions("verify-required")

    assert option.name == "VERIFY_REQUIRED"


def test_verify_required_round_trips_through_protobuf_csr() -> None:
    csr = CertificateSigningRequest(
        RSAKey.generate(2048),
        CertificateParameters(principals=["certuser"]),
    ).to_proto()
    option = csr.criticalOptions.add()
    option.type = CSR.CriticalOption.VERIFY_REQUIRED
    option.value = ""

    signing_request = CertificateSigningRequest.from_proto(csr)

    assert signing_request.cert_params.critical_opts == [
        (CertificateCriticalOptions("verify-required"), "")
    ]


def test_verify_required_is_encoded_as_an_empty_flag() -> None:
    signing_request = CertificateSigningRequest(
        RSAKey.generate(2048),
        CertificateParameters(
            principals=["certuser"],
            critical_options={CertificateCriticalOptions.VERIFY_REQUIRED: ""},
        ),
    )

    details = _inspect_certificate(signing_request, dummy_ecdsa_ca())

    assert details.critical_options == ["verify-required"]


def test_empty_principal_list_is_rejected_by_issuer() -> None:
    with pytest.raises(ValueError, match="principal"):
        CertificateParameters(principals=[])


def test_standard_certificate_key_type_is_emitted() -> None:
    certificate = dummy_ecdsa_ca().sign_certificate(
        RSAKey.generate(2048),
        ["certuser"],
        extensions={},
        key_type_format=CertificateKeyTypeFormat.STANDARD,
    )

    assert certificate.key_type == "ssh-rsa-cert"


def test_openssh_certificate_key_type_remains_the_default() -> None:
    signing_request = CertificateSigningRequest(
        RSAKey.generate(2048),
        CertificateParameters(principals=["certuser"]),
    )

    certificate = signing_request.sign(dummy_ecdsa_ca())

    assert certificate.key_type == "ssh-rsa-cert-v01@openssh.com"


def test_ed448_public_key_handling_follows_paramiko_support() -> None:
    public_key = Ed448PrivateKey.generate().public_key()
    csr = CSR()
    csr.type = CSR.Type.USER
    csr.principals.append("certuser")
    csr.publicKeyType = "ssh-ed448"
    csr.publicKey = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    if Ed448Key is None:
        with pytest.raises(
            NotImplementedError,
            match="Key type not supported by Paramiko: ssh-ed448",
        ):
            CertificateSigningRequest.from_proto(csr)
    else:
        signing_request = CertificateSigningRequest.from_proto(csr)
        assert signing_request.public_key.get_name() == "ssh-ed448"


def test_nonempty_flag_extension_value_is_rejected_by_issuer() -> None:
    with pytest.raises(ValueError, match="empty"):
        CertificateParameters(
            principals=["certuser"],
            extensions={CertificateExtensions.PERMIT_PTY: "unexpected-value"},
        )


def test_nonempty_verify_required_value_is_rejected_by_issuer() -> None:
    with pytest.raises(ValueError, match="empty"):
        CertificateParameters(
            principals=["certuser"],
            critical_options={
                CertificateCriticalOptions.VERIFY_REQUIRED: "unexpected-value"
            },
        )


def test_host_certificate_has_no_user_extensions_by_default() -> None:
    certificate = dummy_ecdsa_ca().sign_certificate(
        RSAKey.generate(2048),
        ["host.example"],
        type=CertificateType.HOST,
    )
    exit_code, details = parse_certificate(certificate.cert_string())

    assert exit_code == 0
    assert details.extensions == "(none)"


def test_user_certificate_keeps_user_extensions_by_default() -> None:
    certificate = dummy_ecdsa_ca().sign_certificate(
        RSAKey.generate(2048),
        ["certuser"],
    )
    exit_code, details = parse_certificate(certificate.cert_string())

    assert exit_code == 0
    assert details.extensions == [
        "no-touch-required",
        "permit-X11-forwarding",
        "permit-agent-forwarding",
        "permit-port-forwarding",
        "permit-pty",
        "permit-user-rc",
    ]


def test_explicit_empty_user_extensions_are_preserved() -> None:
    certificate = dummy_ecdsa_ca().sign_certificate(
        RSAKey.generate(2048),
        ["certuser"],
        extensions={},
    )
    exit_code, details = parse_certificate(certificate.cert_string())

    assert exit_code == 0
    assert details.extensions == "(none)"


def test_rsa_ca_is_rejected() -> None:
    signing_request = CertificateSigningRequest(
        RSAKey.generate(2048),
        CertificateParameters(principals=["certuser"]),
    )

    with pytest.raises(
        NotImplementedError,
        match="RSA certificate authority keys are not supported",
    ):
        signing_request.sign(RSAKey.generate(2048))
