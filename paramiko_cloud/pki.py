import base64
import datetime
import enum
import secrets
import time
from collections.abc import Iterable, Mapping
from typing import Any, TypeVar

import paramiko
from paramiko import ECDSAKey, Ed25519Key, RSAKey
from paramiko.message import Message
from paramiko.pkey import PKey, PublicBlob

from paramiko_cloud.protobuf.csr_pb2 import CSR

T = TypeVar("T")


def _optional_pkey_type(
    namespace: Mapping[str, object], name: str
) -> type[PKey] | None:
    candidate = namespace.get(name)
    if isinstance(candidate, type) and issubclass(candidate, PKey):
        return candidate
    return None


DSSKey = _optional_pkey_type(vars(paramiko), "DSSKey")


def _require_type(value: object, expected: type[T], name: str) -> T:
    if not isinstance(value, expected):
        raise TypeError(f"{name} must be {expected.__name__}")
    return value


def _require_str_list(value: object, name: str) -> list[str]:
    if not isinstance(value, Iterable) or isinstance(value, (str, bytes)):
        raise TypeError(f"{name} must be a list of strings")
    items = list(value)
    if not all(isinstance(item, str) for item in items):
        raise TypeError(f"{name} must be a list of strings")
    return items


def _require_options(
    value: object,
    key_type: type[T],
    name: str,
) -> dict[T, str]:
    if not isinstance(value, dict) or not all(
        isinstance(key, key_type) and isinstance(option, str)
        for key, option in value.items()
    ):
        raise TypeError(f"{name} must map {key_type.__name__} values to strings")
    return value


class CertificateBlob(PublicBlob):
    """
    A signed SSH certificate
    """

    def cert_string(self, comment: str | None = None) -> str:
        """
        Render a string suitable for OpenSSH authorized_keys files

        Args:
            comment: an optional comment, defaulting to the current date and time in ISO format

        Returns:
            The public key string
        """

        return f"{self.key_type} {base64.standard_b64encode(self.key_blob).decode()} {comment or datetime.datetime.now(datetime.timezone.utc).isoformat()}"


class CertificateType(enum.Enum):
    """
    The type of certificate to issue
    """

    # https://github.com/openssh/openssh-portable/blob/2b71010d9b43d7b8c9ec1bf010beb00d98fa765a/PROTOCOL.certkeys#L73
    USER = 1

    # https://github.com/openssh/openssh-portable/blob/2b71010d9b43d7b8c9ec1bf010beb00d98fa765a/PROTOCOL.certkeys#L74
    HOST = 2

    def pb_enum(self) -> CSR.Type:
        """
        Converts the enum into the correct protobuf value for serialization

        Returns:
            The serialized enum value
        """

        return getattr(CSR.Type, self.name)

    @classmethod
    def from_pb_enum(cls, value: int) -> "CertificateType":
        """
        Deserializes the enum value

        Args:
            value: the serialized enum value

        Returns:
            The original enum value
        """

        return getattr(cls, CSR.Type.Name(value))


class CertificateCriticalOptions(enum.Enum):
    """
    `Certificate critical options`_

    .. _Certificate critical options:
       https://github.com/openssh/openssh-portable/blob/2b71010d9b43d7b8c9ec1bf010beb00d98fa765a/PROTOCOL.certkeys#L221
    """

    # https://github.com/openssh/openssh-portable/blob/2b71010d9b43d7b8c9ec1bf010beb00d98fa765a/PROTOCOL.certkeys#L248
    FORCE_COMMAND = "force-command"

    # https://github.com/openssh/openssh-portable/blob/2b71010d9b43d7b8c9ec1bf010beb00d98fa765a/PROTOCOL.certkeys#L253
    SOURCE_ADDRESS = "source-address"

    def pb_enum(self) -> CSR.CriticalOption:
        """
        Converts the enum into the correct protobuf value for serialization

        Returns:
            The serialized enum value
        """

        return getattr(CSR.CriticalOption, self.name)

    @classmethod
    def from_pb_enum(cls, value: int) -> "CertificateCriticalOptions":
        """
        Deserializes the enum value

        Args:
            value: the serialized enum value

        Returns:
            The original enum value
        """

        return getattr(cls, CSR.CriticalOption.Name(value))


class CertificateExtensions(enum.Enum):
    """
    `Certificate extensions`_

    .. _Certificate extensions:
       https://github.com/openssh/openssh-portable/blob/2b71010d9b43d7b8c9ec1bf010beb00d98fa765a/PROTOCOL.certkeys#L270
    """

    # https://github.com/openssh/openssh-portable/blob/2b71010d9b43d7b8c9ec1bf010beb00d98fa765a/PROTOCOL.certkeys#L290
    NO_TOUCH_REQUIRED = "no-touch-required"

    # https://github.com/openssh/openssh-portable/blob/2b71010d9b43d7b8c9ec1bf010beb00d98fa765a/PROTOCOL.certkeys#L297
    PERMIT_X11_FORWARDING = "permit-X11-forwarding"

    # https://github.com/openssh/openssh-portable/blob/2b71010d9b43d7b8c9ec1bf010beb00d98fa765a/PROTOCOL.certkeys#L301
    PERMIT_AGENT_FORWARDING = "permit-agent-forwarding"

    # https://github.com/openssh/openssh-portable/blob/2b71010d9b43d7b8c9ec1bf010beb00d98fa765a/PROTOCOL.certkeys#L306
    PERMIT_PORT_FORWARDING = "permit-port-forwarding"

    # https://github.com/openssh/openssh-portable/blob/2b71010d9b43d7b8c9ec1bf010beb00d98fa765a/PROTOCOL.certkeys#L311
    PERMIT_PTY = "permit-pty"

    # https://github.com/openssh/openssh-portable/blob/2b71010d9b43d7b8c9ec1bf010beb00d98fa765a/PROTOCOL.certkeys#L316
    PERMIT_USER_RC = "permit-user-rc"

    @classmethod
    def permit_all(cls) -> dict["CertificateExtensions", str]:
        """
        Convenience method to return a dict enabling all extensions

        Returns:
            All available extensions
        """

        return {
            cls.NO_TOUCH_REQUIRED: "",
            cls.PERMIT_X11_FORWARDING: "",
            cls.PERMIT_AGENT_FORWARDING: "",
            cls.PERMIT_PORT_FORWARDING: "",
            cls.PERMIT_PTY: "",
            cls.PERMIT_USER_RC: "",
        }

    def pb_enum(self) -> CSR.Extension:
        """
        Converts the enum into the correct protobuf value for serialization

        Returns:
            The serialized enum value
        """

        return getattr(CSR.Extension, self.name)

    @classmethod
    def from_pb_enum(cls, value: int) -> "CertificateExtensions":
        """
        Deserializes the enum value

        Args:
            value: the serialized enum value

        Returns:
            The original enum value
        """

        return getattr(cls, CSR.Extension.Name(value))


class CertificateParameters:
    """
    All certificate parameters needed for signing

    Args:
        valid_for: duration of certificate validity, overridden by `valid_before`

    Keyword Args:
        type (CertificateType): `type of certificate`_ to issue
        key_id (str): `key identifier`_
        serial (int): certificate `serial number`_
        principals (List[str]): list of `valid principals`_
        valid_after (int): `time after which the certificate is valid`_ (unix epoch, defaults to now)
        valid_before (int): `time before which the certificate is valid`_ (unix epoch)
        critical_opts (Dict[CertificateCriticalOptions, str]): dict of certificate `critical options`_
        extensions (Dict[CertificateExtensions, str]): dict of certificate `extensions`_

    .. _type of certificate:
       https://github.com/openssh/openssh-portable/blob/2b71010d9b43d7b8c9ec1bf010beb00d98fa765a/PROTOCOL.certkeys#L169
    .. _key identifier:
       https://github.com/openssh/openssh-portable/blob/2b71010d9b43d7b8c9ec1bf010beb00d98fa765a/PROTOCOL.certkeys#L172
    .. _serial number:
       https://github.com/openssh/openssh-portable/blob/2b71010d9b43d7b8c9ec1bf010beb00d98fa765a/PROTOCOL.certkeys#L164
    .. _valid principals:
       https://github.com/openssh/openssh-portable/blob/2b71010d9b43d7b8c9ec1bf010beb00d98fa765a/PROTOCOL.certkeys#L176
    .. _time after which the certificate is valid:
       https://github.com/openssh/openssh-portable/blob/2b71010d9b43d7b8c9ec1bf010beb00d98fa765a/PROTOCOL.certkeys#L183
    .. _time before which the certificate is valid:
       https://github.com/openssh/openssh-portable/blob/2b71010d9b43d7b8c9ec1bf010beb00d98fa765a/PROTOCOL.certkeys#L183
    .. _critical options:
       https://github.com/openssh/openssh-portable/blob/2b71010d9b43d7b8c9ec1bf010beb00d98fa765a/PROTOCOL.certkeys#L221
    .. _extensions:
       https://github.com/openssh/openssh-portable/blob/2b71010d9b43d7b8c9ec1bf010beb00d98fa765a/PROTOCOL.certkeys#L270
    """

    def __init__(
        self,
        valid_for: datetime.timedelta | None = datetime.timedelta(hours=1),
        **kwargs: object,
    ):
        now = int(time.time())

        # https://github.com/openssh/openssh-portable/blob/2b71010d9b43d7b8c9ec1bf010beb00d98fa765a/PROTOCOL.certkeys#L83
        self.cert_type = _require_type(
            kwargs.get("type", CertificateType.USER),
            CertificateType,
            "type",
        )

        # https://github.com/openssh/openssh-portable/blob/2b71010d9b43d7b8c9ec1bf010beb00d98fa765a/PROTOCOL.certkeys#L84
        self.key_id = _require_type(kwargs.get("key_id", ""), str, "key_id")

        # https://github.com/openssh/openssh-portable/blob/2b71010d9b43d7b8c9ec1bf010beb00d98fa765a/PROTOCOL.certkeys#L82
        self.serial = _require_type(kwargs.get("serial", 0), int, "serial")

        # https://github.com/openssh/openssh-portable/blob/2b71010d9b43d7b8c9ec1bf010beb00d98fa765a/PROTOCOL.certkeys#L85
        self.principals = _require_str_list(kwargs.get("principals", []), "principals")

        # https://github.com/openssh/openssh-portable/blob/2b71010d9b43d7b8c9ec1bf010beb00d98fa765a/PROTOCOL.certkeys#L86
        self.valid_after = _require_type(
            kwargs.get("valid_after", now), int, "valid_after"
        )

        # https://github.com/openssh/openssh-portable/blob/2b71010d9b43d7b8c9ec1bf010beb00d98fa765a/PROTOCOL.certkeys#L87
        valid_before_value = kwargs.get("valid_before")
        valid_before = (
            None
            if valid_before_value is None
            else _require_type(valid_before_value, int, "valid_before")
        )
        valid_for_seconds = int(valid_for.total_seconds()) if valid_for else 0
        self.valid_before = (
            valid_before
            if valid_before is not None
            else self.valid_after + valid_for_seconds
        )

        # https://github.com/openssh/openssh-portable/blob/2b71010d9b43d7b8c9ec1bf010beb00d98fa765a/PROTOCOL.certkeys#L88
        critical_options = _require_options(
            kwargs.get("critical_options", {}),
            CertificateCriticalOptions,
            "critical_options",
        )
        self.critical_opts = sorted(
            critical_options.items(), key=lambda _opt: _opt[0].value
        )

        # https://github.com/openssh/openssh-portable/blob/2b71010d9b43d7b8c9ec1bf010beb00d98fa765a/PROTOCOL.certkeys#L89
        extensions = _require_options(
            kwargs.get("extensions", {}),
            CertificateExtensions,
            "extensions",
        )
        self.extensions = sorted(
            extensions.items(),
            key=lambda _ext: _ext[0].value,
        )


class CertificateSigningRequest:
    """
    Combines the key to be signed and the certificate parameters

    Args:
        public_key: key to sign
        cert_params: certificate parameters
    """

    _CERT_SUFFIX = "-cert-v01@openssh.com"

    def __init__(self, public_key: PKey, cert_params: CertificateParameters):
        self.cert_params = cert_params
        self.public_key = public_key

    def to_proto(self) -> CSR:
        """
        Serializes the certificate signing request into a protobuf object

        Returns:
            Certificate signing request protobuf object
        """

        csr = CSR()
        if self.cert_params.cert_type == CertificateType.USER:
            csr.type = CSR.Type.USER
        else:
            csr.type = CSR.Type.HOST
        csr.keyId = self.cert_params.key_id
        csr.serial = self.cert_params.serial
        csr.principals.extend(self.cert_params.principals)
        csr.validAfter = self.cert_params.valid_after
        csr.validBefore = self.cert_params.valid_before
        for opt, val in self.cert_params.critical_opts:
            option_value = CSR.CriticalOptionValue()
            option_value.type = opt.pb_enum()
            option_value.value = val
            csr.criticalOptions.append(option_value)
        for ext, val in self.cert_params.extensions:
            extension_value = CSR.ExtensionValue()
            extension_value.type = ext.pb_enum()
            extension_value.value = val
            csr.extensions.append(extension_value)
        csr.publicKeyType = self.public_key.get_name()
        csr.publicKey = self._get_public_parts().asbytes()
        return csr

    @classmethod
    def from_proto(cls, csr: CSR) -> "CertificateSigningRequest":
        """
        Deserializes the certificate signing request from a protobuf object

        Returns:
            The original certificate signing request
        """

        params = CertificateParameters(
            type=CertificateType.from_pb_enum(csr.type),
            key_id=csr.keyId,
            serial=csr.serial,
            principals=csr.principals,
            valid_after=csr.validAfter,
            valid_before=csr.validBefore,
            critical_options={
                CertificateCriticalOptions.from_pb_enum(opt.type): opt.value
                for opt in csr.criticalOptions
            },
            extensions={
                CertificateExtensions.from_pb_enum(ext.type): ext.value
                for ext in csr.extensions
            },
        )

        key_type: str = csr.publicKeyType
        public_key_message = Message()
        public_key_message.add_string(key_type)
        public_key_message.add_bytes(csr.publicKey)
        public_key_message.rewind()

        if key_type == "ssh-rsa":
            public_key: PKey = RSAKey(public_key_message)
        elif key_type == "ssh-ed25519":
            public_key = Ed25519Key(public_key_message)
        elif key_type.startswith("ecdsa-sha2"):
            public_key = ECDSAKey(public_key_message)
        elif key_type == "ssh-dss" and DSSKey is not None:
            public_key = DSSKey(public_key_message)
        else:
            raise NotImplementedError(f"Key type not supported: {key_type}")

        return cls(public_key, params)

    def _get_public_parts(self) -> Message:
        """
        Get the public parts from the public key to be signed

        Returns:
            The public parts of the key to be signed
        """

        public_parts = Message(self.public_key.asbytes())
        public_parts.get_string()
        return Message(public_parts.get_remainder())

    @staticmethod
    def _encode_options(
        opts: Iterable[tuple[CertificateCriticalOptions | CertificateExtensions, str]],
    ) -> Message:
        """
        Encodes the certificate options and extensions into the required format

        Args:
            opts: list of options / extensions to encode

        Returns:
            The encoded set of options / extensions
        """

        m = Message()
        for k, v in opts:
            m.add_string(k.value)
            if len(v) == 0:
                m.add_string("")
            else:
                opt_value = Message()
                for _v in v:
                    opt_value.add_string(_v)
                m.add_string(opt_value.asbytes())
        return m

    def sign(self, signing_key: PKey) -> CertificateBlob:
        """
        Signs the public key using the signing key

        Args:
            signing_key: CA key used for signing

        Returns:
            The signed certificate
        """

        assert signing_key.can_sign(), "Key not capable of signing."

        public_parts = self._get_public_parts()

        cert = Message()
        cert.add_string(self.public_key.get_name() + self._CERT_SUFFIX)
        cert.add_string(secrets.token_bytes(32))
        cert.add_bytes(public_parts.asbytes())
        cert.add_int64(self.cert_params.serial)
        cert.add_int(self.cert_params.cert_type.value)
        cert.add_string(self.cert_params.key_id)

        if len(self.cert_params.principals) == 0:
            cert.add_string("")
        else:
            m = Message()
            for p in self.cert_params.principals:
                m.add_string(p)
            cert.add_string(m.asbytes())

        cert.add_int64(self.cert_params.valid_after)
        cert.add_int64(self.cert_params.valid_before)

        for opts in (
            self.cert_params.critical_opts,
            self.cert_params.extensions,
        ):
            if len(opts) == 0:
                cert.add_string("")
            else:
                cert.add_string(self._encode_options(opts).asbytes())

        cert.add_string("")
        cert.add_string(signing_key.asbytes())
        cert.add_string(signing_key.sign_ssh_data(cert.asbytes()))
        cert.rewind()

        return CertificateBlob.from_message(cert)


class CertificateSigningKeyMixin(PKey):
    """
    Mixin that allows a key to act as a certificate authority
    """

    def sign_certificate(
        self,
        pub_key: PKey,
        principals: list[str],
        extensions: dict[CertificateExtensions, str] | None = None,
        **kwargs: Any,
    ) -> CertificateBlob:
        """
        Signs a public key to produce a certificate

        Args:
            pub_key: the SSH public key
            principals: a list of principals to encode into the certificate
            extensions: a dictionary of certificate extensions, see :py:mod:`paramiko_cloud.pki.CertificateExtensions`
            **kwargs: additional certificate configuration parameters passed to the constructor of :py:mod:`paramiko_cloud.pki.CertificateParameters`

        Returns:
            A PublicBlob object containing the signed certificate
        """

        return CertificateSigningRequest(
            pub_key,
            CertificateParameters(
                principals=principals,
                extensions=extensions or CertificateExtensions.permit_all(),
                **kwargs,
            ),
        ).sign(self)
