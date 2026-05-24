Certificate Signing
===================

Paramiko-Cloud signs OpenSSH certificates with the same high-level pattern for
every provider:

1. Create a cloud-backed ECDSA certificate authority key.
2. Provide the public key that should receive a certificate.
3. Choose principals, validity, certificate type, and options.
4. Write the returned certificate line to the matching ``*-cert.pub`` file.

The result is an OpenSSH certificate public key line, not an X.509
certificate. OpenSSH certificates are compact SSH public-key records that bind a
subject key to identity, validity, and policy fields signed by a trusted CA key.

Signing a User Certificate
--------------------------

This example uses AWS KMS for the certificate authority key, but the
``sign_certificate`` call is the same for AWS, Google Cloud, Azure, and any other
Paramiko key that includes ``CertificateSigningKeyMixin``.

.. code-block:: python

   from datetime import timedelta

   from paramiko import RSAKey

   from paramiko_cloud.aws.keys import ECDSAKey
   from paramiko_cloud.pki import CertificateExtensions

   ca_key = ECDSAKey(
       "arn:aws:kms:us-east-1:012345678901:key/example-key-id",
       region_name="us-east-1",
   )
   subject_key = RSAKey.generate(3072)

   cert = ca_key.sign_certificate(
       subject_key,
       principals=["alice"],
       key_id="alice@example.com",
       serial=1001,
       valid_for=timedelta(hours=8),
       extensions={
           CertificateExtensions.PERMIT_PTY: "",
           CertificateExtensions.PERMIT_AGENT_FORWARDING: "",
       },
   )

   cert_line = cert.cert_string("alice@example.com")

``cert_line`` is an OpenSSH certificate public key line. Save it next to the
subject private key using OpenSSH's certificate naming convention, such as
``id_rsa-cert.pub`` for ``id_rsa``.

Certificate Parameters
----------------------

``sign_certificate`` accepts ``principals`` directly and forwards the remaining
certificate configuration to ``CertificateParameters``.

Common parameters are:

.. list-table::
   :header-rows: 1

   * - Parameter
     - Purpose
     - Default
   * - ``principals``
     - User names or host names valid for the certificate.
     - Required by ``sign_certificate``.
   * - ``type``
     - ``CertificateType.USER`` or ``CertificateType.HOST``.
     - ``CertificateType.USER``
   * - ``key_id``
     - Audit label stored in the certificate.
     - Empty string
   * - ``serial``
     - CA-defined certificate serial number.
     - ``0``
   * - ``valid_after``
     - Unix timestamp when the certificate becomes valid.
     - Current time
   * - ``valid_before``
     - Unix timestamp when the certificate expires.
     - ``valid_after + valid_for``
   * - ``valid_for``
     - Duration used when ``valid_before`` is not provided.
     - One hour
   * - ``critical_options``
     - OpenSSH critical options.
     - No critical options
   * - ``extensions``
     - OpenSSH extensions.
     - All supported extensions enabled by ``sign_certificate``

The certificate also includes a nonce, the subject public key, the CA public
key, and a CA signature over the preceding certificate fields. Paramiko-Cloud
handles those wire-format details when it builds the certificate.

OpenSSH treats critical options as mandatory restrictions. If a client or server
does not understand a critical option in a certificate, it must reject that
certificate. Extensions are non-critical grants such as PTY or agent forwarding.
Pass ``extensions={}`` when you want a certificate with no extensions.

The standard extension values are empty strings:

.. code-block:: python

   extensions = {
       CertificateExtensions.PERMIT_PTY: "",
       CertificateExtensions.PERMIT_AGENT_FORWARDING: "",
   }

Critical option values carry option-specific data:

.. code-block:: python

   from paramiko_cloud.pki import CertificateCriticalOptions

   critical_options = {
       CertificateCriticalOptions.SOURCE_ADDRESS: "10.0.0.0/8,192.0.2.0/24",
   }

OpenSSH treats an empty principals list as valid for any principal of the
certificate type. Prefer explicit principals for normal user and host
certificates.

Signing a Host Certificate
--------------------------

Host certificates use the same API with ``CertificateType.HOST``. Principals are
the hostnames or address names that should validate against the host key.

.. code-block:: python

   from datetime import timedelta

   from paramiko import ECDSAKey as ParamikoECDSAKey

   from paramiko_cloud.gcp.keys import ECDSAKey as GCPECDSAKey
   from paramiko_cloud.pki import CertificateType

   ca_key = GCPECDSAKey(kms_client, key_version_name)
   host_key = ParamikoECDSAKey.generate()

   host_cert = ca_key.sign_certificate(
       host_key,
       principals=["web-01.example.com", "10.0.0.15"],
       type=CertificateType.HOST,
       key_id="web-01",
       valid_for=timedelta(days=7),
       extensions={},
   )

   host_cert_line = host_cert.cert_string("web-01.example.com")

Public CA Key
-------------

Cloud-backed keys can expose their public key in OpenSSH format:

.. code-block:: python

   ca_public_key = ca_key.pubkey_string("production-user-ca")

Private key export and local key generation are intentionally disabled for
cloud-backed keys. Create and rotate the CA key in the provider's key management
service, then point Paramiko-Cloud at the existing key.

OpenSSH validates the certificate only when the CA public key is trusted by the
server for user certificates or by the client for host certificates.

Serializing Signing Requests
----------------------------

``CertificateSigningRequest`` can serialize a request to protobuf and reconstruct
it later. This is the format used by the gRPC API.

.. code-block:: python

   from paramiko import RSAKey

   from paramiko_cloud.pki import (
       CertificateParameters,
       CertificateSigningRequest,
   )

   request = CertificateSigningRequest(
       RSAKey.generate(3072),
       CertificateParameters(principals=["alice"], key_id="alice@example.com"),
   )

   proto = request.to_proto()
   payload = proto.SerializeToString()
   restored_proto = type(proto).FromString(payload)
   restored = CertificateSigningRequest.from_proto(restored_proto)
   cert = restored.sign(ca_key)
