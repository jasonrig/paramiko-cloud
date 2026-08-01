Cloud-Backed Keys
=================

Each provider exposes an ``ECDSAKey`` class that subclasses Paramiko's ECDSA key
implementation. The private key remains inside the provider KMS. Paramiko-Cloud
loads the public key, maps the provider signing API to Paramiko's signing
interface, and returns DER-encoded ECDSA signatures to Paramiko.

Paramiko-Cloud intentionally implements only ECDSA certificate-authority keys.
Some providers expose RSA signing services, but this package does not wrap them
and rejects RSA certificate-authority keys. This does not prevent an RSA public
key from being the subject of a certificate signed by an ECDSA CA.

Cloud-backed keys can:

* sign SSH data through ``sign_ssh_data``;
* verify signatures with the public key material;
* sign OpenSSH certificates with ``sign_certificate``;
* render a public CA key line with ``pubkey_string``.

Cloud-backed keys cannot export private key material or generate new keys
locally. Use the provider KMS APIs or console to create the key before using it
with Paramiko-Cloud.

AWS KMS
-------

``paramiko_cloud.aws.keys.ECDSAKey`` creates its own ``boto3`` KMS client. Pass
the KMS key ID or ARN as the first argument and any ``boto3.client("kms", ...)``
keyword arguments after that.

.. code-block:: python

   from paramiko_cloud.aws.keys import ECDSAKey

   ca_key = ECDSAKey(
       "arn:aws:kms:us-east-1:012345678901:key/example-key-id",
       region_name="us-east-1",
   )

The AWS key must have ``SIGN_VERIFY`` usage and one of these supported key and
algorithm pairs:

.. list-table::
   :header-rows: 1

   * - KMS key spec
     - Signing algorithm
   * - ``ECC_NIST_P256``
     - ``ECDSA_SHA_256``
   * - ``ECC_NIST_P384``
     - ``ECDSA_SHA_384``
   * - ``ECC_NIST_P521``
     - ``ECDSA_SHA_512``

The caller needs permission for ``kms:GetPublicKey`` during key construction and
``kms:Sign`` for each signature.

Google Cloud KMS
----------------

``paramiko_cloud.gcp.keys.ECDSAKey`` uses a caller-provided
``KeyManagementServiceClient``. Pass the crypto key version resource name, not
just the crypto key name, because asymmetric signing happens at the key version
level.

.. code-block:: python

   from google.cloud import kms
   from paramiko_cloud.gcp.keys import ECDSAKey

   kms_client = kms.KeyManagementServiceClient()
   key_version_name = (
       "projects/example-project/locations/us-central1/"
       "keyRings/ssh-ca/cryptoKeys/user-ca/cryptoKeyVersions/1"
   )

   ca_key = ECDSAKey(kms_client, key_version_name)

Supported Google Cloud algorithms are ``EC_SIGN_P256_SHA256`` and
``EC_SIGN_P384_SHA384``. The caller needs permission to get the public key and to
asymmetrically sign with the selected key version.

Azure Key Vault
---------------

``paramiko_cloud.azure.keys.ECDSAKey`` uses Azure Key Vault's key and crypto
clients. Pass an Azure credential, the vault URL, and the key name.

.. code-block:: python

   from azure.identity import DefaultAzureCredential
   from paramiko_cloud.azure.keys import ECDSAKey

   credential = DefaultAzureCredential()

   ca_key = ECDSAKey(
       credential,
       "https://example-vault.vault.azure.net/",
       "ssh-user-ca",
   )

The Key Vault key must be an EC key. Signing supports the ``P-256``, ``P-384``,
and ``P-521`` curves through Azure's ``ES256``, ``ES384``, and ``ES512``
signature algorithms. The caller needs permission to read the key and perform
cryptographic signing operations.

Provider Choice
---------------

The certificate signing API is provider-neutral after construction:

.. code-block:: python

   cert = ca_key.sign_certificate(subject_key, ["alice"])

Use provider-specific configuration only at the boundary where you create the CA
key object. Keep certificate policy, validity, principals, and extensions in the
shared PKI layer so the application code stays portable across providers.
