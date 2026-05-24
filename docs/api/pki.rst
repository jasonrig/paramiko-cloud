PKI
===

The PKI module builds compact OpenSSH certificates and serializes certificate
signing requests to protobuf for remote signing workflows.

Certificate Model
-----------------

.. autoclass:: paramiko_cloud.pki.CertificateParameters
   :members:
   :show-inheritance:

.. autoclass:: paramiko_cloud.pki.CertificateSigningRequest
   :members:
   :show-inheritance:

.. autoclass:: paramiko_cloud.pki.CertificateBlob
   :members:
   :show-inheritance:

Signing Mixin
-------------

.. autoclass:: paramiko_cloud.pki.CertificateSigningKeyMixin
   :members:
   :show-inheritance:

Enums
-----

.. autoclass:: paramiko_cloud.pki.CertificateType
   :members:
   :show-inheritance:

.. autoclass:: paramiko_cloud.pki.CertificateCriticalOptions
   :members:
   :show-inheritance:

.. autoclass:: paramiko_cloud.pki.CertificateExtensions
   :members:
   :show-inheritance:
