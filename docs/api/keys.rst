Keys
====

Cloud-backed key classes adapt provider signing APIs to Paramiko's ECDSA key
interface. They are certificate-authority keys as well as regular Paramiko
signing keys.

Shared Base Classes
-------------------

.. autoclass:: paramiko_cloud.base.CloudSigningKey
   :members:
   :show-inheritance:

.. autoclass:: paramiko_cloud.base.BaseKeyECDSA
   :members:
   :show-inheritance:
   :exclude-members: generate, write_private_key, write_private_key_file

Provider Implementations
------------------------

AWS KMS
^^^^^^^

.. automodule:: paramiko_cloud.aws.keys
   :members:
   :show-inheritance:
   :exclude-members: _AWSSigningKey

Google Cloud KMS
^^^^^^^^^^^^^^^^

.. automodule:: paramiko_cloud.gcp.keys
   :members:
   :show-inheritance:
   :exclude-members: _GCPSigningKey

Azure Key Vault
^^^^^^^^^^^^^^^

.. automodule:: paramiko_cloud.azure.keys
   :members:
   :show-inheritance:
   :exclude-members: _AzureSigningKey
