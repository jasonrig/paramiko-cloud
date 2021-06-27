Welcome to Paramiko-Cloud's documentation!
==========================================

This project aims to extend Paramiko to provide SSH keys that
are backed by cloud-based key management services. Further,
SSH certificate signing capabilities are added that make
implementation of SSH certificate authorities straightforward.

.. toctree::
   api/keys
   api/pki

Installation
------------
Install Paramiko-Cloud using pip:

.. code-block:: bash

   # Install with AWS support
   pip install paramiko-cloud[aws]

   # Install with Azure support
   pip install paramiko-cloud[azure]

   # Install with GCP support
   pip install paramiko-cloud[gcp]

Examples
--------

Amazon Web Services
^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   from paramiko_cloud.aws.keys import ECDSAKey

   ca_key = ECDSAKey(
       "arn:aws:kms:ap-northeast-1:012345678901:key/e9a4e926-b826-46fe-840d-58d44f0c6a89",
       region_name="ap-northeast-1"
   )
   client_key = RSAKey.generate(1024)
   cert_string = ca_key.sign_certificate(
       client_key,
       ["test.user"]
   ).cert_string()

Microsoft Azure
^^^^^^^^^^^^^^^

.. code-block:: python

   from azure.identity import DefaultAzureCredential
   from paramiko_cloud.azure.keys import ECDSAKey

   credential = DefaultAzureCredential()

   ca_key = ECDSAKey(
       credential,
       "https://your.vault.url/",
       "key_name"
   )
   client_key = RSAKey.generate(1024)
   cert_string = ca_key.sign_certificate(
       client_key,
       ["test.user"]
   ).cert_string()

Google Cloud Platform
^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   from google.cloud import kms
   from paramiko_cloud.gcp.keys import ECDSAKey

   kms_client = kms.KeyManagementServiceClient()
   key_name = "projects/PROJECT_NAME/locations/REGION_NAME/keyRings/YOUR_KEY_RING_NAME/cryptoKeys/YOUR_KEY_NAME/cryptoKeyVersions/YOUR_KEY_VERSION"

   ca_key = ECDSAKey(kms_client, key_name)
   client_key = RSAKey.generate(1024)
   cert_string = ca_key.sign_certificate(
       client_key,
       ["test.user"]
   ).cert_string()

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
