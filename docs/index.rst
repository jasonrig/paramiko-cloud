Paramiko-Cloud
==============

Paramiko-Cloud extends Paramiko with ECDSA keys whose private material stays in
cloud key management services. The provider key classes behave like Paramiko
``ECDSAKey`` objects, so they can sign SSH data and issue OpenSSH certificates
without exporting the private key.

The package also includes a small PKI layer for building OpenSSH certificate
signing requests, serializing those requests through protobuf, and returning
certificate lines that can be saved as ``*-cert.pub`` files.

Features
--------

* AWS KMS, Google Cloud KMS, and Azure Key Vault ECDSA signing keys.
* OpenSSH user and host certificate generation.
* Certificate options, extensions, principals, serials, key IDs, and validity
  windows.
* Protobuf serialization for signing requests.
* A gRPC server wrapper for exposing certificate signing services.

.. toctree::
   :maxdepth: 2
   :caption: User Guide

   installation
   usage
   cloud-keys
   grpc

.. toctree::
   :maxdepth: 2
   :caption: API Reference

   api/index

Indices and Tables
------------------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
