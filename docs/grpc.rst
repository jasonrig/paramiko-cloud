gRPC Signing Service
====================

Paramiko-Cloud includes a small wrapper around ``grpc.server`` for exposing a
certificate signing service. The protobuf messages and service definitions are
generated from the ``ssh-cert-proto`` submodule.

``GRPCServer`` does not implement signing policy itself. You provide a
``SignerServicer`` implementation, and the wrapper registers it, binds a port,
and starts or stops the server as a context manager.

Server Skeleton
---------------

.. code-block:: python

   from paramiko_cloud.grpc_server import GRPCServer
   from paramiko_cloud.pki import CertificateSigningRequest
   from paramiko_cloud.protobuf import rpc_pb2, rpc_pb2_grpc


   class Signer(rpc_pb2_grpc.SignerServicer):
       def __init__(self, ca_key):
           super().__init__()
           self.ca_key = ca_key

       def SignCertificate(self, request, context):
           csr = CertificateSigningRequest.from_proto(
               request.signingRequestPayload
           )
           cert = csr.sign(self.ca_key)

           response = rpc_pb2.CloudCertificateSigningResponse()
           response.certificateType = cert.key_type
           response.certificate = cert.key_blob
           return response

       def GetCertificateAuthority(self, request, context):
           response = rpc_pb2.GetCertificateAuthorityResponse()
           response.keyType = self.ca_key.get_name()
           response.publicKey = self.ca_key.asbytes()
           return response


   with GRPCServer(Signer(ca_key), bind_addr="[::]", port=50051):
       wait_for_shutdown()

Use ``server_credentials`` to bind a secure port:

.. code-block:: python

   with GRPCServer(
       Signer(ca_key),
       bind_addr="[::]",
       port=50051,
       server_credentials=credentials,
   ):
       wait_for_shutdown()

Operational Notes
-----------------

* ``GRPCServer`` defaults to port ``50051`` and a thread pool with ten workers.
* ``shutdown_grace`` is passed to ``grpc.Server.stop`` when the context exits.
* The service implementation should enforce provider selection, key IDs,
  authorization, audit logging, validity limits, and principal policy before
  signing.
* ``CertificateSigningRequest.from_proto`` supports RSA, ECDSA, Ed25519, and
  DSS public keys when the installed Paramiko version still exposes DSS support.
