gRPC
====

The gRPC helper owns server setup and lifecycle. Application code still owns the
``SignerServicer`` implementation and signing policy.

.. automodule:: paramiko_cloud.grpc_server
   :members:
   :show-inheritance:

Generated Modules
-----------------

The protobuf and gRPC modules are generated into ``paramiko_cloud.protobuf`` by
``scripts/build_proto.py``:

* ``paramiko_cloud.protobuf.csr_pb2``
* ``paramiko_cloud.protobuf.rpc_pb2``
* ``paramiko_cloud.protobuf.rpc_pb2_grpc``

They are not committed to the repository. Initialize the ``ssh-cert-proto``
submodule and run the build script before importing them directly.
