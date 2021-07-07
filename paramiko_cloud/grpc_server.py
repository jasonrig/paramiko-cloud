from concurrent import futures
from typing import Optional

import grpc

from paramiko_cloud.protobuf import rpc_pb2_grpc
from paramiko_cloud.protobuf.rpc_pb2_grpc import SignerServicer


class GRPCServer:
    """
    A gRPC server object that can be used to respond to signing requests

    Args:
        signer_servicer: an object that can process the incoming requests
        bind_addr: address to which the gRPC server should bind
        port: the port on which the server should listen
        server_credentials: server credentials, if a secure channel should be used
        max_workers: maximum number of workers to use in the thread pool
    """

    def __init__(self, signer_servicer: SignerServicer, bind_addr: str = "[::]", port: int = 50051,
                 server_credentials: Optional[grpc.ServerCredentials] = None, max_workers: int = 10,
                 shutdown_grace: Optional[int] = None):
        self.shutdown_grace = shutdown_grace
        self.server = grpc.server(futures.ThreadPoolExecutor(max_workers=max_workers))
        rpc_pb2_grpc.add_SignerServicer_to_server(signer_servicer, self.server)
        address = "{}:{}".format(bind_addr, port)
        if server_credentials:
            self.server.add_secure_port(address, server_credentials)
        else:
            self.server.add_insecure_port(address)

    def __enter__(self) -> grpc.Server:
        self.server.start()
        return self.server

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.server.stop(self.shutdown_grace)
