from unittest import TestCase

import grpc
from paramiko.rsakey import RSAKey

from paramiko_cloud.grpc_server import GRPCServer
from paramiko_cloud.pki import CertificateSigningRequest, CertificateParameters
from paramiko_cloud.protobuf import rpc_pb2_grpc, rpc_pb2


class SignerServicer(rpc_pb2_grpc.SignerServicer):

    def __init__(self):
        super().__init__()
        self.last_request = None

    def SignCertificate(self, request, context):
        self.last_request = request
        resp = rpc_pb2.CloudCertificateSigningResponse()
        resp.certificate = b"this is where the certificate would be"
        return resp


class GRPCServerTest(TestCase):
    def test_server(self):
        servicer = SignerServicer()
        with GRPCServer(servicer) as server:
            channel = grpc.insecure_channel("localhost:50051")
            stub = rpc_pb2_grpc.SignerStub(channel)
            req = rpc_pb2.CloudCertificateSigningRequest()
            req.provider = rpc_pb2.CloudCertificateSigningRequest.Provider.AWS
            req.kmsKeyId = "key id"
            req.signingRequestPayload.CopyFrom(
                CertificateSigningRequest(RSAKey.generate(1024), CertificateParameters()).to_proto())
            resp = stub.SignCertificate(req)
        self.assertEqual("key id", servicer.last_request.kmsKeyId)
        self.assertEqual("ssh-rsa", servicer.last_request.signingRequestPayload.publicKeyType)
        self.assertEqual(b"this is where the certificate would be", resp.certificate)
