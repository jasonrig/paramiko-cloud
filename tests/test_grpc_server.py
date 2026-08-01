from unittest import TestCase

import grpc
from paramiko.rsakey import RSAKey

from paramiko_cloud.grpc_server import GRPCServer
from paramiko_cloud.pki import CertificateParameters, CertificateSigningRequest
from paramiko_cloud.protobuf import rpc_pb2, rpc_pb2_grpc


class SignerServicer(rpc_pb2_grpc.SignerServicer):
    def __init__(self):
        super().__init__()
        self.last_request = None

    def SignCertificate(self, request, context):
        self.last_request = request
        resp = rpc_pb2.CloudCertificateSigningResponse()
        resp.certificateType = "cert type"
        resp.certificate = b"this is where the certificate would be"
        return resp

    def GetCertificateAuthority(self, request, context):
        self.last_request = request
        resp = rpc_pb2.GetCertificateAuthorityResponse()
        resp.keyType = "key type"
        resp.publicKey = b"this is where the CA key would be"
        return resp


class GRPCServerTest(TestCase):
    def test_server_signing(self):
        servicer = SignerServicer()
        with GRPCServer(servicer):
            channel = grpc.insecure_channel("localhost:50051")
            stub = rpc_pb2_grpc.SignerStub(channel)
            req = rpc_pb2.CloudCertificateSigningRequest()
            req.provider = rpc_pb2.CloudProvider.AWS
            req.kmsKeyId = "key id"
            req.signingRequestPayload.CopyFrom(
                CertificateSigningRequest(
                    RSAKey.generate(1024),
                    CertificateParameters(principals=["test.user"]),
                ).to_proto()
            )
            resp = stub.SignCertificate(req)
        self.assertEqual(servicer.last_request.provider, rpc_pb2.CloudProvider.AWS)
        self.assertEqual(servicer.last_request.kmsKeyId, "key id")
        self.assertEqual(
            servicer.last_request.signingRequestPayload.publicKeyType, "ssh-rsa"
        )
        self.assertEqual(resp.certificateType, "cert type")
        self.assertEqual(resp.certificate, b"this is where the certificate would be")

    def test_server_get_ca(self):
        servicer = SignerServicer()
        with GRPCServer(servicer):
            channel = grpc.insecure_channel("localhost:50051")
            stub = rpc_pb2_grpc.SignerStub(channel)
            req = rpc_pb2.GetCertificateAuthorityRequest()
            req.provider = rpc_pb2.CloudProvider.AWS
            req.kmsKeyId = "key id"
            resp = stub.GetCertificateAuthority(req)
        self.assertEqual(servicer.last_request.kmsKeyId, "key id")
        self.assertEqual(resp.keyType, "key type")
        self.assertEqual(resp.publicKey, b"this is where the CA key would be")
