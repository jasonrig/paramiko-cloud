import itertools
import os.path

from setuptools import setup, Command

setup_path = os.path.dirname(os.path.realpath(__file__))

class GrpcBuild(Command):

    GRPC_PROTO_PATH = os.path.join(setup_path, "protobuf")
    PYTHON_OUT_PATH = os.path.join(setup_path, "paramiko_cloud", "protobuf")

    description = "build the grpc interface from proto schemas"

    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        import grpc_tools.protoc
        grpc_tools.protoc.main([
            'grpc_tools.protoc',
            '-I{}'.format(self.GRPC_PROTO_PATH),
            '--python_out={}'.format(self.PYTHON_OUT_PATH),
            '--grpc_python_out={}'.format(self.PYTHON_OUT_PATH),
            os.path.join(self.GRPC_PROTO_PATH, "rpc.proto")
        ])

extras_require = {
    "aws": ["boto3"],
    "gcp": ["google-cloud-kms"],
    "azure": [
        "azure-keyvault-keys",
        "azure-identity"
    ]
}
extras_require["all"] = list(itertools.chain(*extras_require.values()))



setup(
    name='paramiko-cloud',
    version='1.0',
    packages=['paramiko_cloud', 'paramiko_cloud.aws', 'paramiko_cloud.gcp'],
    include_package_data=True,
    url='',
    license='MIT',
    author='Jason Rigby',
    author_email='hello@jasonrig.by',
    description='Use cloud-managed keys to sign SSH certificates',
    setup_requires=[
        "protobuf_distutils"
    ],
    cmdclass={
        "build_grpc": GrpcBuild
    },
    options={
        "generate_py_protobufs": {
            "source_dir": os.path.join(setup_path, "protobuf"),
            "proto_root_path": os.path.join(setup_path, "protobuf"),
            "output_dir": os.path.join(setup_path, "paramiko_cloud", "protobuf")
        }
    },
    install_requires=[
        "paramiko",
        "cryptography",
        "protobuf",
        "grpcio-tools"
    ],
    extras_require=extras_require
)
