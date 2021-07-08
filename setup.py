import ast
import itertools
import os.path
from distutils.cmd import Command
from glob import glob
from typing import List, Tuple

from setuptools import setup

setup_path = os.path.dirname(os.path.realpath(__file__))


class ProtoBuild(Command):
    """
    Builds all protobuf and gRPC source files
    """

    GRPC_PROTO_PATH = os.path.join(".", "ssh-cert-proto")
    PYTHON_OUT_PATH = os.path.join(".", "paramiko_cloud", "protobuf")
    BASE_MODULE = "paramiko_cloud.protobuf"

    description = "build the grpc interface from proto schemas"

    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        import pasta
        from pasta.augment import rename
        import grpc_tools.protoc

        # Build the regular protobuf files
        self.run_command("generate_py_protobufs")

        # Build the gRPC stubs
        grpc_tools.protoc.main([
            'grpc_tools.protoc',
            '-I{}'.format(self.GRPC_PROTO_PATH),
            '--python_out={}'.format(self.PYTHON_OUT_PATH),
            '--grpc_python_out={}'.format(self.PYTHON_OUT_PATH),
            os.path.join(self.GRPC_PROTO_PATH, "rpc.proto")
        ])

        # Fix the imports in the generated pb2 source files
        for proto_file in glob(os.path.join(self.PYTHON_OUT_PATH, "*_pb2*.py")):
            # Stores the old and new module import
            rename_modules: List[Tuple[str, str]] = list()

            with open(proto_file, "r") as f:
                # Parse the source file
                tree = pasta.parse(f.read())

                # Find all imports ending in "pb2"
                for node in ast.iter_child_nodes(tree):
                    if isinstance(node, ast.Import):
                        for name in node.names:
                            if name.name.endswith("pb2"):
                                # Map the old module to the new module name
                                rename_modules.append((name.name, ".".join([self.BASE_MODULE, name.name])))
            # Apply the module name change
            for old_module, new_module in rename_modules:
                rename.rename_external(tree, old_module, new_module)

            # Write out the new source file
            with open(proto_file, "w") as f:
                f.write(pasta.dump(tree))


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
    version='1.1',
    packages=[
        'paramiko_cloud',
        'paramiko_cloud.aws',
        'paramiko_cloud.azure',
        'paramiko_cloud.gcp',
        'paramiko_cloud.protobuf'
    ],
    include_package_data=True,
    url='https://github.com/jasonrig/paramiko-cloud/',
    license='MIT',
    author='Jason Rigby',
    author_email='hello@jasonrig.by',
    description='Use cloud-managed keys to sign SSH certificates',
    setup_requires=[
        "protobuf_distutils",
        "grpcio-tools",
        "google-pasta"
    ],
    cmdclass={
        "build_proto": ProtoBuild
    },
    options={
        "generate_py_protobufs": {
            "source_dir": os.path.join(setup_path, "ssh-cert-proto"),
            "proto_root_path": os.path.join(setup_path, "ssh-cert-proto"),
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
