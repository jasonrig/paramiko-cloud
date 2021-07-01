import itertools

from setuptools import setup

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
    url='',
    license='MIT',
    author='Jason Rigby',
    author_email='hello@jasonrig.by',
    description='Use cloud-managed keys to sign SSH certificates',
    setup_requires=[
        "protobuf_distutils",
        "protoc-wheel-0"
    ],
    options={
        "generate_py_protobufs": {
            "source_dir": "./paramiko_cloud/protobuf",
            "proto_root_path": "."
        }
    },
    install_requires=[
        "paramiko",
        "cryptography",
        "protobuf"
    ],
    extras_require=extras_require
)
