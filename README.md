# Paramiko-Cloud
[![codecov](https://codecov.io/gh/jasonrig/paramiko-cloud/branch/main/graph/badge.svg?token=CJCQ9ITFT4)](https://codecov.io/gh/jasonrig/paramiko-cloud)

Paramiko-Cloud is an extension to Paramiko that provides ECDSA SSH keys managed by
cloud-based key management services. As well as enabling Paramiko to perform SSH
operations using cloud-managed keys, it also provides certificate signing functions,
simplifying the implementation of an SSH certificate authority.

Paramiko-Cloud supports:
* [Amazon Web Services - Key Management Service](https://aws.amazon.com/kms/)
* [Google Cloud Platform - Cloud Key Management Service](https://cloud.google.com/security-key-management)
* [Microsoft Azure - Key Vault](https://azure.microsoft.com/en-us/services/key-vault/)
