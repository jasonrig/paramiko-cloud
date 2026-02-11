# Paramiko-Cloud
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=jasonrig_paramiko-cloud&metric=sqale_rating)](https://sonarcloud.io/dashboard?id=jasonrig_paramiko-cloud) [![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=jasonrig_paramiko-cloud&metric=security_rating)](https://sonarcloud.io/dashboard?id=jasonrig_paramiko-cloud) [![Technical Debt](https://sonarcloud.io/api/project_badges/measure?project=jasonrig_paramiko-cloud&metric=sqale_index)](https://sonarcloud.io/dashboard?id=jasonrig_paramiko-cloud)

Paramiko-Cloud is an extension to Paramiko that provides ECDSA SSH keys managed by
cloud-based key management services. As well as enabling Paramiko to perform SSH
operations using cloud-managed keys, it also provides certificate signing functions,
simplifying the implementation of an SSH certificate authority.

Paramiko-Cloud supports:
* [Amazon Web Services - Key Management Service](https://aws.amazon.com/kms/)
* [Google Cloud Platform - Cloud Key Management Service](https://cloud.google.com/security-key-management)
* [Microsoft Azure - Key Vault](https://azure.microsoft.com/en-us/services/key-vault/)

Read the docs here: https://paramiko-cloud.readthedocs.io/en/latest/

## Development with uv

```shell
# Sync runtime + optional cloud provider dependencies + test tooling
uv sync --extra all --group dev

# Generate protobuf / gRPC Python modules
uv run python scripts/build_proto.py

# Run tests
uv run pytest --cov=./ --cov-report=xml

# Static checks (requires generated protobuf modules first)
uv run python scripts/build_proto.py
uv run ruff check .
uv run ruff format . --check
uv run mypy paramiko_cloud
```
