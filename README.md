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
uv run mypy paramiko_cloud tests
```

## OpenSSH integration tests

The integration harness starts a disposable OpenSSH server in Docker, configures
it to trust a CA backed by the dummy signing service, sends certificate signing
requests through gRPC/protobuf, and attempts real SSH authentication with the
issued certificates.

Prerequisites:

- Docker with Compose v2
- An OpenSSH client providing `ssh`
- `uv`

Run the complete integration workflow locally:

```shell
./scripts/run_openssh_integration.sh
```

The harness assigns an ephemeral loopback port and removes its containers and
volumes after the test session. The same command sequence runs in the
`OpenSSH integration` GitHub Actions workflow on Ubuntu.

## Standards-convergence tests

Tests marked `standards` assert the behavior described by
[`draft-ietf-sshm-cert-01`](https://www.ietf.org/archive/id/draft-ietf-sshm-cert-01.html).
They are regular assertions rather than expected failures, so a future
standards regression fails the corresponding test and CI job directly.

Run the fast standards checks, which use `ssh-keygen -L` as an independent
certificate-format parser where possible:

```shell
uv run pytest -m standards tests/test_draft_compliance.py -vv
```

The Docker integration command also runs standards cases that require a real
OpenSSH authentication decision.
