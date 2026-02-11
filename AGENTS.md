# AGENTS.md

This file is a fast orientation guide for coding agents working in this repository.

## Repository Purpose

`paramiko-cloud` extends Paramiko with cloud-managed signing keys and SSH certificate support.

Primary modules:
- `paramiko_cloud/aws/keys.py`: AWS KMS-backed keys
- `paramiko_cloud/gcp/keys.py`: GCP KMS-backed keys
- `paramiko_cloud/azure/keys.py`: Azure Key Vault-backed keys
- `paramiko_cloud/pki.py`: certificate request/response models and serialization
- `paramiko_cloud/grpc_server.py`: gRPC service wrapper
- `paramiko_cloud/test_*.py`: core unit tests

## Environment and Setup

Use `uv` for all local workflows.

```bash
uv sync --extra all --group dev
```

## Required Build Step

Some checks depend on generated protobuf files.

```bash
uv run python scripts/build_proto.py
```

Notes:
- Protos live in `ssh-cert-proto/`.
- Generated files are under `paramiko_cloud/protobuf/`.
- If proto definitions change, regenerate before lint/type/test.

## Canonical Checks

Run from repo root:

```bash
uv run ruff check .
uv run ruff format . --check
uv run mypy paramiko_cloud
uv run pytest --cov=./ --cov-report=xml
```

Important:
- Use `uv run mypy paramiko_cloud` (not `uv run mypy .`) to match CI scope.

## Editing Guardrails

- Keep changes minimal and targeted; avoid broad refactors unless requested.
- Do not manually edit generated protobuf modules in `paramiko_cloud/protobuf/*_pb2*.py`.
- If changes affect protobuf imports or proto messages, re-run `scripts/build_proto.py`.
- Prefer fixing lint/type issues in source modules, not by weakening tool settings.

## Fast Navigation

- Search code: `rg "pattern" paramiko_cloud scripts`
- List files: `rg --files`
- Focused tests:
  - `uv run pytest paramiko_cloud/test_pki.py -q`
  - `uv run pytest paramiko_cloud/test_grpc_server.py -q`

## Commit Hygiene

- Keep commits scoped to one logical change.
- Include regenerated protobuf files in the same commit when proto changes require it.
