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
- `tests/`: unit tests, organized by provider

## Environment and Setup

Use `uv` for all local workflows.

```bash
uv sync --frozen --no-build --no-install-project --all-extras --all-groups
```

When using GitHub CLI (`gh`), escalate out of the sandbox so it can access the
keyring-backed GitHub credentials.

## Required Build Step

Some checks depend on generated protobuf files.

```bash
uv run --frozen --no-build --no-sync python scripts/build_proto.py
```

Notes:

- Protos live in `ssh-cert-proto/`.
- Generated files are under `paramiko_cloud/protobuf/`.
- If proto definitions change, regenerate before lint/type/test.
- Do not manually edit generated `*_pb2*.py` or `*_pb2*.pyi` files.
- Mypy excludes generated `*_pb2*.py` implementations but checks their generated
  `.pyi` interfaces.

## Canonical Checks

Run from repo root:

```bash
uv run --frozen --no-build --no-sync ruff check .
uv run --frozen --no-build --no-sync ruff format . --check
uv run --frozen --no-build --no-sync mypy paramiko_cloud tests
uv run --frozen --no-build --no-sync pytest --cov=./ --cov-report=xml
```

Important:

- Type-check both `paramiko_cloud` and `tests` to match CI scope.
- Preserve the frozen environment during checks; dependency changes belong in
  `pyproject.toml` and `uv.lock`, not an implicit `uv run` re-resolution.

## Editing Guardrails

- Keep changes minimal and targeted; avoid broad refactors unless requested.
- If changes affect protobuf imports or proto messages, re-run `scripts/build_proto.py`.
- Fix lint and type issues in source or tests. Do not introduce `noqa`,
  `type: ignore`, `cast`, coverage exclusions, blanket mypy overrides, or weaker
  tool settings to silence findings.

## SonarCloud Remediation

- Treat every SonarCloud finding and failed quality-gate metric as a code or
  workflow problem to investigate. Do not remove warnings by changing
  `sonar-project.properties`, analysis exclusions, quality profiles, quality-gate
  thresholds, or issue status.
- Check both the issue list and the quality-gate conditions. A PR can have zero
  open issues and still fail a metric such as new-code duplication.
- Fix the root cause in the analyzed code:
  - extract genuinely shared test setup and assertions when duplication is real;
  - keep exception assertion scopes limited to one potentially throwing call;
  - make CI dependency installation reproducible with frozen, non-building `uv`
    commands.
- Test placement is a repository design decision, not a remediation mechanism.
  Keep tests under `tests/`; do not move or exclude code merely to hide findings.
- Do not replace a Sonar finding with an inline suppression or a configuration
  exception. If a finding appears incorrect, document the technical reasoning
  and seek review before changing analysis behavior.
- After pushing a fix, wait for the refreshed analysis and verify all of:
  - the SonarCloud check passes;
  - unresolved issue count is zero;
  - the quality gate reports `OK`;
  - no quality-gate condition is ignored.

## Fast Navigation

- Search code: `rg "pattern" paramiko_cloud tests scripts`
- List files: `rg --files`
- Focused tests:
  - `uv run --frozen --no-build --no-sync pytest tests/test_pki.py -q`
  - `uv run --frozen --no-build --no-sync pytest tests/test_grpc_server.py -q`

## Commit Hygiene

- Keep commits scoped to one logical change.
- Include regenerated protobuf files in the same commit when proto changes require it.
