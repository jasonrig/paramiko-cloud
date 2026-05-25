#!/usr/bin/env python3
import ast
from pathlib import Path

import grpc_tools.protoc

ROOT = Path(__file__).resolve().parent.parent
PROTO_DIR = ROOT / "ssh-cert-proto"
OUT_DIR = ROOT / "paramiko_cloud" / "protobuf"
BASE_MODULE = "paramiko_cloud.protobuf"
GENERATED_MODULE_PATTERNS = ("*_pb2*.py", "*_pb2*.pyi")


def run_protoc(*args: str) -> None:
    rc = grpc_tools.protoc.main(["grpc_tools.protoc", *args])
    if rc != 0:
        raise SystemExit(rc)


def generated_module_paths() -> list[Path]:
    return sorted(
        {
            path
            for pattern in GENERATED_MODULE_PATTERNS
            for path in OUT_DIR.glob(pattern)
        }
    )


def is_local_pb2_module(module_name: str) -> bool:
    return "." not in module_name and module_name.endswith("_pb2")


def format_pb2_import(alias: ast.alias) -> str:
    rewritten = f"from {BASE_MODULE} import {alias.name}"
    if alias.asname:
        return f"{rewritten} as {alias.asname}"
    return rewritten


def pb2_import_replacement(node: ast.AST) -> list[str] | None:
    if not isinstance(node, ast.Import):
        return None
    if not node.names or not all(
        is_local_pb2_module(alias.name) for alias in node.names
    ):
        return None
    return [format_pb2_import(alias) for alias in node.names]


def rewrite_pb2_imports_in_source(source: str, filename: str) -> str:
    tree = ast.parse(source, filename=filename)
    lines = source.splitlines()
    replacements: list[tuple[int, int, list[str]]] = []

    for node in ast.walk(tree):
        replacement = pb2_import_replacement(node)
        if replacement is None:
            continue
        replacements.append(
            (
                node.lineno - 1,
                node.end_lineno or node.lineno,
                replacement,
            )
        )

    if not replacements:
        return source

    for start, end, replacement in sorted(replacements, reverse=True):
        lines[start:end] = replacement

    rewritten = "\n".join(lines)
    if source.endswith("\n"):
        rewritten += "\n"
    return rewritten


def rewrite_pb2_imports() -> None:
    for path in generated_module_paths():
        source = path.read_text()
        rewritten = rewrite_pb2_imports_in_source(source, str(path))
        if rewritten != source:
            path.write_text(rewritten)


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    proto_files = sorted(PROTO_DIR.glob("*.proto"))
    run_protoc(
        f"-I{PROTO_DIR}",
        f"--python_out={OUT_DIR}",
        f"--pyi_out={OUT_DIR}",
        *[str(p) for p in proto_files],
    )

    rpc_proto = PROTO_DIR / "rpc.proto"
    run_protoc(
        f"-I{PROTO_DIR}",
        f"--grpc_python_out={OUT_DIR}",
        str(rpc_proto),
    )

    rewrite_pb2_imports()


if __name__ == "__main__":
    main()
