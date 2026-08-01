#!/usr/bin/env python3
import ast
import importlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROTO_DIR = ROOT / "ssh-cert-proto"
OUT_DIR = ROOT / "paramiko_cloud" / "protobuf"
BASE_MODULE = "paramiko_cloud.protobuf"
GENERATED_MODULE_PATTERNS = ("*_pb2*.py", "*_pb2*.pyi")


def run_protoc(*args: str) -> None:
    protoc = importlib.import_module("grpc_tools.protoc")
    protoc_main = getattr(protoc, "main", None)
    if not callable(protoc_main):
        raise TypeError("grpc_tools.protoc does not provide a compatible main function")
    rc = protoc_main(["grpc_tools.protoc", *args])
    if not isinstance(rc, int):
        raise TypeError("grpc_tools.protoc returned an invalid result")
    if rc != 0:
        raise SystemExit(rc)


def validate_generated_module_path(path: Path, output_dir: Path = OUT_DIR) -> Path:
    output_root = output_dir.resolve(strict=True)
    resolved_path = path.resolve(strict=True)
    if resolved_path.parent != output_root:
        raise ValueError(f"Generated module is outside the output directory: {path}")
    return resolved_path


def generated_module_paths() -> list[Path]:
    return sorted(
        {
            validate_generated_module_path(path)
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


def pb2_import_replacement(
    node: ast.AST,
) -> tuple[int, int, list[str]] | None:
    if not isinstance(node, ast.Import):
        return None
    if not node.names or not all(
        is_local_pb2_module(alias.name) for alias in node.names
    ):
        return None
    return (
        node.lineno - 1,
        node.end_lineno or node.lineno,
        [format_pb2_import(alias) for alias in node.names],
    )


def rewrite_pb2_imports_in_source(source: str, filename: str) -> str:
    tree = ast.parse(source, filename=filename)
    lines = source.splitlines()
    replacements: list[tuple[int, int, list[str]]] = []

    for node in ast.walk(tree):
        import_replacement = pb2_import_replacement(node)
        if import_replacement is None:
            continue
        replacements.append(import_replacement)

    if not replacements:
        return source

    for start, end, replacement_lines in sorted(replacements, reverse=True):
        lines[start:end] = replacement_lines

    rewritten = "\n".join(lines)
    if source.endswith("\n"):
        rewritten += "\n"
    return rewritten


def rewrite_pb2_imports() -> None:
    for path in generated_module_paths():
        with path.open(encoding="utf-8") as generated_module:
            source = generated_module.read()
        rewritten = rewrite_pb2_imports_in_source(source, str(path))
        if rewritten != source:
            with path.open("w", encoding="utf-8") as generated_module:
                generated_module.write(rewritten)


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
